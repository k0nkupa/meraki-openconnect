"""One-shot Chrome host-permission setup over private per-user IPC."""

from __future__ import annotations

import json
import os
import re
import secrets
import socket
import stat
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TextIO
from urllib.parse import urlsplit

from meraki_openconnect.callback import default_state_directory


ACTIVE_SETUP_FILE = "extension-setup.json"
_ACTIVE_AUTH_FILE = "authentication.json"
_MAX_MESSAGE_BYTES = 16 * 1024
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


def setup_socket_directory() -> Path:
    return Path("/tmp") / f"meraki-openconnect-{os.getuid()}"


class ExtensionSetupTimeout(TimeoutError):
    """Chrome did not return a host-permission result in time."""


class ExtensionSetupError(RuntimeError):
    """The private extension-permission handoff was unsafe or invalid."""


@dataclass(frozen=True)
class ExtensionPermissionReceipt:
    gateway_origin: str
    profile_digest: str
    granted: bool


def _validate_gateway_origin(origin: str) -> str:
    try:
        parsed = urlsplit(origin)
        port = parsed.port
    except (TypeError, ValueError) as exc:
        raise ExtensionSetupError("gateway origin is invalid") from exc
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.hostname != parsed.hostname.lower()
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or origin != f"https://{parsed.hostname}"
    ):
        raise ExtensionSetupError("gateway origin is invalid")
    return origin


class ExtensionSetupCallback:
    """Serve one permission bootstrap and accept one exact result."""

    def __init__(
        self,
        *,
        gateway_origin: str,
        profile_digest: str,
        timeout_seconds: float = 180,
        state_directory: Path | None = None,
    ):
        self._gateway_origin = _validate_gateway_origin(gateway_origin)
        if not _DIGEST.fullmatch(profile_digest):
            raise ExtensionSetupError("profile digest is invalid")
        self._profile_digest = profile_digest
        self._timeout_seconds = timeout_seconds
        self._state_directory = state_directory or default_state_directory()
        self._state_path = self._state_directory / ACTIVE_SETUP_FILE
        self._socket_path: Path | None = None
        self._server: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._result_ready = threading.Event()
        self._receipt: ExtensionPermissionReceipt | None = None
        self._error: ExtensionSetupError | None = None

    @property
    def socket_path(self) -> Path:
        if self._socket_path is None:
            raise ExtensionSetupError("extension setup socket is unavailable")
        return self._socket_path

    def _prepare_state_directory(self) -> None:
        try:
            self._state_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            metadata = self._state_directory.lstat()
            if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
                raise ExtensionSetupError("extension setup state directory is unsafe")
            self._state_directory.chmod(0o700)
        except OSError as exc:
            raise ExtensionSetupError(
                "extension setup state directory is unavailable"
            ) from exc

    @staticmethod
    def _prepare_socket_directory() -> Path:
        directory = setup_socket_directory()
        try:
            directory.mkdir(mode=0o700, exist_ok=True)
            metadata = directory.lstat()
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                raise ExtensionSetupError("extension setup socket directory is unsafe")
            directory.chmod(0o700)
        except OSError as exc:
            raise ExtensionSetupError(
                "extension setup socket directory is unavailable"
            ) from exc
        return directory

    def _clear_stale_state(self) -> None:
        if (self._state_directory / _ACTIVE_AUTH_FILE).exists():
            raise ExtensionSetupError("an authentication exchange is active")
        if not self._state_path.exists():
            return
        try:
            metadata = self._state_path.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise ExtensionSetupError("extension setup state file is unsafe")
            state = json.loads(self._state_path.read_text())
            if not isinstance(state, dict) or set(state) != {"pid", "socket"}:
                raise ExtensionSetupError("extension setup state file is invalid")
            pid = state["pid"]
            socket_name = state["socket"]
            if (
                not isinstance(pid, int)
                or pid <= 1
                or not isinstance(socket_name, str)
                or Path(socket_name).name != socket_name
            ):
                raise ExtensionSetupError("extension setup state file is invalid")
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                pass
            except PermissionError as exc:
                raise ExtensionSetupError(
                    "another extension setup process owns the handoff"
                ) from exc
            else:
                raise ExtensionSetupError("another extension setup process is active")
            stale_socket = self._state_directory / socket_name
            if stale_socket.exists():
                socket_metadata = stale_socket.lstat()
                if (
                    not stat.S_ISSOCK(socket_metadata.st_mode)
                    or socket_metadata.st_uid != os.getuid()
                ):
                    raise ExtensionSetupError("extension setup socket is unsafe")
                stale_socket.unlink()
            self._state_path.unlink()
        except (OSError, json.JSONDecodeError) as exc:
            raise ExtensionSetupError("extension setup state file is invalid") from exc

    def _publish_state(self) -> None:
        temporary = self._state_path.with_suffix(".tmp")
        temporary.write_text(
            json.dumps(
                {"pid": os.getpid(), "socket": str(self.socket_path)},
                sort_keys=True,
            )
            + "\n"
        )
        temporary.chmod(0o600)
        temporary.replace(self._state_path)
        self._state_path.chmod(0o600)

    @staticmethod
    def _read_message(stream: TextIO) -> dict[str, Any]:
        raw = stream.readline(_MAX_MESSAGE_BYTES + 1)
        if not raw or len(raw.encode()) > _MAX_MESSAGE_BYTES:
            raise ExtensionSetupError("native host message is missing or too large")
        try:
            message = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ExtensionSetupError("native host message is invalid") from exc
        if not isinstance(message, dict):
            raise ExtensionSetupError("native host message is invalid")
        return message

    @staticmethod
    def _write_message(stream: TextIO, message: dict[str, Any]) -> None:
        stream.write(json.dumps(message, separators=(",", ":")) + "\n")
        stream.flush()

    def _serve(self) -> None:
        try:
            if self._server is None:
                raise ExtensionSetupError("extension setup socket is unavailable")
            connection, _ = self._server.accept()
            with connection:
                stream = connection.makefile("rw", encoding="utf-8", newline="\n")
                with stream:
                    request = self._read_message(stream)
                    if request != {"type": "setup-bootstrap"}:
                        raise ExtensionSetupError("setup bootstrap request is invalid")
                    self._write_message(
                        stream,
                        {
                            "type": "setup-bootstrap",
                            "gatewayOrigin": self._gateway_origin,
                            "profileDigest": self._profile_digest,
                        },
                    )
                    result = self._read_message(stream)
                    if (
                        set(result)
                        != {
                            "type",
                            "gatewayOrigin",
                            "profileDigest",
                            "granted",
                        }
                        or result.get("type") != "setup-result"
                        or result.get("gatewayOrigin") != self._gateway_origin
                        or result.get("profileDigest") != self._profile_digest
                        or not isinstance(result.get("granted"), bool)
                    ):
                        raise ExtensionSetupError("setup result is invalid")
                    self._receipt = ExtensionPermissionReceipt(
                        gateway_origin=self._gateway_origin,
                        profile_digest=self._profile_digest,
                        granted=result["granted"],
                    )
                    self._write_message(stream, {"type": "accepted"})
        except (ExtensionSetupError, OSError) as exc:
            self._error = (
                exc
                if isinstance(exc, ExtensionSetupError)
                else ExtensionSetupError("native host connection failed")
            )
        finally:
            self._result_ready.set()

    def __enter__(self) -> "ExtensionSetupCallback":
        self._prepare_state_directory()
        self._clear_stale_state()
        socket_directory = self._prepare_socket_directory()
        self._socket_path = socket_directory / f"setup-{secrets.token_hex(8)}.sock"
        try:
            self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._server.bind(str(self._socket_path))
            self._socket_path.chmod(0o600)
            self._server.listen(1)
            self._publish_state()
        except OSError as exc:
            self.__exit__(None, None, None)
            raise ExtensionSetupError(
                "extension setup socket could not be created"
            ) from exc
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        return self

    def wait(self) -> ExtensionPermissionReceipt:
        if not self._result_ready.wait(self._timeout_seconds):
            raise ExtensionSetupTimeout(
                "Chrome did not return extension permission before timeout"
            )
        if self._error is not None:
            raise self._error
        if self._receipt is None:
            raise ExtensionSetupTimeout("extension permission result was unavailable")
        receipt = self._receipt
        self._receipt = None
        return receipt

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        if self._server is not None:
            self._server.close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None
        self._state_path.unlink(missing_ok=True)
        if self._socket_path is not None:
            self._socket_path.unlink(missing_ok=True)
        self._receipt = None
