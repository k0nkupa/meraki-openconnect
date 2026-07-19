"""Private local handoff between meraki-openconnect and its Chrome native host."""

from __future__ import annotations

import json
import os
import secrets
import socket
import stat
import threading
from pathlib import Path
from typing import Any, TextIO


ACTIVE_AUTH_FILE = "authentication.json"
_ACTIVE_SETUP_FILE = "extension-setup.json"
_MAX_MESSAGE_BYTES = 16 * 1024


class CallbackTimeout(TimeoutError):
    """Chrome did not return the VPN token before the callback expired."""


class CallbackError(RuntimeError):
    """The private authentication handoff could not be established safely."""


def default_state_directory() -> Path:
    return Path.home() / ".local" / "state" / "meraki-openconnect"


class TokenCallback:
    """Serve one bootstrap and accept one token over private per-user IPC."""

    def __init__(
        self,
        bootstrap: dict[str, Any],
        *,
        timeout_seconds: float = 180,
        state_directory: Path | None = None,
    ):
        self._bootstrap = bootstrap
        self._timeout_seconds = timeout_seconds
        self._state_directory = state_directory or default_state_directory()
        self._state_path = self._state_directory / ACTIVE_AUTH_FILE
        self._socket_path: Path | None = None
        self._server: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._token_ready = threading.Event()
        self._bootstrap_used = False
        self._token_used = False
        self._token: str | None = None
        self._error: CallbackError | None = None

    def _prepare_state_directory(self) -> None:
        try:
            self._state_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            metadata = self._state_directory.lstat()
            if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
                raise CallbackError("authentication state directory is unsafe")
            self._state_directory.chmod(0o700)
        except OSError as exc:
            raise CallbackError("authentication state directory is unavailable") from exc

    def _clear_stale_state(self) -> None:
        if (self._state_directory / _ACTIVE_SETUP_FILE).exists():
            raise CallbackError("an extension setup exchange is active")
        if not self._state_path.exists():
            return
        try:
            metadata = self._state_path.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise CallbackError("authentication state file is unsafe")
            state = json.loads(self._state_path.read_text())
            if not isinstance(state, dict) or set(state) != {"pid", "socket"}:
                raise CallbackError("authentication state file is invalid")
            pid = state["pid"]
            socket_name = state["socket"]
            if (
                not isinstance(pid, int)
                or pid <= 1
                or not isinstance(socket_name, str)
                or Path(socket_name).name != socket_name
            ):
                raise CallbackError("authentication state file is invalid")
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                pass
            except PermissionError as exc:
                raise CallbackError("another authentication process owns the handoff") from exc
            else:
                raise CallbackError("another authentication process is active")
            stale_socket = self._state_directory / socket_name
            if stale_socket.exists():
                socket_metadata = stale_socket.lstat()
                if (
                    not stat.S_ISSOCK(socket_metadata.st_mode)
                    or socket_metadata.st_uid != os.getuid()
                ):
                    raise CallbackError("authentication socket is unsafe")
                stale_socket.unlink()
            self._state_path.unlink()
        except (OSError, json.JSONDecodeError) as exc:
            raise CallbackError("authentication state file is invalid") from exc

    def _publish_state(self) -> None:
        if self._socket_path is None:
            raise CallbackError("authentication socket is unavailable")
        temporary = self._state_path.with_suffix(".tmp")
        temporary.write_text(
            json.dumps(
                {"pid": os.getpid(), "socket": self._socket_path.name},
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
            raise CallbackError("native host message is missing or too large")
        try:
            message = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise CallbackError("native host message is invalid") from exc
        if not isinstance(message, dict):
            raise CallbackError("native host message is invalid")
        return message

    @staticmethod
    def _write_message(stream: TextIO, message: dict[str, Any]) -> None:
        stream.write(json.dumps(message, separators=(",", ":")) + "\n")
        stream.flush()

    def _serve(self) -> None:
        try:
            if self._server is None:
                raise CallbackError("authentication socket is unavailable")
            connection, _ = self._server.accept()
            with connection:
                stream = connection.makefile("rw", encoding="utf-8", newline="\n")
                with stream:
                    bootstrap_request = self._read_message(stream)
                    if bootstrap_request != {"type": "bootstrap"} or self._bootstrap_used:
                        raise CallbackError("native host bootstrap request is invalid")
                    self._bootstrap_used = True
                    bootstrap = self._bootstrap
                    self._bootstrap = {}
                    self._write_message(
                        stream,
                        {"type": "bootstrap", "bootstrap": bootstrap},
                    )

                    token_request = self._read_message(stream)
                    if set(token_request) != {"type", "token"} or token_request.get(
                        "type"
                    ) != "token":
                        raise CallbackError("native host token request is invalid")
                    token = token_request.get("token")
                    if not isinstance(token, str) or not token or self._token_used:
                        raise CallbackError("native host token request is invalid")
                    self._token_used = True
                    self._token = token
                    self._write_message(stream, {"type": "accepted"})
        except (CallbackError, OSError) as exc:
            self._error = (
                exc
                if isinstance(exc, CallbackError)
                else CallbackError("native host connection failed")
            )
        finally:
            self._token_ready.set()

    def __enter__(self) -> "TokenCallback":
        self._prepare_state_directory()
        self._clear_stale_state()
        socket_name = f"authentication-{secrets.token_hex(8)}.sock"
        self._socket_path = self._state_directory / socket_name
        try:
            self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._server.bind(str(self._socket_path))
            self._socket_path.chmod(0o600)
            self._server.listen(1)
            self._publish_state()
        except OSError as exc:
            self.__exit__(None, None, None)
            raise CallbackError("authentication socket could not be created") from exc
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        return self

    def wait(self) -> str:
        if not self._token_ready.wait(self._timeout_seconds):
            raise CallbackTimeout("Chrome did not return a VPN token before timeout")
        if self._error is not None:
            raise self._error
        if self._token is None:
            raise CallbackTimeout("VPN token was unavailable")
        token = self._token
        self._token = None
        return token

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
            self._socket_path = None
        self._bootstrap = {}
        self._token = None
