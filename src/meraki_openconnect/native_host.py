"""Chrome Native Messaging bridge for the active private authentication exchange."""

from __future__ import annotations

import json
import os
import re
import shlex
import socket
import stat
import struct
import sys
from pathlib import Path
from typing import Any, BinaryIO, TextIO

from meraki_openconnect.callback import ACTIVE_AUTH_FILE, default_state_directory
from meraki_openconnect.extension_setup import (
    ACTIVE_SETUP_FILE,
    setup_socket_directory,
)


NATIVE_HOST_NAME = "io.github.k0nkupa.meraki_openconnect"
_HEADER = struct.Struct("=I")
_MAX_REQUEST_BYTES = 16 * 1024
_MAX_RESPONSE_BYTES = 1024 * 1024
_EXTENSION_ID = re.compile(r"[a-p]{32}\Z")
_SOL_LOCAL = 0
_LOCAL_PEERPID = 0x002


class NativeHostError(RuntimeError):
    """The native host request or private controller endpoint is unsafe."""


def _native_host_paths(home: Path) -> tuple[Path, Path]:
    manifest = (
        home
        / "Library"
        / "Application Support"
        / "Google"
        / "Chrome"
        / "NativeMessagingHosts"
        / f"{NATIVE_HOST_NAME}.json"
    )
    wrapper = home / ".local" / "share" / "meraki-openconnect" / "native-host"
    return manifest, wrapper


def _wrapper_text(executable: Path) -> str:
    return (
        "#!/bin/sh\n"
        f"exec {shlex.quote(str(executable))} -m meraki_openconnect.native_host\n"
    )


def configure_native_host(
    extension_id: str,
    *,
    home: Path | None = None,
    python_executable: Path | None = None,
) -> Path:
    """Install a user-owned Chrome host restricted to one extension origin."""
    if not _EXTENSION_ID.fullmatch(extension_id):
        raise NativeHostError("Chrome extension ID must contain 32 letters a-p")
    executable = python_executable or Path(sys.executable)
    if not executable.is_absolute() or "\n" in str(executable):
        raise NativeHostError("native host Python executable is unsafe")
    manifest_path, wrapper_path = _native_host_paths(home or Path.home())
    wrapper_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    wrapper_path.parent.chmod(0o700)
    wrapper_temporary = wrapper_path.with_suffix(".tmp")
    wrapper_temporary.write_text(_wrapper_text(executable))
    wrapper_temporary.chmod(0o700)
    wrapper_temporary.replace(wrapper_path)
    wrapper_path.chmod(0o700)

    manifest_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    manifest_path.parent.chmod(0o700)
    manifest = {
        "name": NATIVE_HOST_NAME,
        "description": "Meraki OpenConnect private authentication bridge",
        "path": str(wrapper_path),
        "type": "stdio",
        "allowed_origins": [f"chrome-extension://{extension_id}/"],
    }
    manifest_temporary = manifest_path.with_suffix(".tmp")
    manifest_temporary.write_text(json.dumps(manifest, sort_keys=True) + "\n")
    manifest_temporary.chmod(0o600)
    manifest_temporary.replace(manifest_path)
    manifest_path.chmod(0o600)
    return manifest_path


def native_host_configured(
    extension_id: str,
    *,
    home: Path | None = None,
    python_executable: Path | None = None,
) -> bool:
    """Return whether the exact extension-to-host binding is safely installed."""
    if not _EXTENSION_ID.fullmatch(extension_id):
        return False
    executable = python_executable or Path(sys.executable)
    manifest_path, wrapper_path = _native_host_paths(home or Path.home())
    try:
        manifest_directory = manifest_path.parent.lstat()
        wrapper_directory = wrapper_path.parent.lstat()
        manifest_metadata = manifest_path.lstat()
        wrapper_metadata = wrapper_path.lstat()
        if (
            not executable.is_absolute()
            or not stat.S_ISDIR(manifest_directory.st_mode)
            or manifest_directory.st_uid != os.getuid()
            or stat.S_IMODE(manifest_directory.st_mode) != 0o700
            or not stat.S_ISDIR(wrapper_directory.st_mode)
            or wrapper_directory.st_uid != os.getuid()
            or stat.S_IMODE(wrapper_directory.st_mode) != 0o700
            or not stat.S_ISREG(manifest_metadata.st_mode)
            or manifest_metadata.st_uid != os.getuid()
            or stat.S_IMODE(manifest_metadata.st_mode) != 0o600
            or not stat.S_ISREG(wrapper_metadata.st_mode)
            or wrapper_metadata.st_uid != os.getuid()
            or stat.S_IMODE(wrapper_metadata.st_mode) != 0o700
        ):
            return False
        manifest = json.loads(manifest_path.read_text())
        wrapper = wrapper_path.read_text()
    except (OSError, json.JSONDecodeError):
        return False
    return wrapper == _wrapper_text(executable) and manifest == {
        "name": NATIVE_HOST_NAME,
        "description": "Meraki OpenConnect private authentication bridge",
        "path": str(wrapper_path),
        "type": "stdio",
        "allowed_origins": [f"chrome-extension://{extension_id}/"],
    }


def _read_exact(stream: BinaryIO, length: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < length:
        chunk = stream.read(length - len(chunks))
        if not chunk:
            raise NativeHostError("native messaging request ended unexpectedly")
        chunks.extend(chunk)
    return bytes(chunks)


def _read_native_message(stream: BinaryIO) -> dict[str, Any]:
    header = _read_exact(stream, _HEADER.size)
    length = _HEADER.unpack(header)[0]
    if not 1 <= length <= _MAX_REQUEST_BYTES:
        raise NativeHostError("native messaging request is too large")
    try:
        message = json.loads(_read_exact(stream, length))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NativeHostError("native messaging request is invalid") from exc
    if not isinstance(message, dict):
        raise NativeHostError("native messaging request is invalid")
    return message


def _write_native_message(stream: BinaryIO, message: dict[str, Any]) -> None:
    payload = json.dumps(message, separators=(",", ":")).encode()
    if len(payload) > _MAX_RESPONSE_BYTES:
        raise NativeHostError("native messaging response is too large")
    stream.write(_HEADER.pack(len(payload)))
    stream.write(payload)
    stream.flush()


def _read_controller_message(stream: TextIO) -> dict[str, Any]:
    raw = stream.readline(_MAX_RESPONSE_BYTES + 1)
    if not raw or len(raw.encode()) > _MAX_RESPONSE_BYTES:
        raise NativeHostError("controller response is missing or too large")
    try:
        message = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise NativeHostError("controller response is invalid") from exc
    if not isinstance(message, dict):
        raise NativeHostError("controller response is invalid")
    return message


def _load_socket_path(state_directory: Path) -> tuple[str, Path, int]:
    try:
        directory_metadata = state_directory.lstat()
        if (
            not stat.S_ISDIR(directory_metadata.st_mode)
            or directory_metadata.st_uid != os.getuid()
            or stat.S_IMODE(directory_metadata.st_mode) != 0o700
        ):
            raise NativeHostError("authentication state directory is unsafe")
        active = [
            ("authentication", state_directory / ACTIVE_AUTH_FILE),
            ("setup", state_directory / ACTIVE_SETUP_FILE),
        ]
        existing = [(mode, path) for mode, path in active if path.exists()]
        if len(existing) != 1:
            raise NativeHostError("active private exchange is unavailable")
        mode, state_path = existing[0]
        state_metadata = state_path.lstat()
        if (
            not stat.S_ISREG(state_metadata.st_mode)
            or state_metadata.st_uid != os.getuid()
            or stat.S_IMODE(state_metadata.st_mode) != 0o600
        ):
            raise NativeHostError(f"{mode} state file is unsafe")
        state = json.loads(state_path.read_text())
        if not isinstance(state, dict) or set(state) != {"pid", "socket"}:
            raise NativeHostError(f"{mode} state file is invalid")
        pid = state["pid"]
        socket_name = state["socket"]
        if (
            not isinstance(pid, int)
            or pid <= 1
            or not isinstance(socket_name, str)
        ):
            raise NativeHostError(f"{mode} state file is invalid")
        socket_value = Path(socket_name)
        if mode == "setup" and socket_value.is_absolute():
            socket_directory = setup_socket_directory()
            directory_metadata = socket_directory.lstat()
            if (
                socket_value.parent != socket_directory
                or socket_value.name != socket_name.rsplit("/", 1)[-1]
                or not stat.S_ISDIR(directory_metadata.st_mode)
                or directory_metadata.st_uid != os.getuid()
                or stat.S_IMODE(directory_metadata.st_mode) != 0o700
            ):
                raise NativeHostError("setup socket directory is unsafe")
            socket_path = socket_value
        elif socket_value.name == socket_name:
            socket_path = state_directory / socket_name
        else:
            raise NativeHostError(f"{mode} state file is invalid")
        os.kill(pid, 0)
        socket_metadata = socket_path.lstat()
        if (
            not stat.S_ISSOCK(socket_metadata.st_mode)
            or socket_metadata.st_uid != os.getuid()
            or stat.S_IMODE(socket_metadata.st_mode) != 0o600
        ):
            raise NativeHostError(f"{mode} socket is unsafe")
        return mode, socket_path, pid
    except (OSError, json.JSONDecodeError) as exc:
        raise NativeHostError("active authentication exchange is unavailable") from exc


def _controller_peer_pid(client: socket.socket) -> int:
    """Return the PID at the other end of a macOS local-domain socket."""
    try:
        raw_pid = client.getsockopt(
            _SOL_LOCAL,
            _LOCAL_PEERPID,
            struct.calcsize("i"),
        )
        peer_pid = struct.unpack("i", raw_pid)[0]
    except (OSError, struct.error) as exc:
        raise NativeHostError("controller identity could not be verified") from exc
    if peer_pid <= 1:
        raise NativeHostError("controller identity could not be verified")
    return peer_pid


def run_native_host(
    input_stream: BinaryIO,
    output_stream: BinaryIO,
    *,
    state_directory: Path | None = None,
) -> None:
    """Bridge two bounded Chrome messages to the current user-owned exchange."""
    mode, socket_path, controller_pid = _load_socket_path(
        state_directory or default_state_directory()
    )
    expected_types = (
        ("setup-bootstrap", "setup-result")
        if mode == "setup"
        else ("bootstrap", "token")
    )
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.connect(str(socket_path))
            if _controller_peer_pid(client) != controller_pid:
                raise NativeHostError("controller identity is unsafe")
            controller = client.makefile("rw", encoding="utf-8", newline="\n")
            with controller:
                for expected_type in expected_types:
                    message = _read_native_message(input_stream)
                    if message.get("type") != expected_type:
                        raise NativeHostError("native messaging request order is invalid")
                    controller.write(json.dumps(message, separators=(",", ":")) + "\n")
                    controller.flush()
                    response = _read_controller_message(controller)
                    _write_native_message(output_stream, response)
    except OSError as exc:
        raise NativeHostError("active authentication exchange failed") from exc


def entrypoint() -> None:
    try:
        run_native_host(sys.stdin.buffer, sys.stdout.buffer)
    except NativeHostError:
        raise SystemExit(1) from None


if __name__ == "__main__":
    entrypoint()
