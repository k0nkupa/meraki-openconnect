import io
import json
import multiprocessing
import os
import socket
import stat
import struct
import tempfile
from pathlib import Path

import pytest

from meraki_openconnect.callback import TokenCallback
from meraki_openconnect.extension_setup import ExtensionSetupCallback
from meraki_openconnect.native_host import NativeHostError, run_native_host


HEADER = struct.Struct("=I")


def _frame(message: dict[str, object]) -> bytes:
    payload = json.dumps(message, separators=(",", ":")).encode()
    return HEADER.pack(len(payload)) + payload


def _messages(payload: bytes) -> list[dict[str, object]]:
    messages = []
    stream = io.BytesIO(payload)
    while header := stream.read(HEADER.size):
        length = HEADER.unpack(header)[0]
        messages.append(json.loads(stream.read(length)))
    return messages


def test_native_host_bridges_only_the_active_private_exchange():
    bootstrap = {"loginUrl": "https://example.test/login", "cookies": []}
    native_input = io.BytesIO(
        _frame({"type": "bootstrap"})
        + _frame({"type": "token", "token": "token-for-test"})
    )
    native_output = io.BytesIO()

    with tempfile.TemporaryDirectory(prefix="meraki-openconnect-test-", dir="/tmp") as temporary:
        state_directory = Path(temporary)
        with TokenCallback(
            bootstrap,
            timeout_seconds=1,
            state_directory=state_directory,
        ) as callback:
            run_native_host(
                native_input,
                native_output,
                state_directory=state_directory,
            )
            assert callback.wait() == "token-for-test"

    assert _messages(native_output.getvalue()) == [
        {"type": "bootstrap", "bootstrap": bootstrap},
        {"type": "accepted"},
    ]


def test_configure_native_host_binds_chrome_to_the_exact_extension(tmp_path):
    try:
        from meraki_openconnect.native_host import configure_native_host, native_host_configured
    except ImportError:
        pytest.fail("native host configuration support is missing")

    extension_id = "abcdefghijklmnopabcdefghijklmnop"
    manifest_path = configure_native_host(
        extension_id,
        home=tmp_path,
        python_executable=Path("/opt/meraki-openconnect/python3"),
    )
    manifest = json.loads(manifest_path.read_text())
    wrapper_path = Path(manifest["path"])

    assert manifest == {
        "name": "io.github.k0nkupa.meraki_openconnect",
        "description": "Meraki OpenConnect private authentication bridge",
        "path": str(wrapper_path),
        "type": "stdio",
        "allowed_origins": [f"chrome-extension://{extension_id}/"],
    }
    assert wrapper_path.read_text() == (
        "#!/bin/sh\nexec /opt/meraki-openconnect/python3 -m meraki_openconnect.native_host\n"
    )
    assert stat.S_IMODE(wrapper_path.stat().st_mode) == 0o700
    assert stat.S_IMODE(manifest_path.stat().st_mode) == 0o600
    assert native_host_configured(
        extension_id,
        home=tmp_path,
        python_executable=Path("/opt/meraki-openconnect/python3"),
    ) is True


def test_native_host_rejects_world_readable_authentication_state():
    with tempfile.TemporaryDirectory(prefix="meraki-openconnect-test-", dir="/tmp") as temporary:
        state_directory = Path(temporary)
        with TokenCallback(
            {"loginUrl": "https://example.test/login", "cookies": []},
            timeout_seconds=0.01,
            state_directory=state_directory,
        ):
            (state_directory / "authentication.json").chmod(0o644)
            with pytest.raises(NativeHostError, match="unsafe"):
                run_native_host(
                    io.BytesIO(_frame({"type": "bootstrap"})),
                    io.BytesIO(),
                    state_directory=state_directory,
                )


def test_native_host_preserves_bounded_large_bootstrap_payloads():
    bootstrap = {
        "loginUrl": "https://example.test/login",
        "cookies": [{"name": "synthetic", "value": "x" * (20 * 1024)}],
    }
    native_input = io.BytesIO(
        _frame({"type": "bootstrap"})
        + _frame({"type": "token", "token": "token-for-test"})
    )
    native_output = io.BytesIO()

    with tempfile.TemporaryDirectory(prefix="meraki-openconnect-test-", dir="/tmp") as temporary:
        state_directory = Path(temporary)
        with TokenCallback(
            bootstrap,
            timeout_seconds=1,
            state_directory=state_directory,
        ) as callback:
            run_native_host(
                native_input,
                native_output,
                state_directory=state_directory,
            )
            assert callback.wait() == "token-for-test"

    assert _messages(native_output.getvalue())[0] == {
        "type": "bootstrap",
        "bootstrap": bootstrap,
    }


def test_native_host_routes_only_setup_messages_to_setup_exchange(tmp_path: Path):
    native_input = io.BytesIO(
        _frame({"type": "setup-bootstrap"})
        + _frame(
            {
                "type": "setup-result",
                "gatewayOrigin": "https://vpn.example.com",
                "profileDigest": "sha256:" + "1" * 64,
                "granted": True,
            }
        )
    )
    native_output = io.BytesIO()

    with ExtensionSetupCallback(
        gateway_origin="https://vpn.example.com",
        profile_digest="sha256:" + "1" * 64,
        timeout_seconds=1,
        state_directory=tmp_path,
    ) as callback:
        run_native_host(native_input, native_output, state_directory=tmp_path)
        assert callback.wait().granted is True

    assert _messages(native_output.getvalue()) == [
        {
            "type": "setup-bootstrap",
            "gatewayOrigin": "https://vpn.example.com",
            "profileDigest": "sha256:" + "1" * 64,
        },
        {"type": "accepted"},
    ]


def test_native_host_rejects_authentication_message_in_setup_mode(tmp_path: Path):
    with ExtensionSetupCallback(
        gateway_origin="https://vpn.example.com",
        profile_digest="sha256:" + "1" * 64,
        timeout_seconds=0.01,
        state_directory=tmp_path,
    ):
        with pytest.raises(NativeHostError, match="order"):
            run_native_host(
                io.BytesIO(_frame({"type": "bootstrap"})),
                io.BytesIO(),
                state_directory=tmp_path,
            )


def _serve_replacement_socket(socket_path: str, ready) -> None:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(socket_path)
        os.chmod(socket_path, 0o600)
        server.listen(1)
        ready.set()
        connection, _ = server.accept()
        with connection:
            connection.recv(4096)


def test_native_host_rejects_socket_server_that_is_not_published_controller():
    with tempfile.TemporaryDirectory(
        prefix="moc-peer-test-", dir="/tmp"
    ) as temporary:
        state_directory = Path(temporary)
        socket_path = state_directory / "replaced.sock"
        ready = multiprocessing.Event()
        replacement = multiprocessing.Process(
            target=_serve_replacement_socket,
            args=(str(socket_path), ready),
        )
        replacement.start()
        try:
            assert ready.wait(timeout=2)
            state_path = state_directory / "authentication.json"
            state_path.write_text(
                json.dumps({"pid": os.getpid(), "socket": socket_path.name}) + "\n"
            )
            state_path.chmod(0o600)

            with pytest.raises(NativeHostError, match="controller identity"):
                run_native_host(
                    io.BytesIO(_frame({"type": "bootstrap"})),
                    io.BytesIO(),
                    state_directory=state_directory,
                )
        finally:
            replacement.join(timeout=2)
            if replacement.is_alive():
                replacement.terminate()
                replacement.join(timeout=2)
