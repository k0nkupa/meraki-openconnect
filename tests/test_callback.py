import json
import socket
import stat
import tempfile
import time
from pathlib import Path

import pytest

from meraki_openconnect.callback import TokenCallback
from meraki_openconnect.callback import CallbackError


ACTIVE_AUTH_FILE = "authentication.json"


def _read_message(stream):
    return json.loads(stream.readline())


def test_callback_exchanges_bootstrap_and_token_over_private_user_socket():
    bootstrap = {"loginUrl": "https://example.test/login", "cookies": []}

    with tempfile.TemporaryDirectory(prefix="meraki-openconnect-test-", dir="/tmp") as temporary:
        state_directory = Path(temporary)
        with TokenCallback(
            bootstrap,
            timeout_seconds=1,
            state_directory=state_directory,
        ) as callback:
            state_path = state_directory / ACTIVE_AUTH_FILE
            state = json.loads(state_path.read_text())
            socket_path = state_directory / state["socket"]

            assert set(state) == {"pid", "socket"}
            assert stat.S_IMODE(state_directory.stat().st_mode) == 0o700
            assert stat.S_IMODE(state_path.stat().st_mode) == 0o600
            assert stat.S_IMODE(socket_path.stat().st_mode) == 0o600
            assert not hasattr(callback, "nonce")
            assert not hasattr(callback, "base_url")

            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.connect(str(socket_path))
                stream = client.makefile("rw", encoding="utf-8", newline="\n")
                stream.write('{"type":"bootstrap"}\n')
                stream.flush()
                assert _read_message(stream) == {
                    "type": "bootstrap",
                    "bootstrap": bootstrap,
                }

                stream.write('{"type":"token","token":"token-for-test"}\n')
                stream.flush()
                assert _read_message(stream) == {"type": "accepted"}

            assert callback.wait() == "token-for-test"

    assert not state_path.exists()
    assert not socket_path.exists()


def test_callback_shutdown_stops_idle_accept_thread():
    with tempfile.TemporaryDirectory(prefix="meraki-openconnect-test-", dir="/tmp") as temporary:
        with TokenCallback(
            {"loginUrl": "https://example.test/login", "cookies": []},
            timeout_seconds=0.01,
            state_directory=Path(temporary),
        ) as callback:
            thread = callback._thread
            time.sleep(0.02)

        assert thread is not None
        assert thread.is_alive() is False


def test_authentication_callback_rejects_setup_messages():
    with tempfile.TemporaryDirectory(prefix="meraki-openconnect-test-", dir="/tmp") as temporary:
        with TokenCallback(
            {"loginUrl": "https://example.test/login", "cookies": []},
            timeout_seconds=1,
            state_directory=Path(temporary),
        ) as callback:
            state = json.loads((Path(temporary) / ACTIVE_AUTH_FILE).read_text())
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.connect(str(Path(temporary) / state["socket"]))
                client.sendall(b'{"type":"setup-bootstrap"}\n')
            with pytest.raises(CallbackError):
                callback.wait()


def test_authentication_refuses_active_setup_exchange(tmp_path: Path):
    tmp_path.chmod(0o700)
    (tmp_path / "extension-setup.json").write_text("{}\n")

    with pytest.raises(CallbackError, match="setup exchange"):
        TokenCallback(
            {"loginUrl": "https://example.test/login", "cookies": []},
            state_directory=tmp_path,
        ).__enter__()
