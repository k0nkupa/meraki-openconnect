from __future__ import annotations

import json
import socket
import stat
import time
from pathlib import Path

import pytest

from meraki_openconnect.extension_setup import (
    ACTIVE_SETUP_FILE,
    ExtensionPermissionReceipt,
    ExtensionSetupCallback,
    ExtensionSetupError,
    ExtensionSetupTimeout,
)


ORIGIN = "https://vpn.example.com"
DIGEST = "sha256:" + "1" * 64


def _exchange(
    socket_path: Path,
    result: dict[str, object] | None = None,
) -> ExtensionPermissionReceipt:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.connect(str(socket_path))
        stream = client.makefile("rw", encoding="utf-8", newline="\n")
        with stream:
            stream.write('{"type":"setup-bootstrap"}\n')
            stream.flush()
            assert json.loads(stream.readline()) == {
                "type": "setup-bootstrap",
                "gatewayOrigin": ORIGIN,
                "profileDigest": DIGEST,
            }
            payload = result or {
                "type": "setup-result",
                "gatewayOrigin": ORIGIN,
                "profileDigest": DIGEST,
                "granted": True,
            }
            stream.write(json.dumps(payload) + "\n")
            stream.flush()
            assert json.loads(stream.readline()) == {"type": "accepted"}
    return ExtensionPermissionReceipt(ORIGIN, DIGEST, bool(payload["granted"]))


def test_setup_receipt_matches_candidate_policy(tmp_path: Path) -> None:
    with ExtensionSetupCallback(
        gateway_origin=ORIGIN,
        profile_digest=DIGEST,
        state_directory=tmp_path,
    ) as callback:
        expected = _exchange(callback.socket_path)
        receipt = callback.wait()
        with pytest.raises(ExtensionSetupTimeout):
            callback.wait()
        state_path = tmp_path / ACTIVE_SETUP_FILE
        assert stat.S_IMODE(tmp_path.stat().st_mode) == 0o700
        assert stat.S_IMODE(state_path.stat().st_mode) == 0o600

    assert receipt == expected
    assert not state_path.exists()
    assert not callback.socket_path.exists()


@pytest.mark.parametrize(
    "changed",
    [
        {
            "type": "setup-result",
            "gatewayOrigin": "https://other.example.com",
            "profileDigest": DIGEST,
            "granted": True,
        },
        {
            "type": "setup-result",
            "gatewayOrigin": ORIGIN,
            "profileDigest": "sha256:" + "2" * 64,
            "granted": True,
        },
        {"type": "token", "token": "forbidden"},
    ],
)
def test_setup_rejects_mismatch_and_authentication_messages(
    tmp_path: Path, changed: dict[str, object]
) -> None:
    with ExtensionSetupCallback(
        gateway_origin=ORIGIN,
        profile_digest=DIGEST,
        state_directory=tmp_path,
    ) as callback:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.connect(str(callback.socket_path))
            stream = client.makefile("rw", encoding="utf-8", newline="\n")
            stream.write('{"type":"setup-bootstrap"}\n')
            stream.flush()
            json.loads(stream.readline())
            stream.write(json.dumps(changed) + "\n")
            stream.flush()
        with pytest.raises(ExtensionSetupError):
            callback.wait()


def test_setup_records_explicit_permission_denial(tmp_path: Path) -> None:
    with ExtensionSetupCallback(
        gateway_origin=ORIGIN,
        profile_digest=DIGEST,
        state_directory=tmp_path,
    ) as callback:
        _exchange(
            callback.socket_path,
            {
                "type": "setup-result",
                "gatewayOrigin": ORIGIN,
                "profileDigest": DIGEST,
                "granted": False,
            },
        )
        assert callback.wait().granted is False


def test_setup_rejects_unsafe_existing_state_file(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    state = tmp_path / ACTIVE_SETUP_FILE
    state.write_text('{}\n')
    state.chmod(0o644)

    with pytest.raises(ExtensionSetupError, match="unsafe"):
        ExtensionSetupCallback(
            gateway_origin=ORIGIN,
            profile_digest=DIGEST,
            state_directory=tmp_path,
        ).__enter__()


def test_setup_timeout_and_idle_shutdown_clean_state(tmp_path: Path) -> None:
    callback = ExtensionSetupCallback(
        gateway_origin=ORIGIN,
        profile_digest=DIGEST,
        timeout_seconds=0.01,
        state_directory=tmp_path,
    )
    with callback:
        thread = callback._thread
        socket_path = callback.socket_path
        with pytest.raises(ExtensionSetupTimeout):
            callback.wait()
        time.sleep(0.02)

    assert thread is not None and not thread.is_alive()
    assert not socket_path.exists()
    assert not (tmp_path / ACTIVE_SETUP_FILE).exists()
