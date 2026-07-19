import io
import json
import stat
import subprocess
from pathlib import Path

import pytest

from meraki_openconnect.health import HealthCheckResult
from meraki_openconnect.profile import OrganizationProfile
from meraki_openconnect.privileged import HELPER_PATH
from meraki_openconnect.settings import MachineSettings
from meraki_openconnect.tunnel import (
    TunnelError,
    TunnelSession,
    TunnelStore,
    Frame,
    MessageType,
    disconnect_tunnel,
    read_frame,
    run_tunnel,
    _run_privileged_operation,
    _DnsSetupError,
    _require_readiness,
    _browser_token,
    _SubprocessWorker,
    _verify_privileged_helper,
    write_frame,
)


class FakeWorker:
    def __init__(self, frames: list[Frame]):
        self.frames = list(frames)
        self.written: list[Frame] = []
        self.closed = False

    def read_frame(self, timeout: float | None = None) -> Frame:
        del timeout
        if not self.frames:
            raise EOFError
        return self.frames.pop(0)

    def write_frame(self, frame: Frame) -> None:
        self.written.append(frame)

    def close(self) -> None:
        self.closed = True


PROFILE = OrganizationProfile.load(
    Path(__file__).parents[1] / "examples" / "profile.example.json"
)
PIN = "pin-sha256:" + "A" * 43 + "="
SETTINGS = MachineSettings(
    schema_version=1,
    chrome_profile_directory="Profile 1",
    extension_id="a" * 32,
    extension_gateway_origin="https://vpn.example.com",
    extension_profile_digest=PROFILE.profile_digest(),
    server_cert_pin=PIN,
    installed_policy_digest="sha256:" + "1" * 64,
)
GATEWAY = PROFILE.gateway.host
FINAL_URL = f"https://{GATEWAY}{PROFILE.authentication.final_path}"
PASSED_CHECKS = (
    HealthCheckResult("route", "192.0.2.53", True),
    HealthCheckResult("dns", "service.internal.example.com", True),
    HealthCheckResult("tcp", "192.0.2.10:443", True),
)


@pytest.fixture(autouse=True)
def ready_runtime(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        "meraki_openconnect.tunnel._require_readiness",
        lambda profile, settings: None,
    )


def test_browser_token_binds_profile_receipt_and_configured_chrome_profile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    class Callback:
        def __init__(self, bootstrap: dict[str, object]):
            captured["bootstrap"] = bootstrap

        def __enter__(self):
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def wait(self) -> str:
            return "opaque-token"

    monkeypatch.setattr("meraki_openconnect.tunnel.TokenCallback", Callback)
    monkeypatch.setattr(
        "meraki_openconnect.tunnel.open_in_chrome_profile",
        lambda url, profile: captured.update(url=url, profile=profile),
    )

    assert _browser_token(
        f"https://{GATEWAY}{PROFILE.authentication.login_path}",
        PROFILE,
        SETTINGS.browser_settings,
    ) == "opaque-token"
    bootstrap = captured["bootstrap"]
    assert isinstance(bootstrap, dict)
    assert bootstrap["gatewayOrigin"] == f"https://{GATEWAY}"
    assert bootstrap["profileDigest"] == PROFILE.profile_digest()
    assert captured["profile"] == SETTINGS.chrome_profile_directory


def test_python_frame_round_trip_matches_native_shape():
    output = io.BytesIO()
    frame = Frame(
        MessageType.CONNECTED,
        ("321", "utun9", "192.0.2.20", "dtls"),
    )

    write_frame(output, frame)
    output.seek(0)

    assert read_frame(output) == frame
    assert len(output.getvalue()[:17]) == 17


def test_frame_rejects_control_characters():
    with pytest.raises(TunnelError, match="printable ASCII"):
        write_frame(io.BytesIO(), Frame(MessageType.STAGE, ("auth\ntoken",)))


def test_unknown_frame_reports_only_numeric_message_type():
    stream = io.BytesIO(b"C" + (b"\0" * 16))

    with pytest.raises(TunnelError, match=r"unknown message type 67$"):
        read_frame(stream)


def test_privileged_operation_rejects_non_mutation_before_subprocess(
    monkeypatch: pytest.MonkeyPatch,
):
    calls: list[list[str]] = []
    monkeypatch.setattr(
        "meraki_openconnect.tunnel.subprocess.run",
        lambda args, **_kwargs: calls.append(args),
    )

    with pytest.raises(TunnelError, match="unsupported privileged operation"):
        _run_privileged_operation("policy-digest")

    assert calls == []


@pytest.mark.parametrize(
    ("returncode", "rollback_complete"), ((1, True), (2, False), (70, False))
)
def test_dns_setup_exit_code_distinguishes_clean_and_failed_rollback(
    monkeypatch: pytest.MonkeyPatch,
    returncode: int,
    rollback_complete: bool,
) -> None:
    def runner(args: list[str], **_kwargs: object) -> None:
        raise subprocess.CalledProcessError(returncode, args)

    monkeypatch.setattr("meraki_openconnect.tunnel.subprocess.run", runner)

    with pytest.raises(_DnsSetupError) as caught:
        _run_privileged_operation("dns-connect")

    assert caught.value.rollback_complete is rollback_complete


def test_outdated_privileged_helper_requests_reinstall(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(
        "meraki_openconnect.tunnel.installed_policy_digest", lambda: None
    )

    with pytest.raises(
        TunnelError,
        match=r"^privileged helper is outdated; run meraki-openconnect privileged install$",
    ):
        _verify_privileged_helper("sha256:" + "1" * 64)


def test_privileged_helper_digest_must_match_expected_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "meraki_openconnect.tunnel.installed_policy_digest",
        lambda: "sha256:" + "2" * 64,
    )

    with pytest.raises(TunnelError, match="privileged policy is outdated"):
        _verify_privileged_helper("sha256:" + "1" * 64)


def test_store_persists_only_non_secret_state(tmp_path: Path):
    store = TunnelStore(tmp_path)
    legacy_names = ("session.json", "openconnect.pid", "experimental.json")
    for name in legacy_names:
        (tmp_path / name).write_text("legacy")
    session = TunnelSession(
        pid=321,
        gateway=GATEWAY,
        interface="utun9",
        address="192.0.2.20",
        transport="dtls",
    )

    store.save(session)

    assert store.path == tmp_path / "tunnel.json"
    assert all(not (tmp_path / name).exists() for name in legacy_names)
    assert store.load() == session
    assert json.loads(store.path.read_text()) == {
        "address": "192.0.2.20",
        "gateway": GATEWAY,
        "interface": "utun9",
        "pid": 321,
        "transport": "dtls",
    }
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o600
    for forbidden in ("token", "cookie", "assertion", "secret", "strap", "query"):
        assert forbidden not in store.path.read_text().lower()


def test_store_clears_state_when_worker_identity_is_not_verified(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    store = TunnelStore(tmp_path)
    store.save(TunnelSession(321, GATEWAY, "utun9", "192.0.2.20", "dtls"))
    monkeypatch.setattr("meraki_openconnect.tunnel._verify_worker", lambda _pid: False)

    assert store.load_verified() is None
    assert store.path.exists() is False


def test_controller_returns_webview_result_to_same_worker(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    login_url = f"https://{GATEWAY}/saml/sp/login?state=abc"
    worker = FakeWorker(
        [
            Frame(MessageType.STAGE, ("auth",)),
            Frame(MessageType.WEBVIEW_REQUIRED, (login_url,)),
            Frame(MessageType.CONNECTED, ("321", "utun9", "192.0.2.20", "dtls")),
            Frame(MessageType.DISCONNECTED),
        ]
    )
    events: list[tuple[TunnelSession, tuple[HealthCheckResult, ...]]] = []
    order: list[str] = []
    store = TunnelStore(tmp_path)
    original_save = store.save
    monkeypatch.setattr("meraki_openconnect.tunnel._start_worker", lambda: worker)
    monkeypatch.setattr(
        "meraki_openconnect.tunnel.gateway_tls_pin",
        lambda _gateway: SETTINGS.server_cert_pin,
    )
    monkeypatch.setattr("meraki_openconnect.tunnel._browser_token", lambda *_args: "opaque-token")
    monkeypatch.setattr("meraki_openconnect.tunnel._verify_worker", lambda _pid: True)
    monkeypatch.setattr(
        "meraki_openconnect.tunnel._run_privileged_operation",
        lambda operation: order.append(operation),
        raising=False,
    )
    monkeypatch.setattr(
        store,
        "save",
        lambda session: (order.append("save"), original_save(session))[1],
    )
    monkeypatch.setattr(
        "meraki_openconnect.tunnel.run_health_checks",
        lambda checks, interface: order.append("health-checks")
        or PASSED_CHECKS,
    )

    session = run_tunnel(
        PROFILE,
        SETTINGS,
        on_connected=lambda current, checks: events.append((current, checks)),
        store=store,
    )

    assert worker.written == [
        Frame(MessageType.WEBVIEW_RESULT, (FINAL_URL, "opaque-token"))
    ]
    assert session.interface == "utun9"
    assert events == [(session, PASSED_CHECKS)]
    assert order == [
        "dns-connect",
        "save",
        "health-checks",
        "dns-disconnect",
    ]
    assert store.path.exists() is False
    assert worker.closed is True


def test_pin_mismatch_stops_before_worker_start(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    started = []
    monkeypatch.setattr("meraki_openconnect.tunnel.gateway_tls_pin", lambda _gateway: "pin-sha256:changed")
    monkeypatch.setattr("meraki_openconnect.tunnel._start_worker", lambda: started.append(True))

    with pytest.raises(TunnelError, match="certificate pin changed"):
        run_tunnel(
            PROFILE,
            SETTINGS,
            on_connected=lambda *_args: None,
            store=TunnelStore(tmp_path),
        )

    assert started == []


def test_policy_mismatch_stops_before_worker_start(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    started: list[bool] = []
    monkeypatch.setattr(
        "meraki_openconnect.tunnel._require_readiness", _require_readiness
    )
    monkeypatch.setattr(
        "meraki_openconnect.tunnel.installed_policy_digest",
        lambda: "sha256:" + "9" * 64,
    )
    monkeypatch.setattr(
        "meraki_openconnect.tunnel.privileged_component_installed",
        lambda path: True,
    )
    monkeypatch.setattr(
        "meraki_openconnect.tunnel._start_worker", lambda: started.append(True)
    )

    with pytest.raises(TunnelError, match="setup is not ready"):
        run_tunnel(
            PROFILE,
            SETTINGS,
            on_connected=lambda *_args: None,
            store=TunnelStore(tmp_path),
        )

    assert started == []


def test_wrong_webview_host_is_rejected_without_echoing_query(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    worker = FakeWorker(
        [Frame(MessageType.WEBVIEW_REQUIRED, ("https://evil.example/login?secret=value",))]
    )
    monkeypatch.setattr(
        "meraki_openconnect.tunnel.gateway_tls_pin",
        lambda _gateway: SETTINGS.server_cert_pin,
    )
    monkeypatch.setattr("meraki_openconnect.tunnel._start_worker", lambda: worker)
    monkeypatch.setattr(
        "meraki_openconnect.tunnel._run_privileged_operation",
        lambda _operation: None,
    )

    with pytest.raises(TunnelError) as caught:
        run_tunnel(
            PROFILE,
            SETTINGS,
            on_connected=lambda *_args: None,
            store=TunnelStore(tmp_path),
        )

    assert "secret=value" not in str(caught.value)


def test_failed_worker_message_is_sanitized(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    worker = FakeWorker([Frame(MessageType.FAILED, ("cstp", "connection-rejected"))])
    monkeypatch.setattr(
        "meraki_openconnect.tunnel.gateway_tls_pin",
        lambda _gateway: SETTINGS.server_cert_pin,
    )
    monkeypatch.setattr("meraki_openconnect.tunnel._start_worker", lambda: worker)
    monkeypatch.setattr(
        "meraki_openconnect.tunnel._run_privileged_operation",
        lambda _operation: None,
    )

    with pytest.raises(TunnelError, match="cstp: connection-rejected"):
        run_tunnel(
            PROFILE,
            SETTINGS,
            on_connected=lambda *_args: None,
            store=TunnelStore(tmp_path),
        )


def test_exceptional_worker_failure_forces_fixed_privileged_disconnect(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    worker = FakeWorker([Frame(MessageType.STAGE, ("unexpected",))])
    operations: list[str] = []
    monkeypatch.setattr(
        "meraki_openconnect.tunnel.gateway_tls_pin",
        lambda _gateway: SETTINGS.server_cert_pin,
    )
    monkeypatch.setattr("meraki_openconnect.tunnel._start_worker", lambda: worker)
    monkeypatch.setattr(
        "meraki_openconnect.tunnel._run_privileged_operation",
        lambda operation: operations.append(operation),
    )

    with pytest.raises(TunnelError, match="invalid stage"):
        run_tunnel(
            PROFILE,
            SETTINGS,
            on_connected=lambda *_args: None,
            store=TunnelStore(tmp_path),
        )

    assert worker.written == [Frame(MessageType.CANCEL)]
    assert worker.closed is True
    assert operations == ["vpn-disconnect"]


def test_subprocess_worker_close_cannot_silently_leave_process_running(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class StubbornProcess:
        def __init__(self) -> None:
            self.stdin = io.BytesIO()
            self.stdout = io.BytesIO()
            self.waits = 0
            self.killed = False

        def wait(self, timeout: float) -> int:
            assert timeout == 5
            self.waits += 1
            if self.waits < 3:
                raise subprocess.TimeoutExpired("worker", timeout)
            return 0

        def kill(self) -> None:
            self.killed = True

    process = StubbornProcess()
    operations: list[str] = []
    monkeypatch.setattr(
        "meraki_openconnect.tunnel._run_privileged_operation",
        lambda operation: operations.append(operation),
    )

    _SubprocessWorker(process).close()  # type: ignore[arg-type]

    assert operations == ["vpn-disconnect"]
    assert process.killed is True
    assert process.waits == 3


def test_failed_forced_disconnect_still_closes_worker_with_sanitized_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    worker = FakeWorker([Frame(MessageType.STAGE, ("unexpected",))])
    monkeypatch.setattr(
        "meraki_openconnect.tunnel.gateway_tls_pin",
        lambda _gateway: SETTINGS.server_cert_pin,
    )
    monkeypatch.setattr("meraki_openconnect.tunnel._start_worker", lambda: worker)

    def fail_disconnect(operation: str) -> None:
        assert operation == "vpn-disconnect"
        raise TunnelError("private cleanup target")

    monkeypatch.setattr(
        "meraki_openconnect.tunnel._run_privileged_operation", fail_disconnect
    )

    with pytest.raises(TunnelError) as caught:
        run_tunnel(
            PROFILE,
            SETTINGS,
            on_connected=lambda *_args: None,
            store=TunnelStore(tmp_path),
        )

    assert str(caught.value) == "VPN worker cleanup failed"
    assert "private cleanup target" not in str(caught.value)
    assert worker.closed is True


def test_failed_live_checks_wait_for_disconnect_confirmation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    worker = FakeWorker(
        [
            Frame(MessageType.CONNECTED, ("321", "utun9", "192.0.2.20", "dtls")),
            Frame(MessageType.DISCONNECTED),
        ]
    )
    store = TunnelStore(tmp_path)
    operations: list[str] = []
    monkeypatch.setattr(
        "meraki_openconnect.tunnel.gateway_tls_pin",
        lambda _gateway: SETTINGS.server_cert_pin,
    )
    monkeypatch.setattr("meraki_openconnect.tunnel._start_worker", lambda: worker)
    monkeypatch.setattr("meraki_openconnect.tunnel._verify_worker", lambda _pid: True)
    monkeypatch.setattr(
        "meraki_openconnect.tunnel._run_privileged_operation",
        lambda operation: operations.append(operation),
        raising=False,
    )
    monkeypatch.setattr(
        "meraki_openconnect.tunnel.run_health_checks",
        lambda checks, interface: (
            HealthCheckResult("route", "192.0.2.53", False),
            HealthCheckResult("dns", "private.example.com", True),
        ),
    )

    with pytest.raises(TunnelError) as caught:
        run_tunnel(
            PROFILE,
            SETTINGS,
            on_connected=lambda *_args: None,
            store=store,
        )

    assert str(caught.value) == "tunnel verification failed"
    assert "192.0.2.53" not in str(caught.value)
    assert worker.written == [Frame(MessageType.CANCEL)]
    assert worker.frames == []
    assert operations == ["dns-connect", "dns-disconnect"]
    assert store.path.exists() is False


def test_failed_live_checks_retain_state_when_resolver_cleanup_fails_twice(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    worker = FakeWorker(
        [
            Frame(MessageType.CONNECTED, ("321", "utun9", "192.0.2.20", "dtls")),
            Frame(MessageType.DISCONNECTED),
        ]
    )
    store = TunnelStore(tmp_path)
    operations: list[str] = []
    monkeypatch.setattr(
        "meraki_openconnect.tunnel.gateway_tls_pin",
        lambda _gateway: SETTINGS.server_cert_pin,
    )
    monkeypatch.setattr("meraki_openconnect.tunnel._start_worker", lambda: worker)
    monkeypatch.setattr("meraki_openconnect.tunnel._verify_worker", lambda _pid: True)

    def privileged(operation: str) -> None:
        operations.append(operation)
        if operation == "dns-disconnect":
            raise TunnelError("private resolver target")

    monkeypatch.setattr(
        "meraki_openconnect.tunnel._run_privileged_operation", privileged
    )
    monkeypatch.setattr(
        "meraki_openconnect.tunnel.run_health_checks",
        lambda checks, interface: (
            HealthCheckResult("route", "192.0.2.53", False),
        ),
    )

    with pytest.raises(TunnelError) as caught:
        run_tunnel(
            PROFILE,
            SETTINGS,
            on_connected=lambda *_args: None,
            store=store,
        )

    assert str(caught.value) == "VPN worker cleanup failed"
    assert "private resolver target" not in str(caught.value)
    assert operations == ["dns-connect", "dns-disconnect", "dns-disconnect"]
    assert store.path.exists() is True
    assert worker.closed is True


def test_keyboard_interrupt_retries_resolver_cleanup_and_retains_failed_state(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    class InterruptingWorker(FakeWorker):
        def __init__(self) -> None:
            super().__init__([])
            self.reads = 0

        def read_frame(self, timeout: float | None = None) -> Frame:
            del timeout
            self.reads += 1
            if self.reads == 1:
                return Frame(
                    MessageType.CONNECTED,
                    ("321", "utun9", "192.0.2.20", "dtls"),
                )
            if self.reads == 2:
                raise KeyboardInterrupt
            return Frame(MessageType.DISCONNECTED)

    worker = InterruptingWorker()
    store = TunnelStore(tmp_path)
    operations: list[str] = []
    monkeypatch.setattr(
        "meraki_openconnect.tunnel.gateway_tls_pin",
        lambda _gateway: SETTINGS.server_cert_pin,
    )
    monkeypatch.setattr("meraki_openconnect.tunnel._start_worker", lambda: worker)
    monkeypatch.setattr("meraki_openconnect.tunnel._verify_worker", lambda _pid: True)

    def privileged(operation: str) -> None:
        operations.append(operation)
        if operation == "dns-disconnect":
            raise TunnelError("private resolver target")

    monkeypatch.setattr(
        "meraki_openconnect.tunnel._run_privileged_operation", privileged
    )
    monkeypatch.setattr(
        "meraki_openconnect.tunnel.run_health_checks",
        lambda checks, interface: PASSED_CHECKS,
    )

    with pytest.raises(TunnelError) as caught:
        run_tunnel(
            PROFILE,
            SETTINGS,
            on_connected=lambda *_args: None,
            store=store,
        )

    assert str(caught.value) == "VPN worker cleanup failed"
    assert "private resolver target" not in str(caught.value)
    assert operations == ["dns-connect", "dns-disconnect", "dns-disconnect"]
    assert store.path.exists() is True
    assert worker.closed is True


def test_partial_multi_rule_resolver_failure_retains_state_when_cleanup_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    worker = FakeWorker(
        [
            Frame(MessageType.CONNECTED, ("321", "utun9", "192.0.2.20", "dtls")),
            Frame(MessageType.DISCONNECTED),
        ]
    )
    operations: list[str] = []
    store = TunnelStore(tmp_path)
    monkeypatch.setattr(
        "meraki_openconnect.tunnel.gateway_tls_pin",
        lambda _gateway: SETTINGS.server_cert_pin,
    )
    monkeypatch.setattr("meraki_openconnect.tunnel._start_worker", lambda: worker)
    monkeypatch.setattr("meraki_openconnect.tunnel._verify_worker", lambda _pid: True)

    def privileged(operation: str) -> None:
        operations.append(operation)
        if operation == "dns-connect":
            raise _DnsSetupError(rollback_complete=False)
        raise TunnelError("DNS resolver cleanup failed")

    monkeypatch.setattr(
        "meraki_openconnect.tunnel._run_privileged_operation", privileged, raising=False
    )

    with pytest.raises(TunnelError, match=r"^VPN worker cleanup failed$"):
        run_tunnel(
            PROFILE,
            SETTINGS,
            on_connected=lambda *_args: None,
            store=store,
        )

    assert worker.written == [Frame(MessageType.CANCEL)]
    assert operations == ["dns-connect", "dns-disconnect", "dns-disconnect"]
    assert store.path.exists() is True


def test_clean_dns_setup_rollback_skips_generic_resolver_cleanup(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    worker = FakeWorker(
        [
            Frame(MessageType.CONNECTED, ("321", "utun9", "192.0.2.20", "dtls")),
            Frame(MessageType.DISCONNECTED),
        ]
    )
    operations: list[str] = []
    store = TunnelStore(tmp_path)
    monkeypatch.setattr(
        "meraki_openconnect.tunnel.gateway_tls_pin",
        lambda _gateway: SETTINGS.server_cert_pin,
    )
    monkeypatch.setattr("meraki_openconnect.tunnel._start_worker", lambda: worker)
    monkeypatch.setattr("meraki_openconnect.tunnel._verify_worker", lambda _pid: True)

    def privileged(operation: str) -> None:
        operations.append(operation)
        if operation == "dns-connect":
            raise _DnsSetupError(rollback_complete=True)

    monkeypatch.setattr(
        "meraki_openconnect.tunnel._run_privileged_operation", privileged
    )

    with pytest.raises(TunnelError, match=r"^DNS resolver setup failed$"):
        run_tunnel(PROFILE, SETTINGS, on_connected=lambda *_args: None, store=store)

    assert operations == ["dns-connect"]
    assert store.path.exists() is False


def test_disconnect_uses_only_fixed_helper(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    calls: list[list[str]] = []

    def runner(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr("meraki_openconnect.tunnel.subprocess.run", runner)

    disconnect_tunnel(TunnelStore(tmp_path))

    assert calls == [
        [
            "/usr/bin/sudo",
            "-n",
            HELPER_PATH,
            "vpn-disconnect",
        ]
    ]
