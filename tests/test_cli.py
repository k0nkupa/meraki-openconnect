import json
from pathlib import Path

import pytest

from meraki_openconnect.cli import main
from meraki_openconnect.pin import PinError
from meraki_openconnect.profile import OrganizationProfile
from meraki_openconnect.readiness import Readiness
from meraki_openconnect.service import AuthenticationResult
from meraki_openconnect.settings import MachineSettings
from meraki_openconnect.settings import BrowserSettings
from meraki_openconnect.setup import SetupResult
from meraki_openconnect.setup import SetupCancelled
from meraki_openconnect.tunnel import TunnelSession


READY_DOCTOR = {
    "certificate_pinned": True,
    "chrome_available": True,
    "chrome_profile_available": True,
    "cisco_connected": False,
    "connected": False,
    "extension_configured": True,
    "extension_permission_granted": True,
    "native_messaging_configured": True,
    "native_worker_installed": True,
    "openconnect": True,
    "openconnect_saml": True,
    "policy_digest_matches": True,
    "profile_configured": True,
    "privileged_helper_installed": True,
    "settings_configured": True,
}

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


def test_main_requires_a_subcommand(capsys):
    assert main([]) == 2
    assert "doctor" in capsys.readouterr().err


def test_profile_validate_command_prints_sanitized_counts(
    monkeypatch, capsys, tmp_path: Path
):
    candidate = tmp_path / "profile.json"
    candidate.write_text("{}")
    calls = []
    monkeypatch.setattr(
        "meraki_openconnect.cli.validate_profile_command",
        lambda path: calls.append(path)
        or {
            "name": "Example Organization",
            "gateway": "vpn.example.com",
            "dns_rule_count": 1,
            "health_check_count": 3,
            "profile_digest": PROFILE.profile_digest(),
        },
    )

    assert main(["profile", "validate", str(candidate)]) == 0
    assert calls == [candidate]
    output = capsys.readouterr().out
    assert "Example Organization" in output
    assert "vpn.example.com" in output
    assert "dns_rule_count: 1" in output
    assert "health_check_count: 3" in output


def test_setup_command_uses_exact_browser_options_and_prints_digest_after_success(
    monkeypatch, capsys, tmp_path: Path
):
    candidate = tmp_path / "profile.json"
    candidate.write_text("{}")
    calls = []

    def setup(path, browser, *, confirm):
        calls.append((path, browser))
        assert confirm("safe summary") is True
        return SetupResult(PROFILE, SETTINGS, {"ready": True})

    monkeypatch.setattr("meraki_openconnect.cli.run_setup", setup)
    monkeypatch.setattr("builtins.input", lambda _prompt: "yes")

    assert main(
        [
            "setup",
            str(candidate),
            "--extension-id",
            "a" * 32,
            "--chrome-profile-directory",
            "Profile 1",
        ]
    ) == 0
    assert calls == [(candidate, BrowserSettings("Profile 1", "a" * 32))]
    output = capsys.readouterr().out
    assert "safe summary" in output
    assert SETTINGS.installed_policy_digest in output


def test_setup_failure_returns_operational_error_without_success_digest(
    monkeypatch, capsys, tmp_path: Path
):
    candidate = tmp_path / "profile.json"
    candidate.write_text("{}")
    monkeypatch.setattr(
        "meraki_openconnect.cli.run_setup",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            SetupCancelled("permission was not granted")
        ),
    )

    assert main(
        [
            "setup",
            str(candidate),
            "--extension-id",
            "a" * 32,
            "--chrome-profile-directory",
            "Profile 1",
        ]
    ) == 3
    captured = capsys.readouterr()
    assert "permission was not granted" in captured.err
    assert "sha256:" not in captured.out


def test_setup_tls_probe_failure_is_reported_without_traceback(
    monkeypatch, capsys, tmp_path: Path
):
    candidate = tmp_path / "profile.json"
    candidate.write_text("{}")
    monkeypatch.setattr(
        "meraki_openconnect.cli.run_setup",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            PinError("gateway TLS certificate verification failed")
        ),
    )

    assert main(
        [
            "setup",
            str(candidate),
            "--extension-id",
            "a" * 32,
            "--chrome-profile-directory",
            "Profile 1",
        ]
    ) == 3
    captured = capsys.readouterr()
    assert "gateway TLS certificate verification failed" in captured.err
    assert "Traceback" not in captured.err


def test_main_uses_process_arguments_when_not_explicit(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["meraki-openconnect", "doctor", "--json"])
    monkeypatch.setattr("meraki_openconnect.cli._doctor", lambda _store: READY_DOCTOR)

    assert main() == 0
    assert '"openconnect"' in capsys.readouterr().out


def test_doctor_json_is_complete_and_read_only(monkeypatch, capsys):
    class Store:
        def load(self):
            return None

    monkeypatch.setattr("meraki_openconnect.cli.SettingsStore", Store)
    report = {
        "certificate_pinned": False,
        "chrome_available": True,
        "chrome_profile_available": False,
        "cisco_connected": False,
        "connected": False,
        "extension_configured": False,
        "extension_permission_granted": False,
        "interface": None,
        "native_messaging_configured": False,
        "native_worker_installed": True,
        "openconnect": True,
        "openconnect_saml": True,
        "pid": None,
        "policy_digest_matches": False,
        "privileged_helper_installed": True,
        "profile_configured": False,
        "settings_configured": False,
        "transport": None,
    }
    monkeypatch.setattr(
        "meraki_openconnect.cli.collect_readiness",
        lambda **_kwargs: Readiness(report),
    )

    assert main(["doctor", "--json"]) == 4
    assert json.loads(capsys.readouterr().out) == report


def test_extension_configure_reinstalls_exact_active_native_host(
    monkeypatch, capsys
):
    events = []

    class Store:
        def load(self):
            return SETTINGS

    monkeypatch.setattr("meraki_openconnect.cli.SettingsStore", Store)
    monkeypatch.setattr(
        "meraki_openconnect.cli.configure_native_host",
        lambda extension_id: events.append(("host", extension_id)),
        raising=False,
    )

    extension_id = SETTINGS.extension_id
    assert main(["extension", "configure", extension_id]) == 0
    assert events == [("host", extension_id)]
    assert "configured" in capsys.readouterr().out


def test_doctor_returns_success_only_when_setup_is_ready(monkeypatch, capsys):
    monkeypatch.setattr("meraki_openconnect.cli._doctor", lambda _store: READY_DOCTOR)

    assert main(["doctor", "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == READY_DOCTOR


def test_privileged_install_uses_active_profile_and_settings(monkeypatch, capsys):
    installed = []

    monkeypatch.setattr(
        "meraki_openconnect.cli._load_runtime", lambda _store: (PROFILE, SETTINGS)
    )
    monkeypatch.setattr(
        "meraki_openconnect.cli.install_privileged",
        lambda profile, settings: installed.append((profile, settings)),
        raising=False,
    )

    assert main(["privileged", "install"]) == 0
    assert installed == [(PROFILE, SETTINGS)]
    assert "installed" in capsys.readouterr().out


def test_connect_routes_only_to_native_tunnel(monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(
        "meraki_openconnect.cli._load_runtime", lambda _store: (PROFILE, SETTINGS)
    )
    monkeypatch.setattr("meraki_openconnect.cli._cisco_connected", lambda: False)
    monkeypatch.setattr(
        "meraki_openconnect.cli.run_tunnel",
        lambda profile, settings, *, on_connected: calls.append(
            (profile, settings, on_connected)
        )
        or TunnelSession(321, profile.gateway.host, "utun9", "192.0.2.20", "dtls"),
        raising=False,
    )
    monkeypatch.setattr(
        "meraki_openconnect.cli.authenticate",
        lambda *_args: (_ for _ in ()).throw(AssertionError("legacy auth path used")),
    )

    assert main(["connect"]) == 0

    assert calls[0][:2] == (PROFILE, SETTINGS)
    assert "Meraki OpenConnect tunnel disconnected" in capsys.readouterr().out


def test_auth_verifies_saved_pin_before_browser_authentication(monkeypatch, capsys):
    calls = []

    async def authenticate(
        profile, browser, *, expected_server_cert_pin
    ) -> AuthenticationResult:
        calls.append((profile, browser, expected_server_cert_pin))
        return AuthenticationResult("opaque-token", expected_server_cert_pin)

    monkeypatch.setattr(
        "meraki_openconnect.cli._load_runtime", lambda _store: (PROFILE, SETTINGS)
    )
    monkeypatch.setattr("meraki_openconnect.cli.authenticate", authenticate)

    assert main(["auth"]) == 0
    assert calls == [
        (PROFILE, SETTINGS.browser_settings, SETTINGS.server_cert_pin)
    ]
    assert "authentication completed" in capsys.readouterr().out


def test_disconnect_routes_only_to_native_tunnel(monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(
        "meraki_openconnect.cli.disconnect_tunnel", lambda: calls.append(True), raising=False
    )

    assert main(["disconnect"]) == 0

    assert calls == [True]
    assert "Meraki OpenConnect tunnel disconnected" in capsys.readouterr().out


def test_experimental_commands_are_removed(capsys):
    for command in ("experimental-connect", "experimental-disconnect"):
        with pytest.raises(SystemExit) as caught:
            main([command])
        assert caught.value.code == 2
    assert "invalid choice" in capsys.readouterr().err


def test_status_reports_only_verified_tunnel(monkeypatch, capsys):
    session = TunnelSession(321, "gateway", "utun9", "192.0.2.20", "dtls")

    class Store:
        def load_verified(self):
            return session

    monkeypatch.setattr("meraki_openconnect.cli.TunnelStore", Store, raising=False)

    assert main(["status", "--json"]) == 0

    assert json.loads(capsys.readouterr().out) == {
        "connected": True,
        "interface": "utun9",
        "pid": 321,
        "transport": "dtls",
    }


def test_status_reports_disconnected_with_null_details(monkeypatch, capsys):
    class Store:
        def load_verified(self):
            return None

    monkeypatch.setattr("meraki_openconnect.cli.TunnelStore", Store, raising=False)

    assert main(["status", "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == {
        "connected": False,
        "interface": None,
        "pid": None,
        "transport": None,
    }
