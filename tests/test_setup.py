from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from meraki_openconnect.extension_setup import ExtensionPermissionReceipt
from meraki_openconnect.profile import OrganizationProfile
from meraki_openconnect.privileged import (
    HELPER_PATH,
    NATIVE_PATH,
    POLICY_PATH,
    RUNTIME_LIBRARY_PATH,
    VPNC_SCRIPT_PATH,
)
from meraki_openconnect.root_policy import RenderedRootPolicy
from meraki_openconnect.service import AuthenticationResult
from meraki_openconnect.settings import BrowserSettings, MachineSettings
from meraki_openconnect.setup import (
    SetupCancelled,
    SetupDependencies,
    SetupInputError,
    SetupIncomplete,
    run_setup,
    validate_profile_command,
)


PROFILE = OrganizationProfile.load(
    Path(__file__).parents[1] / "examples" / "profile.example.json"
)
BROWSER = BrowserSettings("Profile 1", "a" * 32)
PIN = "pin-sha256:" + "A" * 43 + "="
OLD_PIN = "pin-sha256:" + "B" * 42 + "A="
POLICY_DIGEST = "sha256:" + "2" * 64


def _dependencies(events: list[str]) -> SetupDependencies:
    return SetupDependencies(
        load_profile=lambda path: events.append("validate-profile") or PROFILE,
        validate_browser=lambda browser: events.append("validate-browser") or browser,
        load_existing_settings=lambda: events.append("load-existing-settings") or None,
        privileged_policy_present=lambda: events.append(
            "check-privileged-policy"
        )
        or False,
        probe_server_pin=lambda gateway: events.append("probe-server-pin") or PIN,
        configure_native_host=lambda extension_id: events.append(
            "configure-native-host"
        ),
        grant_extension_origin=lambda profile, browser: events.append(
            "grant-extension-origin"
        )
        or ExtensionPermissionReceipt(
            f"https://{profile.gateway.host}", profile.profile_digest(), True
        ),
        authenticate_and_pin=lambda profile, browser, expected_pin: events.append(
            "authenticate-and-pin"
        )
        or AuthenticationResult("opaque-token", expected_pin),
        render_policy=lambda profile, pin: events.append("render-policy")
        or RenderedRootPolicy("SCHEMA=1\n", POLICY_DIGEST),
        install_privileged=lambda profile, settings: events.append(
            "install-privileged"
        ),
        save_profile=lambda profile: events.append("save-profile"),
        save_settings=lambda settings: events.append("save-settings"),
        doctor=lambda: events.append("doctor")
        or {
            "ready": True,
            "connected": False,
        },
    )


def test_setup_success_has_explicit_order_and_final_receipts(tmp_path: Path) -> None:
    events: list[str] = []

    def confirm(summary: str) -> bool:
        events.append("confirm-summary")
        assert "Example Organization" in summary
        assert "vpn.example.com" in summary
        assert "opaque-token" not in summary
        assert "?" not in summary
        for privileged_path in (
            HELPER_PATH,
            NATIVE_PATH,
            POLICY_PATH,
            VPNC_SCRIPT_PATH,
            RUNTIME_LIBRARY_PATH,
        ):
            assert privileged_path in summary
        assert "/usr/local/" not in summary
        return True

    result = run_setup(
        tmp_path / "candidate.json",
        BROWSER,
        confirm=confirm,
        dependencies=_dependencies(events),
    )

    assert events == [
        "validate-profile",
        "validate-browser",
        "confirm-summary",
        "load-existing-settings",
        "check-privileged-policy",
        "probe-server-pin",
        "configure-native-host",
        "grant-extension-origin",
        "authenticate-and-pin",
        "render-policy",
        "install-privileged",
        "save-profile",
        "save-settings",
        "doctor",
    ]
    assert result.profile == PROFILE
    assert result.settings.extension_gateway_origin == "https://vpn.example.com"
    assert result.settings.extension_profile_digest == PROFILE.profile_digest()
    assert result.settings.server_cert_pin == PIN
    assert result.settings.installed_policy_digest == POLICY_DIGEST


def test_refusal_stops_before_any_mutation(tmp_path: Path) -> None:
    events: list[str] = []

    with pytest.raises(SetupCancelled):
        run_setup(
            tmp_path / "candidate.json",
            BROWSER,
            confirm=lambda summary: events.append("confirm-summary") or False,
            dependencies=_dependencies(events),
        )

    assert events == ["validate-profile", "validate-browser", "confirm-summary"]


def test_permission_denial_preserves_user_state(tmp_path: Path) -> None:
    events: list[str] = []
    dependencies = _dependencies(events)
    dependencies.grant_extension_origin = lambda profile, browser: events.append(
        "grant-extension-origin"
    ) or ExtensionPermissionReceipt(
        f"https://{profile.gateway.host}", profile.profile_digest(), False
    )

    with pytest.raises(SetupCancelled, match="permission"):
        run_setup(
            tmp_path / "candidate.json",
            BROWSER,
            confirm=lambda _summary: events.append("confirm-summary") or True,
            dependencies=dependencies,
        )

    assert "install-privileged" not in events
    assert "save-profile" not in events
    assert "save-settings" not in events


def test_existing_pin_change_requires_separate_approval_before_browser_auth(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    dependencies = _dependencies(events)
    dependencies.load_existing_settings = lambda: MachineSettings(
        schema_version=1,
        chrome_profile_directory="Profile 1",
        extension_id="a" * 32,
        extension_gateway_origin="https://vpn.example.com",
        extension_profile_digest=PROFILE.profile_digest(),
        server_cert_pin=OLD_PIN,
        installed_policy_digest=POLICY_DIGEST,
    )
    dependencies.probe_server_pin = lambda _gateway: events.append(
        "probe-server-pin"
    ) or PIN
    confirmations: list[str] = []

    def confirm(summary: str) -> bool:
        confirmations.append(summary)
        return len(confirmations) == 1

    with pytest.raises(SetupCancelled, match="certificate pin change"):
        run_setup(
            tmp_path / "candidate.json",
            BROWSER,
            confirm=confirm,
            dependencies=dependencies,
        )

    assert len(confirmations) == 2
    assert "TLS certificate pin has changed" in confirmations[1]
    assert f"Previously trusted pin: {OLD_PIN}" in confirmations[1]
    assert f"Newly observed pin: {PIN}" in confirmations[1]
    assert events[-1] == "probe-server-pin"
    assert "configure-native-host" not in events
    assert "grant-extension-origin" not in events
    assert "authenticate-and-pin" not in events


def test_missing_settings_refuses_to_replace_existing_privileged_policy(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    dependencies = _dependencies(events)
    dependencies.privileged_policy_present = lambda: events.append(
        "check-privileged-policy"
    ) or True

    with pytest.raises(SetupInputError, match="privileged policy"):
        run_setup(
            tmp_path / "candidate.json",
            BROWSER,
            confirm=lambda _summary: events.append("confirm-summary") or True,
            dependencies=dependencies,
        )

    assert events == [
        "validate-profile",
        "validate-browser",
        "confirm-summary",
        "load-existing-settings",
        "check-privileged-policy",
    ]
    assert "probe-server-pin" not in events
    assert "configure-native-host" not in events
    assert "authenticate-and-pin" not in events
    assert "install-privileged" not in events


@pytest.mark.parametrize("failure_stage", ["authenticate", "render", "install"])
def test_precommit_failure_never_replaces_user_state(
    tmp_path: Path, failure_stage: str
) -> None:
    events: list[str] = []
    dependencies = _dependencies(events)
    if failure_stage == "authenticate":
        dependencies.authenticate_and_pin = (
            lambda profile, browser, expected_pin: (_ for _ in ()).throw(
                RuntimeError("authentication failed")
            )
        )
    elif failure_stage == "render":
        dependencies.render_policy = lambda profile, pin: (_ for _ in ()).throw(
            ValueError("pin failed")
        )
    else:
        dependencies.install_privileged = lambda profile, settings: (_ for _ in ()).throw(
            subprocess.CalledProcessError(1, ["sudo"])
        )

    with pytest.raises(Exception):
        run_setup(
            tmp_path / "candidate.json",
            BROWSER,
            confirm=lambda _summary: True,
            dependencies=dependencies,
        )

    assert "save-profile" not in events
    assert "save-settings" not in events


def test_state_write_and_doctor_failure_require_rerun(tmp_path: Path) -> None:
    events: list[str] = []
    dependencies = _dependencies(events)
    dependencies.save_profile = lambda profile: (_ for _ in ()).throw(
        OSError("disk full")
    )

    with pytest.raises(SetupIncomplete, match="rerun setup"):
        run_setup(
            tmp_path / "candidate.json",
            BROWSER,
            confirm=lambda _summary: True,
            dependencies=dependencies,
        )
    assert "install-privileged" in events
    assert "save-settings" not in events

    events.clear()
    dependencies = _dependencies(events)
    dependencies.doctor = lambda: events.append("doctor") or {"ready": False}
    with pytest.raises(SetupIncomplete, match="not ready"):
        run_setup(
            tmp_path / "candidate.json",
            BROWSER,
            confirm=lambda _summary: True,
            dependencies=dependencies,
        )
    assert events[-3:] == ["save-profile", "save-settings", "doctor"]


def test_profile_validate_is_read_only_and_sanitized(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate.json"
    candidate.write_bytes(PROFILE.canonical_bytes())

    report = validate_profile_command(candidate)

    assert report == {
        "name": "Example Organization",
        "gateway": "vpn.example.com",
        "dns_rule_count": 1,
        "health_check_count": 3,
        "profile_digest": PROFILE.profile_digest(),
    }
