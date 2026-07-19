from __future__ import annotations

from pathlib import Path

from meraki_openconnect.profile import OrganizationProfile
from meraki_openconnect.privileged import HELPER_PATH, NATIVE_PATH
from meraki_openconnect.readiness import (
    EXPECTED_DOCTOR_KEYS,
    Readiness,
    ReadinessDependencies,
    collect_readiness,
)
from meraki_openconnect.root_policy import compute_policy_digest
from meraki_openconnect.settings import MachineSettings, SettingsStore


PROFILE = OrganizationProfile.load(
    Path(__file__).parents[1] / "examples" / "profile.example.json"
)
PIN = "pin-sha256:" + "A" * 43 + "="
POLICY_DIGEST = compute_policy_digest(PROFILE, PIN)


def _configured(tmp_path: Path) -> tuple[Path, SettingsStore]:
    profile_path = tmp_path / "profile.json"
    profile_path.write_bytes(PROFILE.canonical_bytes())
    store = SettingsStore(tmp_path)
    store.save(
        MachineSettings(
            schema_version=1,
            chrome_profile_directory="Profile 1",
            extension_id="a" * 32,
            extension_gateway_origin="https://vpn.example.com",
            extension_profile_digest=PROFILE.profile_digest(),
            server_cert_pin=PIN,
            installed_policy_digest=POLICY_DIGEST,
        )
    )
    return profile_path, store


def test_complete_doctor_contract_is_read_only_and_ready(tmp_path: Path) -> None:
    profile_path, store = _configured(tmp_path)
    events: list[str] = []
    dependencies = ReadinessDependencies(
        openconnect_available=lambda: events.append("openconnect") or True,
        openconnect_saml_available=lambda: events.append("saml") or True,
        chrome_status=lambda directory: events.append(f"chrome:{directory}")
        or (True, True),
        native_host_configured=lambda extension_id: events.append("native-host")
        or True,
        privileged_component_installed=lambda path: events.append(f"component:{path}")
        or True,
        installed_policy_digest=lambda: events.append("policy-digest")
        or POLICY_DIGEST,
        cisco_connected=lambda: events.append("cisco") or False,
        load_tunnel=lambda: events.append("tunnel") or None,
    )
    before = {
        path.name: (path.read_bytes(), path.stat().st_mode)
        for path in tmp_path.iterdir()
        if path.is_file()
    }

    readiness = collect_readiness(
        profile_path=profile_path,
        settings_store=store,
        dependencies=dependencies,
    )

    assert set(readiness.report) == EXPECTED_DOCTOR_KEYS
    assert readiness.ready is True
    assert readiness.report["extension_permission_granted"] is True
    assert readiness.report["policy_digest_matches"] is True
    assert readiness.report["connected"] is False
    assert readiness.report["pid"] is None
    assert readiness.report["interface"] is None
    assert readiness.report["transport"] is None
    assert events == [
        "openconnect",
        "saml",
        "chrome:Profile 1",
        "native-host",
        f"component:{HELPER_PATH}",
        f"component:{NATIVE_PATH}",
        "policy-digest",
        "cisco",
        "tunnel",
    ]
    after = {
        path.name: (path.read_bytes(), path.stat().st_mode)
        for path in tmp_path.iterdir()
        if path.is_file()
    }
    assert after == before


def test_receipt_and_policy_mismatches_are_separate(tmp_path: Path) -> None:
    profile_path, store = _configured(tmp_path)
    dependencies = ReadinessDependencies(
        openconnect_available=lambda: True,
        openconnect_saml_available=lambda: True,
        chrome_status=lambda directory: (True, True),
        native_host_configured=lambda extension_id: True,
        privileged_component_installed=lambda path: True,
        installed_policy_digest=lambda: "sha256:" + "9" * 64,
        cisco_connected=lambda: False,
        load_tunnel=lambda: None,
    )

    readiness = collect_readiness(
        profile_path=profile_path,
        settings_store=store,
        dependencies=dependencies,
    )

    assert readiness.report["extension_permission_granted"] is True
    assert readiness.report["policy_digest_matches"] is False
    assert readiness.ready is False


def test_missing_profile_and_settings_return_stable_false_report(tmp_path: Path) -> None:
    dependencies = ReadinessDependencies(
        openconnect_available=lambda: False,
        openconnect_saml_available=lambda: False,
        chrome_status=lambda directory: (True, False),
        native_host_configured=lambda extension_id: False,
        privileged_component_installed=lambda path: False,
        installed_policy_digest=lambda: None,
        cisco_connected=lambda: False,
        load_tunnel=lambda: None,
    )

    readiness = collect_readiness(
        profile_path=tmp_path / "missing.json",
        settings_store=SettingsStore(tmp_path / "settings"),
        dependencies=dependencies,
    )

    assert set(readiness.report) == EXPECTED_DOCTOR_KEYS
    assert readiness.report["profile_configured"] is False
    assert readiness.report["settings_configured"] is False
    assert readiness.report["extension_permission_granted"] is False
    assert readiness.report["policy_digest_matches"] is False
    assert readiness.ready is False


def test_readiness_requires_every_fixed_gate_and_no_cisco() -> None:
    report = {key: True for key in EXPECTED_DOCTOR_KEYS}
    report.update(
        {
            "cisco_connected": False,
            "connected": False,
            "pid": None,
            "interface": None,
            "transport": None,
        }
    )
    assert Readiness(report).ready is True
    report["policy_digest_matches"] = False
    assert Readiness(report).ready is False
    report["policy_digest_matches"] = True
    report["cisco_connected"] = True
    assert Readiness(report).ready is False
