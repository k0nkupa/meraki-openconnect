import base64
import json
from dataclasses import replace
from pathlib import Path

import pytest

from meraki_openconnect import cli, rotate_pin
from meraki_openconnect.pin import PinError, TlsPeerEvidence
from meraki_openconnect.profile import OrganizationProfile
from meraki_openconnect.root_policy import compute_policy_digest, render_root_policy
from meraki_openconnect.settings import MachineSettings, SettingsError, SettingsStore


SAVED_PIN = "pin-sha256:" + base64.b64encode(b"a" * 32).decode("ascii")
OBSERVED_PIN = "pin-sha256:" + base64.b64encode(b"b" * 32).decode("ascii")


@pytest.fixture
def configured_rotation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys
) -> tuple[OrganizationProfile, MachineSettings, SettingsStore, Path]:
    profile_path = tmp_path / "profile.json"
    payload = {
        "schema_version": 1,
        "organization": {"display_name": "Example Organization"},
        "gateway": {"host": "vpn.example.com"},
        "authentication": {
            "type": "meraki-entra-saml",
            "idp_host": "login.example.com",
            "issuer": "https://vpn.example.com/saml/metadata",
            "destination": "https://login.example.com/saml",
            "login_path": "/saml/login",
            "final_path": "/saml/final",
            "token_cookie_name": "exampleToken",
        },
        "split_dns": [{"domain": "internal.example.com", "nameservers": ["192.0.2.53"]}],
        "health_checks": [{"type": "route", "target": "192.0.2.53"}],
    }
    profile_path.write_text(json.dumps(payload), encoding="utf-8")
    profile = OrganizationProfile.load(profile_path)
    settings = MachineSettings(
        schema_version=1,
        extension_id="a" * 32,
        extension_gateway_origin=f"https://{profile.gateway.host}",
        extension_profile_digest=profile.profile_digest(),
        server_cert_pin=SAVED_PIN,
        installed_policy_digest=compute_policy_digest(profile, SAVED_PIN),
    )
    store = SettingsStore(tmp_path)
    store.save(settings)
    installed = tmp_path / "installed-policy-digest"
    installed.write_text(settings.installed_policy_digest)
    policy = installed.with_suffix(".conf")
    policy.write_text(render_root_policy(profile, SAVED_PIN).text, encoding="utf-8")

    def probe(gateway: str) -> TlsPeerEvidence:
        assert gateway == profile.gateway.host
        return TlsPeerEvidence(OBSERVED_PIN, "", "")

    def install(
        candidate_profile: OrganizationProfile,
        candidate: MachineSettings,
        *,
        expected_policy: bytes,
    ) -> None:
        if policy.read_bytes() != expected_policy:
            raise rotate_pin.InstalledPolicyChanged("installed policy changed")
        rendered = render_root_policy(candidate_profile, candidate.server_cert_pin)
        installed.write_text(rendered.digest)
        policy.write_text(rendered.text, encoding="utf-8")

    monkeypatch.setattr(cli, "PROFILE_PATH", profile_path)
    monkeypatch.setattr(cli, "SettingsStore", lambda: store)
    monkeypatch.setattr(type(cli.sys.stdin), "isatty", lambda _stream: True)
    monkeypatch.setattr(type(cli.sys.stdout), "isatty", lambda _stream: True)
    monkeypatch.setattr("builtins.input", lambda _prompt: "yes")
    monkeypatch.setattr(rotate_pin, "gateway_tls_evidence_for_exact_dns", probe)
    monkeypatch.setattr(rotate_pin, "installed_policy_digest", installed.read_text)
    monkeypatch.setattr(
        rotate_pin,
        "installed_policy_matches",
        lambda expected: policy.read_bytes() == expected,
    )
    monkeypatch.setattr(rotate_pin, "install_privileged", install)
    return profile, settings, store, installed


def test_rotate_pin_updates_both_stores_and_preserves_chrome_configuration(
    configured_rotation, monkeypatch, capsys
):
    profile, settings, store, installed = configured_rotation
    profile_bytes = cli.PROFILE_PATH.read_bytes()

    def approve(_prompt: str) -> str:
        output = capsys.readouterr().out
        assert profile.gateway.host in output
        assert SAVED_PIN in output
        assert OBSERVED_PIN in output
        assert store.load() == settings
        assert installed.read_text() == settings.installed_policy_digest
        return "yes"

    monkeypatch.setattr("builtins.input", approve)

    assert cli.main(["rotate-pin"]) == 0
    assert "meraki-openconnect connect" in capsys.readouterr().out
    assert cli.PROFILE_PATH.read_bytes() == profile_bytes
    assert store.load() == replace(
        settings,
        server_cert_pin=OBSERVED_PIN,
        installed_policy_digest=compute_policy_digest(profile, OBSERVED_PIN),
    )
    assert installed.read_text() == store.load().installed_policy_digest


def _unexpected_effect(*_args, **_kwargs):
    pytest.fail("unexpected effect during pin rotation")


def test_rotate_pin_with_matching_stores_is_a_no_op(
    configured_rotation, monkeypatch, capsys
):
    _, _, store, _ = configured_rotation
    monkeypatch.setattr("builtins.input", _unexpected_effect)
    monkeypatch.setattr(rotate_pin, "install_privileged", _unexpected_effect)
    monkeypatch.setattr(store, "save", _unexpected_effect)
    monkeypatch.setattr(
        rotate_pin,
        "gateway_tls_evidence_for_exact_dns",
        lambda _gateway: TlsPeerEvidence(SAVED_PIN, "", ""),
    )

    assert cli.main(["rotate-pin"]) == 0
    assert "matches" in capsys.readouterr().out


def test_rotate_pin_with_invalid_certificate_fails_before_approval(
    configured_rotation, monkeypatch
):
    _, _, store, _ = configured_rotation

    def invalid_certificate(*_args, **_kwargs):
        raise PinError("gateway TLS certificate verification failed")

    monkeypatch.setattr(rotate_pin, "gateway_tls_evidence_for_exact_dns", invalid_certificate)
    monkeypatch.setattr("builtins.input", _unexpected_effect)
    monkeypatch.setattr(rotate_pin, "install_privileged", _unexpected_effect)
    monkeypatch.setattr(store, "save", _unexpected_effect)

    assert cli.main(["rotate-pin"]) == 3


@pytest.mark.parametrize("response", ["", "no", "y", EOFError(), KeyboardInterrupt()])
def test_rotate_pin_requires_explicit_yes(configured_rotation, monkeypatch, response):
    _, _, store, _ = configured_rotation

    def approve(_prompt: str) -> str:
        if isinstance(response, BaseException):
            raise response
        return response

    monkeypatch.setattr("builtins.input", approve)
    monkeypatch.setattr(rotate_pin, "install_privileged", _unexpected_effect)
    monkeypatch.setattr(store, "save", _unexpected_effect)

    assert cli.main(["rotate-pin"]) == 3


def test_rotate_pin_rejects_piped_approval(configured_rotation, monkeypatch):
    _, _, store, _ = configured_rotation
    monkeypatch.setattr(type(cli.sys.stdin), "isatty", lambda _stream: False)
    monkeypatch.setattr("builtins.input", _unexpected_effect)
    monkeypatch.setattr(rotate_pin, "install_privileged", _unexpected_effect)
    monkeypatch.setattr(store, "save", _unexpected_effect)

    assert cli.main(["rotate-pin"]) == 3


def test_rotate_pin_does_not_save_if_installed_policy_readback_disagrees(
    configured_rotation, monkeypatch
):
    _, settings, store, _ = configured_rotation
    monkeypatch.setattr(rotate_pin, "install_privileged", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(store, "save", _unexpected_effect)

    assert cli.main(["rotate-pin"]) == 3
    assert store.load() == settings


def test_retry_pin_rotation_finishes_interrupted_local_save(
    configured_rotation, monkeypatch, capsys
):
    profile, settings, store, installed = configured_rotation
    save = store.save

    def fail_save(_: MachineSettings) -> None:
        raise SettingsError("could not save settings")

    monkeypatch.setattr(store, "save", fail_save)
    assert cli.main(["rotate-pin"]) == 3
    assert "meraki-openconnect rotate-pin" in capsys.readouterr().err
    new_digest = compute_policy_digest(profile, OBSERVED_PIN)
    assert installed.read_text() == new_digest
    assert store.load() == settings

    monkeypatch.setattr(rotate_pin, "install_privileged", _unexpected_effect)
    monkeypatch.setattr(store, "save", save)
    monkeypatch.setattr("builtins.input", lambda _prompt: "no")
    assert cli.main(["rotate-pin"]) == 3
    assert store.load() == settings

    monkeypatch.setattr("builtins.input", lambda _prompt: "yes")
    assert cli.main(["rotate-pin"]) == 0
    assert store.load() == replace(
        settings, server_cert_pin=OBSERVED_PIN, installed_policy_digest=new_digest
    )


@pytest.mark.parametrize("live_pin", [SAVED_PIN, OBSERVED_PIN])
def test_rotate_pin_gives_recovery_for_policy_with_neither_pin(
    configured_rotation, monkeypatch, capsys, live_pin
):
    _, _, store, installed = configured_rotation
    installed.write_text("sha256:" + "9" * 64)
    monkeypatch.setattr("builtins.input", _unexpected_effect)
    monkeypatch.setattr(rotate_pin, "install_privileged", _unexpected_effect)
    monkeypatch.setattr(
        rotate_pin,
        "gateway_tls_evidence_for_exact_dns",
        lambda _: TlsPeerEvidence(live_pin, "", ""),
    )
    monkeypatch.setattr(store, "save", _unexpected_effect)

    assert cli.main(["rotate-pin"]) == 3
    error = capsys.readouterr().err
    assert "meraki-openconnect privileged install" in error
    assert "then rerun meraki-openconnect rotate-pin" in error


@pytest.mark.parametrize("live_pin", [SAVED_PIN, OBSERVED_PIN])
def test_rotate_pin_rejects_policy_drift_even_if_helper_receipt_matches(
    configured_rotation, monkeypatch, capsys, live_pin
):
    profile, settings, store, installed = configured_rotation
    installed.write_text(compute_policy_digest(profile, live_pin))
    policy = installed.with_suffix(".conf")
    policy.write_text(
        render_root_policy(profile, "pin-sha256:" + "A" * 43 + "=").text,
        encoding="utf-8",
    )
    if live_pin == SAVED_PIN:
        monkeypatch.setattr("builtins.input", _unexpected_effect)
    monkeypatch.setattr(
        rotate_pin,
        "gateway_tls_evidence_for_exact_dns",
        lambda _: TlsPeerEvidence(live_pin, "", ""),
    )
    monkeypatch.setattr(rotate_pin, "install_privileged", _unexpected_effect)
    monkeypatch.setattr(store, "save", _unexpected_effect)

    assert cli.main(["rotate-pin"]) == 3
    assert "could not verify the privileged policy contents" in capsys.readouterr().err
    assert store.load() == settings


def test_rotate_pin_rechecks_configuration_after_approval(
    configured_rotation, monkeypatch, capsys
):
    _, settings, store, installed = configured_rotation
    changed = replace(settings, extension_id="b" * 32)

    def approve(_prompt: str) -> str:
        store.save(changed)
        return "yes"

    monkeypatch.setattr("builtins.input", approve)
    monkeypatch.setattr(rotate_pin, "install_privileged", _unexpected_effect)

    assert cli.main(["rotate-pin"]) == 3
    assert "the active configuration changed" in capsys.readouterr().err
    assert store.load() == changed
    assert installed.read_text() == settings.installed_policy_digest


@pytest.mark.parametrize("scheme", ["sha1", "sha256"])
def test_matching_legacy_pin_needs_no_approval_or_install(
    configured_rotation, monkeypatch, capsys, scheme
):
    profile, settings, store, installed = configured_rotation
    evidence = TlsPeerEvidence(SAVED_PIN, "", "f" * 40)
    digest = evidence.spki_sha1 if scheme == "sha1" else (b"a" * 32).hex()
    legacy_pin = f"{scheme}:{digest.upper()}"
    policy = render_root_policy(profile, legacy_pin)
    legacy_settings = replace(
        settings, server_cert_pin=legacy_pin, installed_policy_digest=policy.digest
    )
    store.save(legacy_settings)
    installed.write_text(policy.digest)
    installed.with_suffix(".conf").write_text(policy.text)
    monkeypatch.setattr(rotate_pin, "gateway_tls_evidence_for_exact_dns", lambda _: evidence)
    monkeypatch.setattr("builtins.input", _unexpected_effect)
    monkeypatch.setattr(rotate_pin, "install_privileged", _unexpected_effect)
    monkeypatch.setattr(store, "save", _unexpected_effect)

    assert cli.main(["rotate-pin"]) == 0
    assert "matches" in capsys.readouterr().out
    assert store.load() == legacy_settings


def test_rotation_refuses_drift_behind_saved_receipt(configured_rotation, capsys):
    profile, settings, store, installed = configured_rotation
    policy = installed.with_suffix(".conf")
    drifted = render_root_policy(profile, "pin-sha256:" + "A" * 43 + "=").text
    policy.write_text(drifted)

    assert cli.main(["rotate-pin"]) == 3
    assert "privileged install" in capsys.readouterr().err
    assert store.load() == settings
    assert policy.read_text() == drifted
