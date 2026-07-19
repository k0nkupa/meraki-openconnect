from __future__ import annotations

import json
import stat
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from meraki_openconnect.settings import (
    BrowserSettings,
    MachineSettings,
    SettingsError,
    SettingsStore,
    normalize_server_cert_pin,
)


VALID_SPKI_PIN = "pin-sha256:" + "A" * 43 + "="


VALID_SETTINGS = MachineSettings(
    schema_version=1,
    chrome_profile_directory="Profile 1",
    extension_id="a" * 32,
    extension_gateway_origin="https://vpn.example.com",
    extension_profile_digest="sha256:" + "2" * 64,
    server_cert_pin=VALID_SPKI_PIN,
    installed_policy_digest="sha256:" + "1" * 64,
)


def test_settings_store_round_trips_with_private_permissions(tmp_path: Path) -> None:
    store = SettingsStore(tmp_path)

    store.save(VALID_SETTINGS)

    assert store.load() == VALID_SETTINGS
    assert stat.S_IMODE(tmp_path.stat().st_mode) == 0o700
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o600
    assert store.path.name == "settings.json"
    assert not store.path.with_suffix(".tmp").exists()


def test_machine_settings_expose_only_browser_binding() -> None:
    assert VALID_SETTINGS.browser_settings == BrowserSettings(
        chrome_profile_directory="Profile 1",
        extension_id="a" * 32,
    )


def test_settings_store_returns_none_when_absent(tmp_path: Path) -> None:
    assert SettingsStore(tmp_path).load() is None


@pytest.mark.parametrize(
    ("raw", "normalized"),
    [
        ("A" * 40, "sha1:" + "A" * 40),
        ("SHA1:" + "A" * 40, "sha1:" + "A" * 40),
        ("SHA256:" + "B" * 64, "sha256:" + "B" * 64),
        ("PIN-SHA256:" + "A" * 43 + "=", VALID_SPKI_PIN),
    ],
)
def test_normalizes_supported_server_certificate_pins(raw: str, normalized: str) -> None:
    assert normalize_server_cert_pin(raw) == normalized


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "md5:" + "a" * 32,
        "sha1:short",
        "sha256:" + "g" * 64,
        "pin-sha256:not base64",
        "pin-sha256:dGVzdA===",
        "pin-sha256:test\nvalue",
        "pin-sha256:dGVzdA==",
        "pin-sha256:" + "A" * 42 + "==",
        "pin-sha256:" + "A" * 44,
        "pin-sha256:" + "A" * 42 + "B=",
    ],
)
def test_rejects_invalid_server_certificate_pins_without_echoing(raw: str) -> None:
    with pytest.raises(SettingsError) as caught:
        normalize_server_cert_pin(raw)

    if raw:
        assert raw not in str(caught.value)


@pytest.mark.parametrize(
    "chrome_name",
    ["", ".", "..", "Profile/1", "Profile\\1", "/Profile 1", "Profile\n1"],
)
def test_rejects_unsafe_chrome_profile_directory(
    tmp_path: Path, chrome_name: str
) -> None:
    with pytest.raises(SettingsError):
        SettingsStore(tmp_path).save(
            replace(VALID_SETTINGS, chrome_profile_directory=chrome_name)
        )


@pytest.mark.parametrize(
    "extension_id",
    ["a" * 31, "a" * 33, "z" * 32, "A" * 32, "a" * 31 + "0"],
)
def test_rejects_invalid_chrome_extension_id(
    tmp_path: Path, extension_id: str
) -> None:
    with pytest.raises(SettingsError):
        SettingsStore(tmp_path).save(replace(VALID_SETTINGS, extension_id=extension_id))


@pytest.mark.parametrize(
    "origin",
    [
        "http://vpn.example.com",
        "https://vpn.example.com/",
        "https://vpn.example.com/path",
        "https://vpn.example.com?query=1",
        "https://vpn.example.com#fragment",
        "https://user@vpn.example.com",
        "https://vpn.example.com:443",
        "https://vpn.example.com:444",
        "https://192.0.2.10",
        "https://VPN.example.com",
    ],
)
def test_rejects_noncanonical_gateway_origins_without_echoing(
    tmp_path: Path, origin: str
) -> None:
    with pytest.raises(SettingsError) as caught:
        SettingsStore(tmp_path).save(
            replace(VALID_SETTINGS, extension_gateway_origin=origin)
        )

    assert origin not in str(caught.value)


@pytest.mark.parametrize(
    "field",
    ["extension_profile_digest", "installed_policy_digest"],
)
@pytest.mark.parametrize(
    "digest",
    [
        "",
        "sha1:" + "1" * 40,
        "sha256:" + "1" * 63,
        "sha256:" + "A" * 64,
        "sha256:" + "g" * 64,
    ],
)
def test_rejects_invalid_digests(
    tmp_path: Path, field: str, digest: str
) -> None:
    with pytest.raises(SettingsError):
        SettingsStore(tmp_path).save(replace(VALID_SETTINGS, **{field: digest}))


def test_rejects_noninteger_schema_version(tmp_path: Path) -> None:
    with pytest.raises(SettingsError):
        SettingsStore(tmp_path).save(replace(VALID_SETTINGS, schema_version=1.0))


def test_load_rejects_unknown_field_without_echoing_it(tmp_path: Path) -> None:
    payload = _payload()
    rejected = "deployment_label_should_not_echo"
    payload[rejected] = "value"
    _write_raw(tmp_path, payload)

    with pytest.raises(SettingsError) as caught:
        SettingsStore(tmp_path).load()

    assert rejected not in str(caught.value)


def test_load_rejects_unknown_secret_like_field_without_echoing_it(
    tmp_path: Path,
) -> None:
    payload = _payload()
    rejected = "password_material_should_not_echo"
    payload[rejected] = "rejected-secret-value"
    _write_raw(tmp_path, payload)

    with pytest.raises(SettingsError, match="forbidden secret-like field") as caught:
        SettingsStore(tmp_path).load()

    assert rejected not in str(caught.value)
    assert "rejected-secret-value" not in str(caught.value)


def test_allowlisted_pin_and_profile_digest_keys_are_accepted(tmp_path: Path) -> None:
    payload = _payload()
    _write_raw(tmp_path, payload)

    loaded = SettingsStore(tmp_path).load()

    assert loaded is not None
    assert loaded.server_cert_pin == VALID_SETTINGS.server_cert_pin
    assert loaded.extension_profile_digest == VALID_SETTINGS.extension_profile_digest


def test_load_rejects_malformed_json_without_echoing_input(tmp_path: Path) -> None:
    tmp_path.mkdir(parents=True, exist_ok=True)
    rejected = "private-value-should-not-echo"
    (tmp_path / "settings.json").write_text('{"schema_version": 1, "value": "' + rejected)

    with pytest.raises(SettingsError, match="could not read settings") as caught:
        SettingsStore(tmp_path).load()

    assert rejected not in str(caught.value)


def test_failed_atomic_replace_preserves_previous_settings(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    store = SettingsStore(tmp_path)
    store.save(VALID_SETTINGS)
    previous = store.path.read_bytes()

    def fail_replace(_path: Path, _target: Path) -> Path:
        raise OSError("replacement blocked")

    monkeypatch.setattr(Path, "replace", fail_replace)

    with pytest.raises(SettingsError, match="could not save settings"):
        store.save(replace(VALID_SETTINGS, extension_id="b" * 32))

    assert store.path.read_bytes() == previous


def _payload() -> dict[str, Any]:
    return {
        "schema_version": VALID_SETTINGS.schema_version,
        "chrome_profile_directory": VALID_SETTINGS.chrome_profile_directory,
        "extension_id": VALID_SETTINGS.extension_id,
        "extension_gateway_origin": VALID_SETTINGS.extension_gateway_origin,
        "extension_profile_digest": VALID_SETTINGS.extension_profile_digest,
        "server_cert_pin": VALID_SETTINGS.server_cert_pin,
        "installed_policy_digest": VALID_SETTINGS.installed_policy_digest,
    }


def _write_raw(directory: Path, payload: dict[str, Any]) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "settings.json").write_text(json.dumps(payload))
