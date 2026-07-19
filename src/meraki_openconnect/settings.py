"""Machine-local VPN settings and atomic private persistence."""

from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit


_CHROME_EXTENSION_ID = re.compile(r"[a-p]{32}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_HEX_SHA1 = re.compile(r"[0-9A-Fa-f]{40}\Z")
_HEX_SHA256 = re.compile(r"[0-9A-Fa-f]{64}\Z")
_BASE64 = re.compile(r"[A-Za-z0-9+/]+={0,2}\Z")
_SECRET_LIKE = (
    "assertion",
    "cookie",
    "credential",
    "password",
    "secret",
    "token",
    "totp",
)
_SETTINGS_KEYS = frozenset(
    {
        "schema_version",
        "chrome_profile_directory",
        "extension_id",
        "extension_gateway_origin",
        "extension_profile_digest",
        "server_cert_pin",
        "installed_policy_digest",
    }
)


class SettingsError(ValueError):
    """Machine-local settings are malformed or could not be persisted safely."""


@dataclass(frozen=True)
class BrowserSettings:
    chrome_profile_directory: str
    extension_id: str


@dataclass(frozen=True)
class MachineSettings:
    schema_version: Literal[1]
    chrome_profile_directory: str
    extension_id: str
    extension_gateway_origin: str
    extension_profile_digest: str
    server_cert_pin: str
    installed_policy_digest: str

    @property
    def browser_settings(self) -> BrowserSettings:
        return BrowserSettings(
            chrome_profile_directory=self.chrome_profile_directory,
            extension_id=self.extension_id,
        )


def validate_browser_settings(settings: BrowserSettings) -> BrowserSettings:
    """Return normalized browser settings safe for direct Chrome invocation."""
    return BrowserSettings(
        chrome_profile_directory=_chrome_profile_directory(
            settings.chrome_profile_directory
        ),
        extension_id=_extension_id(settings.extension_id),
    )


def _string(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise SettingsError("settings contain an invalid string")
    if any(unicodedata.category(character) == "Cc" for character in value):
        raise SettingsError("settings contain an invalid string")
    return value


def _chrome_profile_directory(value: Any) -> str:
    name = _string(value)
    if name in {".", ".."} or "/" in name or "\\" in name or len(name) > 128:
        raise SettingsError("settings contain an invalid Chrome profile directory")
    return name


def validate_chrome_profile_directory(value: Any) -> str:
    """Validate a Chrome directory name below the standard user-data directory."""
    return _chrome_profile_directory(value)


def _extension_id(value: Any) -> str:
    extension_id = _string(value)
    if not _CHROME_EXTENSION_ID.fullmatch(extension_id):
        raise SettingsError("settings contain an invalid Chrome extension ID")
    return extension_id


def _hostname(value: Any) -> str:
    hostname = _string(value)
    if len(hostname) > 253 or hostname != hostname.lower() or hostname.endswith("."):
        raise SettingsError("settings contain an invalid gateway origin")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise SettingsError("settings contain an invalid gateway origin")
    labels = hostname.split(".")
    if len(labels) < 2 or any(not _HOST_LABEL.fullmatch(label) for label in labels):
        raise SettingsError("settings contain an invalid gateway origin")
    return hostname


def _gateway_origin(value: Any) -> str:
    origin = _string(value)
    try:
        parsed = urlsplit(origin)
        port = parsed.port
    except ValueError as exc:
        raise SettingsError("settings contain an invalid gateway origin") from exc
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise SettingsError("settings contain an invalid gateway origin")
    hostname = _hostname(parsed.hostname)
    if origin != f"https://{hostname}":
        raise SettingsError("settings contain an invalid gateway origin")
    return origin


def _digest(value: Any) -> str:
    digest = _string(value)
    if not _DIGEST.fullmatch(digest):
        raise SettingsError("settings contain an invalid digest")
    return digest


def normalize_server_cert_pin(server_cert_pin: str) -> str:
    """Return a supported OpenConnect certificate fingerprint with a canonical prefix."""
    pin = _string(server_cert_pin)
    if _HEX_SHA1.fullmatch(pin):
        return f"sha1:{pin}"
    prefix, separator, encoded = pin.partition(":")
    prefix = prefix.lower()
    if not separator:
        raise SettingsError("settings contain an invalid certificate pin")
    if prefix == "sha1" and _HEX_SHA1.fullmatch(encoded):
        return f"sha1:{encoded}"
    if prefix == "sha256" and _HEX_SHA256.fullmatch(encoded):
        return f"sha256:{encoded}"
    if prefix == "pin-sha256" and _BASE64.fullmatch(encoded):
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise SettingsError("settings contain an invalid certificate pin") from exc
        if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii") != encoded:
            raise SettingsError("settings contain an invalid certificate pin")
        return f"pin-sha256:{encoded}"
    raise SettingsError("settings contain an invalid certificate pin")


def _require_keys(payload: dict[str, Any]) -> None:
    keys = set(payload)
    unknown = keys - _SETTINGS_KEYS
    if any(any(fragment in key.lower() for fragment in _SECRET_LIKE) for key in unknown):
        raise SettingsError("settings contain a forbidden secret-like field")
    if unknown or keys != _SETTINGS_KEYS:
        raise SettingsError("settings contain an unknown or missing field")


def _validated(settings: MachineSettings) -> MachineSettings:
    if type(settings.schema_version) is not int or settings.schema_version != 1:
        raise SettingsError("settings contain an unsupported schema version")
    return MachineSettings(
        schema_version=1,
        chrome_profile_directory=_chrome_profile_directory(
            settings.chrome_profile_directory
        ),
        extension_id=_extension_id(settings.extension_id),
        extension_gateway_origin=_gateway_origin(settings.extension_gateway_origin),
        extension_profile_digest=_digest(settings.extension_profile_digest),
        server_cert_pin=normalize_server_cert_pin(settings.server_cert_pin),
        installed_policy_digest=_digest(settings.installed_policy_digest),
    )


def validate_machine_settings(settings: MachineSettings) -> MachineSettings:
    """Return a fully normalized machine-settings receipt."""
    return _validated(settings)


def _from_payload(value: Any) -> MachineSettings:
    if not isinstance(value, dict):
        raise SettingsError("settings must be a JSON object")
    _require_keys(value)
    return _validated(
        MachineSettings(
            schema_version=value["schema_version"],
            chrome_profile_directory=value["chrome_profile_directory"],
            extension_id=value["extension_id"],
            extension_gateway_origin=value["extension_gateway_origin"],
            extension_profile_digest=value["extension_profile_digest"],
            server_cert_pin=value["server_cert_pin"],
            installed_policy_digest=value["installed_policy_digest"],
        )
    )


def _payload(settings: MachineSettings) -> dict[str, Any]:
    return {
        "schema_version": settings.schema_version,
        "chrome_profile_directory": settings.chrome_profile_directory,
        "extension_id": settings.extension_id,
        "extension_gateway_origin": settings.extension_gateway_origin,
        "extension_profile_digest": settings.extension_profile_digest,
        "server_cert_pin": settings.server_cert_pin,
        "installed_policy_digest": settings.installed_policy_digest,
    }


class SettingsStore:
    path: Path

    def __init__(self, directory: Path | None = None):
        self.directory = directory or Path.home() / ".config" / "meraki-openconnect"
        self.path = self.directory / "settings.json"

    def load(self) -> MachineSettings | None:
        if not self.path.exists():
            return None
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise SettingsError("could not read settings") from exc
        return _from_payload(raw)

    def save(self, settings: MachineSettings) -> None:
        normalized = _validated(settings)
        temporary = self.path.with_suffix(".tmp")
        try:
            self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            self.directory.chmod(0o700)
            temporary.write_text(
                json.dumps(_payload(normalized), sort_keys=True) + "\n",
                encoding="utf-8",
            )
            temporary.chmod(0o600)
            temporary.replace(self.path)
            self.path.chmod(0o600)
        except OSError as exc:
            temporary.unlink(missing_ok=True)
            raise SettingsError("could not save settings") from exc
