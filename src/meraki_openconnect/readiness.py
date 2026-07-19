"""Read-only readiness aggregation for one configured organization."""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from meraki_openconnect.chrome import chrome_installation_status
from meraki_openconnect.native_host import native_host_configured
from meraki_openconnect.privileged import (
    HELPER_PATH,
    NATIVE_PATH,
    installed_policy_digest,
    privileged_component_installed,
)
from meraki_openconnect.profile import OrganizationProfile, ProfileError
from meraki_openconnect.root_policy import compute_policy_digest
from meraki_openconnect.settings import MachineSettings, SettingsError, SettingsStore


OPENCONNECT_BINARY = Path("/opt/homebrew/bin/openconnect")
DEFAULT_PROFILE_PATH = (
    Path.home() / ".config" / "meraki-openconnect" / "profile.json"
)
EXPECTED_DOCTOR_KEYS = frozenset(
    {
        "openconnect",
        "openconnect_saml",
        "chrome_available",
        "chrome_profile_available",
        "profile_configured",
        "settings_configured",
        "extension_configured",
        "native_messaging_configured",
        "extension_permission_granted",
        "certificate_pinned",
        "privileged_helper_installed",
        "native_worker_installed",
        "policy_digest_matches",
        "cisco_connected",
        "connected",
        "pid",
        "interface",
        "transport",
    }
)
_REQUIRED = (
    "openconnect",
    "openconnect_saml",
    "chrome_available",
    "chrome_profile_available",
    "profile_configured",
    "settings_configured",
    "extension_configured",
    "native_messaging_configured",
    "extension_permission_granted",
    "certificate_pinned",
    "privileged_helper_installed",
    "native_worker_installed",
    "policy_digest_matches",
)


class _Tunnel(Protocol):
    pid: int
    interface: str
    transport: str


@dataclass(frozen=True)
class Readiness:
    report: dict[str, object]

    @property
    def ready(self) -> bool:
        return all(self.report.get(key) is True for key in _REQUIRED) and not bool(
            self.report.get("cisco_connected")
        )


def _openconnect_available() -> bool:
    return OPENCONNECT_BINARY.is_file() and os.access(OPENCONNECT_BINARY, os.X_OK)


def _openconnect_saml_available() -> bool:
    return importlib.util.find_spec("openconnect_saml") is not None


def _chrome_status(profile_directory: str | None) -> tuple[bool, bool]:
    return chrome_installation_status(profile_directory=profile_directory)


def _cisco_connected() -> bool:
    binary = "/opt/cisco/secureclient/bin/vpn"
    if not shutil.which(binary):
        return False
    try:
        result = subprocess.run(
            [binary, "-s", "stats"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return "Connection State:            Connected" in result.stdout


def _load_tunnel() -> _Tunnel | None:
    from meraki_openconnect.tunnel import TunnelStore

    return TunnelStore().load_verified()


@dataclass(frozen=True)
class ReadinessDependencies:
    openconnect_available: Callable[[], bool] = _openconnect_available
    openconnect_saml_available: Callable[[], bool] = _openconnect_saml_available
    chrome_status: Callable[[str | None], tuple[bool, bool]] = _chrome_status
    native_host_configured: Callable[[str], bool] = native_host_configured
    privileged_component_installed: Callable[[str], bool] = (
        privileged_component_installed
    )
    installed_policy_digest: Callable[[], str | None] = installed_policy_digest
    cisco_connected: Callable[[], bool] = _cisco_connected
    load_tunnel: Callable[[], _Tunnel | None] = _load_tunnel


def extension_receipt_matches(
    profile: OrganizationProfile, settings: MachineSettings
) -> bool:
    return (
        settings.extension_gateway_origin == f"https://{profile.gateway.host}"
        and settings.extension_profile_digest == profile.profile_digest()
    )


def policy_receipts_match(
    profile: OrganizationProfile,
    settings: MachineSettings,
    helper_digest: str | None,
) -> bool:
    expected = compute_policy_digest(profile, settings.server_cert_pin)
    return (
        settings.installed_policy_digest == expected
        and helper_digest == expected
    )


def collect_readiness(
    *,
    profile_path: Path = DEFAULT_PROFILE_PATH,
    settings_store: SettingsStore | None = None,
    dependencies: ReadinessDependencies | None = None,
) -> Readiness:
    """Return a stable secret-free report using only read-only probes."""
    dependencies = dependencies or ReadinessDependencies()
    settings_store = settings_store or SettingsStore()
    try:
        profile = OrganizationProfile.load(profile_path)
    except ProfileError:
        profile = None
    try:
        settings = settings_store.load()
    except SettingsError:
        settings = None

    openconnect = bool(dependencies.openconnect_available())
    openconnect_saml = bool(dependencies.openconnect_saml_available())
    chrome_available, chrome_profile_available = dependencies.chrome_status(
        settings.chrome_profile_directory if settings is not None else None
    )
    native_messaging = bool(
        settings is not None
        and dependencies.native_host_configured(settings.extension_id)
    )
    helper_installed = bool(
        dependencies.privileged_component_installed(HELPER_PATH)
    )
    worker_installed = bool(
        dependencies.privileged_component_installed(NATIVE_PATH)
    )
    helper_digest = dependencies.installed_policy_digest()
    cisco_connected = bool(dependencies.cisco_connected())
    try:
        tunnel = dependencies.load_tunnel()
    except Exception:
        tunnel = None

    extension_permission = bool(
        profile is not None
        and settings is not None
        and extension_receipt_matches(profile, settings)
    )
    try:
        policy_matches = bool(
            profile is not None
            and settings is not None
            and policy_receipts_match(profile, settings, helper_digest)
        )
    except SettingsError:
        policy_matches = False
    report: dict[str, object] = {
        "openconnect": openconnect,
        "openconnect_saml": openconnect_saml,
        "chrome_available": bool(chrome_available),
        "chrome_profile_available": bool(chrome_profile_available),
        "profile_configured": profile is not None,
        "settings_configured": settings is not None,
        "extension_configured": settings is not None,
        "native_messaging_configured": native_messaging,
        "extension_permission_granted": extension_permission,
        "certificate_pinned": settings is not None,
        "privileged_helper_installed": helper_installed,
        "native_worker_installed": worker_installed,
        "policy_digest_matches": policy_matches,
        "cisco_connected": cisco_connected,
        "connected": tunnel is not None,
        "pid": tunnel.pid if tunnel is not None else None,
        "interface": tunnel.interface if tunnel is not None else None,
        "transport": tunnel.transport if tunnel is not None else None,
    }
    return Readiness(report)
