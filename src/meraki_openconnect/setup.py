"""Explicit one-organization setup transaction for the public client."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from meraki_openconnect.chrome import (
    build_extension_setup_url,
    open_in_chrome_profile,
)
from meraki_openconnect.extension_setup import (
    ExtensionPermissionReceipt,
    ExtensionSetupCallback,
)
from meraki_openconnect.native_host import configure_native_host
from meraki_openconnect.pin import gateway_tls_pin
from meraki_openconnect.privileged import (
    HELPER_PATH,
    NATIVE_PATH,
    POLICY_PATH,
    RUNTIME_LIBRARY_PATH,
    SUDOERS_PATH,
    VPNC_SCRIPT_PATH,
    install_privileged,
)
from meraki_openconnect.profile import (
    DnsCheck,
    OrganizationProfile,
    RouteCheck,
    TcpCheck,
)
from meraki_openconnect.root_policy import RenderedRootPolicy, render_root_policy
from meraki_openconnect.service import (
    AuthenticationError,
    AuthenticationResult,
    authenticate,
)
from meraki_openconnect.settings import (
    BrowserSettings,
    MachineSettings,
    SettingsStore,
    validate_browser_settings,
    validate_machine_settings,
)


ACTIVE_PROFILE_PATH = (
    Path.home() / ".config" / "meraki-openconnect" / "profile.json"
)


class SetupCancelled(RuntimeError):
    """The user declined or denied an explicit setup action."""


class SetupIncomplete(RuntimeError):
    """Privileged setup occurred but readiness could not be established."""


class SetupInputError(ValueError):
    """A setup command argument is unsafe or incomplete."""


@dataclass(frozen=True)
class SetupResult:
    profile: OrganizationProfile
    settings: MachineSettings
    doctor: dict[str, object]


def _default_grant_extension_origin(
    profile: OrganizationProfile, browser: BrowserSettings
) -> ExtensionPermissionReceipt:
    with ExtensionSetupCallback(
        gateway_origin=f"https://{profile.gateway.host}",
        profile_digest=profile.profile_digest(),
    ) as callback:
        open_in_chrome_profile(
            build_extension_setup_url(browser.extension_id),
            browser.chrome_profile_directory,
        )
        return callback.wait()


def _default_authenticate_and_pin(
    profile: OrganizationProfile,
    browser: BrowserSettings,
    expected_server_cert_pin: str,
) -> AuthenticationResult:
    return asyncio.run(
        authenticate(
            profile,
            browser,
            expected_server_cert_pin=expected_server_cert_pin,
        )
    )


def _load_existing_settings() -> MachineSettings | None:
    return SettingsStore().load()


def _save_profile(profile: OrganizationProfile) -> None:
    directory = ACTIVE_PROFILE_PATH.parent
    temporary = ACTIVE_PROFILE_PATH.with_suffix(".tmp")
    try:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory.chmod(0o700)
        temporary.write_bytes(profile.canonical_bytes() + b"\n")
        temporary.chmod(0o600)
        temporary.replace(ACTIVE_PROFILE_PATH)
        ACTIVE_PROFILE_PATH.chmod(0o600)
    except OSError:
        temporary.unlink(missing_ok=True)
        raise


def _save_settings(settings: MachineSettings) -> None:
    SettingsStore().save(settings)


def _default_doctor() -> dict[str, object]:
    from meraki_openconnect.cli import _doctor
    from meraki_openconnect.readiness import Readiness

    report = _doctor(SettingsStore())
    return {**report, "ready": Readiness(report).ready}


@dataclass
class SetupDependencies:
    load_profile: Callable[[Path], OrganizationProfile] = OrganizationProfile.load
    validate_browser: Callable[[BrowserSettings], BrowserSettings] = (
        validate_browser_settings
    )
    load_existing_settings: Callable[[], MachineSettings | None] = (
        _load_existing_settings
    )
    privileged_policy_present: Callable[[], bool] = lambda: Path(POLICY_PATH).exists()
    probe_server_pin: Callable[[str], str] = gateway_tls_pin
    configure_native_host: Callable[[str], object] = configure_native_host
    grant_extension_origin: Callable[
        [OrganizationProfile, BrowserSettings], ExtensionPermissionReceipt
    ] = _default_grant_extension_origin
    authenticate_and_pin: Callable[
        [OrganizationProfile, BrowserSettings, str], AuthenticationResult
    ] = _default_authenticate_and_pin
    render_policy: Callable[
        [OrganizationProfile, str], RenderedRootPolicy
    ] = render_root_policy
    install_privileged: Callable[
        [OrganizationProfile, MachineSettings], None
    ] = install_privileged
    save_profile: Callable[[OrganizationProfile], None] = _save_profile
    save_settings: Callable[[MachineSettings], None] = _save_settings
    doctor: Callable[[], dict[str, object]] = _default_doctor


def _display_url_without_query(value: str) -> str:
    parsed = urlsplit(value)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def _health_target(check: RouteCheck | DnsCheck | TcpCheck) -> str:
    if isinstance(check, RouteCheck):
        return check.target
    if isinstance(check, DnsCheck):
        return f"{check.record_type} {check.name}"
    return f"{check.host}:{check.port}"


def _setup_summary(profile: OrganizationProfile) -> str:
    dns = ", ".join(rule.domain for rule in profile.split_dns) or "none"
    health = ", ".join(_health_target(check) for check in profile.health_checks) or "none"
    return "\n".join(
        (
            f"Organization: {profile.organization.display_name}",
            f"Gateway: {profile.gateway.host}",
            f"SAML issuer: {_display_url_without_query(profile.authentication.issuer)}",
            "SAML destination: "
            f"{_display_url_without_query(profile.authentication.destination)}",
            f"Split DNS domains: {dns}",
            f"Required health checks: {health}",
            "Privileged paths: "
            + ", ".join(
                (
                    HELPER_PATH,
                    NATIVE_PATH,
                    VPNC_SCRIPT_PATH,
                    RUNTIME_LIBRARY_PATH,
                    POLICY_PATH,
                    SUDOERS_PATH,
                )
            ),
        )
    )


def _pin_change_summary(
    profile: OrganizationProfile,
    previous_pin: str,
    observed_pin: str,
) -> str:
    return (
        f"The verified TLS certificate pin has changed for "
        f"{profile.gateway.host}.\n"
        f"Previously trusted pin: {previous_pin}\n"
        f"Newly observed pin: {observed_pin}\n"
        "Approve this change only after verifying that the organization "
        "intentionally replaced the gateway certificate."
    )


def validate_profile_command(path: Path) -> dict[str, object]:
    """Validate a candidate profile without changing local or external state."""
    if not path.is_absolute():
        raise SetupInputError("profile path must be absolute")
    profile = OrganizationProfile.load(path)
    return {
        "name": profile.organization.display_name,
        "gateway": profile.gateway.host,
        "dns_rule_count": len(profile.split_dns),
        "health_check_count": len(profile.health_checks),
        "profile_digest": profile.profile_digest(),
    }


def run_setup(
    profile_path: Path,
    browser: BrowserSettings,
    *,
    confirm: Callable[[str], bool],
    dependencies: SetupDependencies | None = None,
) -> SetupResult:
    """Run explicit setup and commit user state only after root installation."""
    if not profile_path.is_absolute():
        raise SetupInputError("profile path must be absolute")
    dependencies = dependencies or SetupDependencies()
    profile = dependencies.load_profile(profile_path)
    browser = dependencies.validate_browser(browser)
    if not confirm(_setup_summary(profile)):
        raise SetupCancelled("setup was cancelled before making changes")

    existing_settings = dependencies.load_existing_settings()
    if existing_settings is None and dependencies.privileged_policy_present():
        raise SetupInputError(
            "an installed privileged policy exists without matching local settings; "
            "run the privileged uninstall recovery before setup"
        )
    server_cert_pin = dependencies.probe_server_pin(profile.gateway.host)
    if (
        existing_settings is not None
        and existing_settings.server_cert_pin != server_cert_pin
        and not confirm(
            _pin_change_summary(
                profile,
                existing_settings.server_cert_pin,
                server_cert_pin,
            )
        )
    ):
        raise SetupCancelled("gateway certificate pin change was not approved")

    dependencies.configure_native_host(browser.extension_id)
    receipt = dependencies.grant_extension_origin(profile, browser)
    expected_origin = f"https://{profile.gateway.host}"
    if (
        not receipt.granted
        or receipt.gateway_origin != expected_origin
        or receipt.profile_digest != profile.profile_digest()
    ):
        raise SetupCancelled("Chrome gateway permission was not granted")

    authentication = dependencies.authenticate_and_pin(
        profile, browser, server_cert_pin
    )
    if authentication.server_cert_pin != server_cert_pin:
        raise AuthenticationError(
            "gateway certificate pin changed during setup; refusing authentication"
        )
    authentication = None
    rendered = dependencies.render_policy(profile, server_cert_pin)
    settings = validate_machine_settings(
        MachineSettings(
            schema_version=1,
            chrome_profile_directory=browser.chrome_profile_directory,
            extension_id=browser.extension_id,
            extension_gateway_origin=receipt.gateway_origin,
            extension_profile_digest=receipt.profile_digest,
            server_cert_pin=server_cert_pin,
            installed_policy_digest=rendered.digest,
        )
    )
    dependencies.install_privileged(profile, settings)
    try:
        dependencies.save_profile(profile)
        dependencies.save_settings(settings)
    except Exception as exc:
        raise SetupIncomplete(
            "privileged installation succeeded but local state is incomplete; rerun setup"
        ) from exc
    doctor = dependencies.doctor()
    if doctor.get("ready") is not True:
        raise SetupIncomplete("setup is not ready; rerun setup after resolving doctor")
    return SetupResult(profile=profile, settings=settings, doctor=doctor)
