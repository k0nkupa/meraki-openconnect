from __future__ import annotations

import subprocess
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

from meraki_openconnect.pin import gateway_tls_evidence_for_exact_dns, pin_change_summary
from meraki_openconnect.privileged import (
    InstalledPolicyChanged,
    PrivilegedError,
    install_privileged,
    installed_policy_digest,
    installed_policy_matches,
)
from meraki_openconnect.profile import OrganizationProfile, ProfileError
from meraki_openconnect.readiness import extension_receipt_matches
from meraki_openconnect.root_policy import render_root_policy
from meraki_openconnect.settings import MachineSettings, SettingsError, SettingsStore


_RETRY = "Rerun meraki-openconnect rotate-pin to verify and finish the change."
_RESTORE = (
    "Run meraki-openconnect privileged install to restore the saved policy, "
    "then rerun meraki-openconnect rotate-pin."
)


class PinRotationError(RuntimeError):
    """The gateway pin rotation could not finish safely."""


def _read_installed_digest(saved_digest: str, observed_digest: str) -> str:
    digest = installed_policy_digest()
    if digest is None:
        raise PinRotationError(
            f"could not read the privileged policy. {_RETRY} If the policy is still "
            f"unavailable, restore it. {_RESTORE}"
        )
    if digest not in (saved_digest, observed_digest):
        raise PinRotationError(
            f"privileged policy does not match either pin for the active profile. {_RESTORE}"
        )
    return digest


def rotate_pin(
    profile_path: Path,
    settings_store: SettingsStore,
    *,
    confirm: Callable[[str], bool],
) -> bool:
    """Verify the live pin and return whether the root policy and settings changed."""
    settings = settings_store.load()
    if settings is None:
        raise SettingsError("machine settings are not configured; run setup")
    profile = OrganizationProfile.load(profile_path)
    saved_digest = settings.installed_policy_digest
    saved_policy = render_root_policy(profile, settings.server_cert_pin)
    if (
        not extension_receipt_matches(profile, settings)
        or saved_digest != saved_policy.digest
    ):
        raise PinRotationError(
            "machine settings do not match the active profile and saved pin. "
            "Run meraki-openconnect doctor"
        )

    gateway = profile.gateway.host
    evidence = gateway_tls_evidence_for_exact_dns(gateway)
    pin_matches = evidence.matches_pin(settings.server_cert_pin)
    observed_pin = settings.server_cert_pin if pin_matches else evidence.spki_pin
    observed_policy = render_root_policy(profile, observed_pin)
    observed_digest = observed_policy.digest
    _read_installed_digest(saved_digest, observed_digest)

    def require_installed_policy() -> None:
        try:
            matches = installed_policy_matches(observed_policy.text.encode("utf-8"))
        except OSError as exc:
            raise PinRotationError(
                f"could not verify the privileged policy. {_RETRY}"
            ) from exc
        if not matches:
            raise PinRotationError(
                f"could not verify the privileged policy contents. {_RETRY} "
                f"If verification still fails, restore the saved policy. {_RESTORE}"
            )

    if pin_matches:
        require_installed_policy()
        return False

    try:
        approved = confirm(
            pin_change_summary(gateway, settings.server_cert_pin, observed_pin)
        )
    except (EOFError, KeyboardInterrupt):
        approved = False
    if not approved:
        raise PinRotationError("gateway certificate pin change was not approved")

    updated_settings = replace(
        settings,
        server_cert_pin=observed_pin,
        installed_policy_digest=observed_digest,
    )

    def require_current_configuration(expected: MachineSettings) -> None:
        if (
            settings_store.load() != expected
            or OrganizationProfile.load(profile_path) != profile
        ):
            raise PinRotationError(f"the active configuration changed. {_RETRY}")

    try:
        with settings_store.configuration_lock():
            require_current_configuration(settings)
            if _read_installed_digest(saved_digest, observed_digest) != observed_digest:
                install_privileged(
                    profile,
                    updated_settings,
                    expected_policy=saved_policy.text.encode("utf-8"),
                )
                if _read_installed_digest(saved_digest, observed_digest) != observed_digest:
                    raise PinRotationError(
                        f"the privileged policy update could not be verified. {_RETRY}"
                    )
            else:
                require_installed_policy()
            require_current_configuration(settings)
            settings_store.save(updated_settings)
            require_current_configuration(updated_settings)
            if _read_installed_digest(saved_digest, observed_digest) != observed_digest:
                raise PinRotationError(
                    f"the saved settings and privileged policy do not agree. {_RETRY}"
                )
            require_installed_policy()
    except InstalledPolicyChanged as exc:
        raise PinRotationError(f"the installed policy contents changed. {_RESTORE}") from exc
    except SettingsError as exc:
        raise PinRotationError(f"{exc}. {_RETRY}") from exc
    except (
        KeyboardInterrupt,
        OSError,
        ProfileError,
        PrivilegedError,
        subprocess.CalledProcessError,
    ) as exc:
        raise PinRotationError(f"gateway pin rotation did not finish. {_RETRY}") from exc
    return True
