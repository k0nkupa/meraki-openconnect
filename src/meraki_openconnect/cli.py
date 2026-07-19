"""Command-line entry point for meraki-openconnect."""

from __future__ import annotations

import argparse
import asyncio
import json
import shutil
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

from meraki_openconnect.callback import CallbackError, CallbackTimeout
from meraki_openconnect.chrome import ChromeLaunchError
from meraki_openconnect.extension_setup import (
    ExtensionSetupError,
    ExtensionSetupTimeout,
)
from meraki_openconnect.health import HealthCheckResult
from meraki_openconnect.native_host import (
    NativeHostError,
    configure_native_host,
)
from meraki_openconnect.pin import PinError
from meraki_openconnect.profile import OrganizationProfile, ProfileError
from meraki_openconnect.readiness import Readiness, collect_readiness
from meraki_openconnect.settings import (
    BrowserSettings,
    MachineSettings,
    SettingsError,
    SettingsStore,
)
from meraki_openconnect.setup import (
    SetupCancelled,
    SetupIncomplete,
    SetupInputError,
    run_setup,
    validate_profile_command,
)
from meraki_openconnect.tunnel import (
    TunnelError,
    TunnelSession,
    TunnelStore,
    disconnect_tunnel,
    run_tunnel,
)
from meraki_openconnect.privileged import (
    PrivilegedError,
    install_privileged,
    uninstall_privileged,
)
from meraki_openconnect.service import AuthenticationError, authenticate


PROFILE_PATH = Path.home() / ".config" / "meraki-openconnect" / "profile.json"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="meraki-openconnect")
    subparsers = parser.add_subparsers(dest="command")
    for command in ("doctor", "status"):
        child = subparsers.add_parser(command)
        child.add_argument("--json", action="store_true")
    subparsers.add_parser("auth")
    subparsers.add_parser("connect")
    subparsers.add_parser("disconnect")
    profile = subparsers.add_parser("profile")
    profile_subparsers = profile.add_subparsers(
        dest="profile_command", required=True
    )
    validate = profile_subparsers.add_parser("validate")
    validate.add_argument("profile_path", type=Path)
    setup = subparsers.add_parser("setup")
    setup.add_argument("profile_path", type=Path)
    setup.add_argument("--extension-id", required=True)
    setup.add_argument("--chrome-profile-directory", required=True)
    extension = subparsers.add_parser("extension")
    extension_subparsers = extension.add_subparsers(dest="extension_command", required=True)
    configure = extension_subparsers.add_parser("configure")
    configure.add_argument("extension_id")
    privileged = subparsers.add_parser("privileged")
    privileged_subparsers = privileged.add_subparsers(dest="privileged_command", required=True)
    privileged_subparsers.add_parser("install")
    privileged_subparsers.add_parser("uninstall")
    return parser


def _cisco_connected() -> bool:
    binary = "/opt/cisco/secureclient/bin/vpn"
    if not shutil.which(binary):
        return False
    result = subprocess.run([binary, "-s", "stats"], capture_output=True, text=True, check=False)
    return "Connection State:            Connected" in result.stdout


def _doctor(settings_store: SettingsStore) -> dict[str, object]:
    return collect_readiness(
        profile_path=PROFILE_PATH, settings_store=settings_store
    ).report


def _load_runtime(
    settings_store: SettingsStore,
) -> tuple[OrganizationProfile, MachineSettings]:
    settings = settings_store.load()
    if settings is None:
        raise SettingsError("machine settings are not configured; run setup")
    return OrganizationProfile.load(PROFILE_PATH), settings


def _print_report(report: dict[str, object], as_json: bool) -> None:
    if as_json:
        print(json.dumps(report, sort_keys=True))
        return
    for key, value in report.items():
        print(f"{key}: {value}")


def _confirm_setup(summary: str) -> bool:
    print(summary)
    return input("Type yes to continue setup: ").strip().lower() == "yes"


def _report_tunnel_connected(
    session: TunnelSession, checks: tuple[HealthCheckResult, ...]
) -> None:
    print(
        f"Meraki OpenConnect tunnel connected "
        f"(PID {session.pid}, {session.interface}, {session.address}, {session.transport})"
    )
    for index, check in enumerate(checks):
        print(
            f"check_{index}: {check.type} {check.target} "
            f"{'passed' if check.passed else 'failed'}"
        )


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = list(argv) if argv is not None else sys.argv[1:]
    if not args:
        parser.print_usage(file=sys.stderr)
        return 2
    parsed = parser.parse_args(args)
    settings_store = SettingsStore()
    try:
        if parsed.command == "profile":
            report = validate_profile_command(parsed.profile_path)
            _print_report(report, False)
            return 0
        if parsed.command == "setup":
            result = run_setup(
                parsed.profile_path,
                BrowserSettings(
                    chrome_profile_directory=parsed.chrome_profile_directory,
                    extension_id=parsed.extension_id,
                ),
                confirm=_confirm_setup,
            )
            print(
                "Meraki OpenConnect setup completed: "
                f"{result.settings.installed_policy_digest}"
            )
            return 0
        if parsed.command == "privileged":
            if parsed.privileged_command == "install":
                profile, settings = _load_runtime(settings_store)
                install_privileged(profile, settings)
                print("Meraki OpenConnect privileged helper installed")
            else:
                profile, settings = _load_runtime(settings_store)
                uninstall_privileged(profile, settings)
                print("Meraki OpenConnect privileged helper removed")
            return 0
        if parsed.command == "extension":
            settings = settings_store.load()
            if settings is None or parsed.extension_id != settings.extension_id:
                raise SettingsError("Chrome extension changes require setup")
            configure_native_host(parsed.extension_id)
            print("Meraki OpenConnect Chrome extension configured")
            return 0
        if parsed.command == "doctor":
            report = _doctor(settings_store)
            _print_report(report, parsed.json)
            return 0 if Readiness(report).ready else 4
        if parsed.command == "status":
            session = TunnelStore().load_verified()
            report = {
                "connected": session is not None,
                "pid": session.pid if session else None,
                "interface": session.interface if session else None,
                "transport": session.transport if session else None,
            }
            _print_report(report, parsed.json)
            return 0
        if parsed.command == "disconnect":
            disconnect_tunnel()
            print("Meraki OpenConnect tunnel disconnected")
            return 0
        if parsed.command == "connect":
            if _cisco_connected():
                raise TunnelError(
                    "Cisco is connected; disconnect it explicitly before using meraki-openconnect"
                )
            run_tunnel(
                *_load_runtime(settings_store),
                on_connected=_report_tunnel_connected,
            )
            print("Meraki OpenConnect tunnel disconnected")
            return 0
        profile, settings = _load_runtime(settings_store)
        result = asyncio.run(
            authenticate(
                profile,
                settings.browser_settings,
                expected_server_cert_pin=settings.server_cert_pin,
            )
        )
        if settings.server_cert_pin != result.server_cert_pin:
            raise TunnelError("gateway certificate pin changed; refusing authentication")
        print("Meraki OpenConnect authentication completed; token discarded")
        return 0
    except (
        CallbackError,
        CallbackTimeout,
        ChromeLaunchError,
        ExtensionSetupError,
        ExtensionSetupTimeout,
        NativeHostError,
        AuthenticationError,
        PinError,
        ProfileError,
        SettingsError,
        TunnelError,
        PrivilegedError,
        SetupCancelled,
        SetupIncomplete,
        SetupInputError,
    ) as exc:
        print(f"meraki-openconnect: {exc}", file=sys.stderr)
        return 3
    except subprocess.CalledProcessError:
        print(
            "meraki-openconnect: privileged helper installation did not complete; run it in a visible Terminal",
            file=sys.stderr,
        )
        return 3


def entrypoint() -> None:
    raise SystemExit(main())
