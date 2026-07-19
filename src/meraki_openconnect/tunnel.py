"""Foreground controller for the native Meraki OpenConnect tunnel worker."""

from __future__ import annotations

import ipaddress
import json
import re
import select
import struct
import subprocess
from collections.abc import Callable
from dataclasses import asdict, dataclass
from enum import IntEnum
from pathlib import Path
from typing import BinaryIO, Protocol
from urllib.parse import urlsplit

from meraki_openconnect.callback import TokenCallback
from meraki_openconnect.chrome import (
    build_extension_start_url,
    open_in_chrome_profile,
)
from meraki_openconnect.pin import gateway_tls_pin
from meraki_openconnect.health import HealthCheckResult, run_health_checks
from meraki_openconnect.privileged import installed_policy_digest
from meraki_openconnect.privileged import (
    HELPER_PATH,
    NATIVE_PATH,
    privileged_component_installed,
)
from meraki_openconnect.profile import OrganizationProfile
from meraki_openconnect.readiness import (
    extension_receipt_matches,
    policy_receipts_match,
)
from meraki_openconnect.settings import BrowserSettings, MachineSettings


FIELD_MAX = 8192
HEADER = struct.Struct("!BIIII")
_INTERFACE = re.compile(r"utun[0-9]+\Z")
_STAGES = {"init", "auth", "cstp", "tun", "mainloop"}
_FAILURES = {
    "initialization-failed",
    "policy",
    "pin-config-invalid",
    "authentication-failed",
    "connection-rejected",
    "tunnel-setup-failed",
    "connection-report-failed",
    "cancel-watcher-failed",
}


class TunnelError(RuntimeError):
    """The fixed Meraki OpenConnect tunnel worker failed or violated its protocol."""


class _DnsSetupError(TunnelError):
    def __init__(self, *, rollback_complete: bool):
        super().__init__("DNS resolver setup failed")
        self.rollback_complete = rollback_complete


class MessageType(IntEnum):
    WEBVIEW_REQUIRED = 1
    STAGE = 2
    CONNECTED = 3
    FAILED = 4
    DISCONNECTED = 5
    WEBVIEW_RESULT = 16
    CANCEL = 17


_FIELD_COUNTS = {
    MessageType.WEBVIEW_REQUIRED: 1,
    MessageType.STAGE: 1,
    MessageType.CONNECTED: 4,
    MessageType.FAILED: 2,
    MessageType.DISCONNECTED: 0,
    MessageType.WEBVIEW_RESULT: 2,
    MessageType.CANCEL: 0,
}


@dataclass(frozen=True)
class Frame:
    type: MessageType
    fields: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        expected = _FIELD_COUNTS.get(self.type)
        if expected is None or len(self.fields) != expected:
            raise TunnelError("worker frame has an invalid field count")
        for field in self.fields:
            try:
                encoded = field.encode("ascii")
            except UnicodeEncodeError as exc:
                raise TunnelError("worker fields must use printable ASCII") from exc
            if not 1 <= len(encoded) <= FIELD_MAX or any(byte < 0x20 or byte > 0x7E for byte in encoded):
                raise TunnelError("worker fields must use printable ASCII")


def _read_exact(stream: BinaryIO, length: int, *, allow_eof: bool = False) -> bytes:
    chunks = bytearray()
    while len(chunks) < length:
        piece = stream.read(length - len(chunks))
        if not piece:
            if allow_eof and not chunks:
                raise EOFError
            raise TunnelError("worker protocol ended mid-frame")
        chunks.extend(piece)
    return bytes(chunks)


def write_frame(stream: BinaryIO, frame: Frame) -> None:
    payloads = [field.encode("ascii") for field in frame.fields]
    payloads.extend([b""] * (4 - len(payloads)))
    stream.write(HEADER.pack(int(frame.type), *(len(payload) for payload in payloads)))
    for payload in payloads:
        stream.write(payload)
    stream.flush()


def read_frame(stream: BinaryIO) -> Frame:
    header = _read_exact(stream, HEADER.size, allow_eof=True)
    raw_type, *lengths = HEADER.unpack(header)
    try:
        message_type = MessageType(raw_type)
    except ValueError as exc:
        raise TunnelError(f"worker sent an unknown message type {raw_type}") from exc
    expected = _FIELD_COUNTS[message_type]
    if any(length > FIELD_MAX for length in lengths) or any(
        (index < expected and length == 0) or (index >= expected and length != 0)
        for index, length in enumerate(lengths)
    ):
        raise TunnelError("worker frame has invalid field lengths")
    fields: list[str] = []
    for length in lengths[:expected]:
        raw = _read_exact(stream, length)
        try:
            field = raw.decode("ascii")
        except UnicodeDecodeError as exc:
            raise TunnelError("worker fields must use printable ASCII") from exc
        if any(byte < 0x20 or byte > 0x7E for byte in raw):
            raise TunnelError("worker fields must use printable ASCII")
        fields.append(field)
    return Frame(message_type, tuple(fields))


@dataclass(frozen=True)
class TunnelSession:
    pid: int
    gateway: str
    interface: str | None
    address: str | None
    transport: str | None


class TunnelStore:
    LEGACY_NAMES = ("session.json", "openconnect.pid", "experimental.json")

    def __init__(self, directory: Path | None = None):
        self.directory = directory or Path.home() / ".local" / "state" / "meraki-openconnect"
        self.path = self.directory / "tunnel.json"

    def _clear_legacy(self) -> None:
        for name in self.LEGACY_NAMES:
            (self.directory / name).unlink(missing_ok=True)

    def load(self, expected_gateway: str | None = None) -> TunnelSession | None:
        self._clear_legacy()
        if not self.path.exists():
            return None
        try:
            raw = json.loads(self.path.read_text())
            if not isinstance(raw, dict) or set(raw) != {
                "pid",
                "gateway",
                "interface",
                "address",
                "transport",
            }:
                raise ValueError
            session = TunnelSession(
                pid=int(raw["pid"]),
                gateway=str(raw["gateway"]),
                interface=str(raw["interface"]) if raw["interface"] is not None else None,
                address=str(raw["address"]) if raw["address"] is not None else None,
                transport=str(raw["transport"]) if raw["transport"] is not None else None,
            )
        except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise TunnelError("Meraki OpenConnect tunnel state is invalid") from exc
        if session.pid <= 1 or not session.gateway or (
            expected_gateway is not None and session.gateway != expected_gateway
        ):
            raise TunnelError("Meraki OpenConnect tunnel state is invalid")
        return session

    def save(self, session: TunnelSession) -> None:
        self._clear_legacy()
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.directory.chmod(0o700)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(asdict(session), sort_keys=True) + "\n")
        temporary.chmod(0o600)
        temporary.replace(self.path)
        self.path.chmod(0o600)

    def load_verified(self, expected_gateway: str | None = None) -> TunnelSession | None:
        session = self.load(expected_gateway)
        if session is None:
            return None
        if not _verify_worker(session.pid):
            self.clear()
            return None
        return session

    def clear(self) -> None:
        self.path.unlink(missing_ok=True)
        self._clear_legacy()


class Worker(Protocol):
    def read_frame(self, timeout: float | None = None) -> Frame: ...

    def write_frame(self, frame: Frame) -> None: ...

    def close(self) -> None: ...


class _SubprocessWorker:
    def __init__(self, process: subprocess.Popen[bytes]):
        if process.stdin is None or process.stdout is None:
            raise TunnelError("worker protocol pipes are unavailable")
        self.process = process
        self.stdin = process.stdin
        self.stdout = process.stdout

    def read_frame(self, timeout: float | None = None) -> Frame:
        if timeout is not None:
            ready, _, _ = select.select([self.stdout], [], [], timeout)
            if not ready:
                raise TunnelError("worker cleanup confirmation timed out")
        return read_frame(self.stdout)

    def write_frame(self, frame: Frame) -> None:
        write_frame(self.stdin, frame)

    def close(self) -> None:
        try:
            self.stdin.close()
            self.stdout.close()
        finally:
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    _run_privileged_operation("vpn-disconnect")
                except TunnelError:
                    pass
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        self.process.kill()
                        self.process.wait(timeout=5)
                    except (OSError, subprocess.TimeoutExpired) as exc:
                        raise TunnelError("VPN worker cleanup failed") from exc


def _start_worker() -> Worker:
    _verify_privileged_helper()
    try:
        process = subprocess.Popen(
            ["/usr/bin/sudo", "-n", HELPER_PATH, "vpn-connect"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            start_new_session=False,
            bufsize=0,
        )
    except OSError as exc:
        raise TunnelError("VPN worker could not start") from exc
    return _SubprocessWorker(process)


def _run_privileged_operation(operation: str) -> None:
    if operation not in {
        "vpn-connect",
        "vpn-disconnect",
        "dns-connect",
        "dns-disconnect",
    }:
        raise TunnelError("unsupported privileged operation")
    try:
        subprocess.run(
            ["/usr/bin/sudo", "-n", HELPER_PATH, operation],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        if operation == "dns-connect":
            raise _DnsSetupError(rollback_complete=exc.returncode == 1) from exc
        raise TunnelError("DNS resolver cleanup failed") from exc
    except OSError as exc:
        if operation == "dns-connect":
            raise _DnsSetupError(rollback_complete=False) from exc
        raise TunnelError("DNS resolver cleanup failed") from exc


def _verify_privileged_helper(expected_digest: str | None = None) -> None:
    digest = installed_policy_digest()
    if digest is None:
        raise TunnelError(
            "privileged helper is outdated; run meraki-openconnect privileged install"
        )
    if expected_digest is not None and digest != expected_digest:
        raise TunnelError(
            "privileged policy is outdated; run meraki-openconnect privileged install"
        )


def _require_readiness(
    profile: OrganizationProfile, settings: MachineSettings
) -> None:
    helper_digest = installed_policy_digest()
    try:
        receipts_match = extension_receipt_matches(
            profile, settings
        ) and policy_receipts_match(profile, settings, helper_digest)
    except ValueError:
        receipts_match = False
    if not receipts_match or not privileged_component_installed(
        HELPER_PATH
    ) or not privileged_component_installed(NATIVE_PATH):
        raise TunnelError("setup is not ready; run meraki-openconnect doctor")


def _cleanup_resolver_best_effort() -> bool:
    try:
        _run_privileged_operation("dns-disconnect")
    except TunnelError:
        return False
    return True


def _webview_url_is_allowed(uri: str, profile: OrganizationProfile) -> bool:
    try:
        parsed = urlsplit(uri)
        port = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme == "https"
        and parsed.hostname == profile.gateway.host
        and port in (None, 443)
        and parsed.username is None
        and parsed.password is None
        and parsed.path == profile.authentication.login_path
        and not parsed.fragment
    )


def _browser_token(
    login_url: str,
    profile: OrganizationProfile,
    browser: BrowserSettings,
) -> str:
    bootstrap = {
        "gatewayOrigin": f"https://{profile.gateway.host}",
        "profileDigest": profile.profile_digest(),
        "loginOrigin": f"https://{profile.gateway.host}",
        "loginUrl": login_url,
        "finalUrl": (
            f"https://{profile.gateway.host}{profile.authentication.final_path}"
        ),
        "cookieName": profile.authentication.token_cookie_name,
        "cookies": [],
    }
    with TokenCallback(bootstrap) as callback:
        start_url = build_extension_start_url(browser.extension_id)
        open_in_chrome_profile(start_url, browser.chrome_profile_directory)
        return callback.wait()


def _verify_worker(pid: int) -> bool:
    result = subprocess.run(
        ["/bin/ps", "-p", str(pid), "-o", "uid=,comm="],
        capture_output=True,
        text=True,
        check=False,
    )
    parts = result.stdout.strip().split(maxsplit=1)
    return result.returncode == 0 and parts == ["0", NATIVE_PATH]


def _session_from_frame(frame: Frame, gateway: str) -> TunnelSession:
    pid_text, interface, address, transport = frame.fields
    if not pid_text.isascii() or not pid_text.isdecimal():
        raise TunnelError("worker reported invalid connection state")
    pid = int(pid_text)
    try:
        parsed_address = ipaddress.ip_address(address)
    except ValueError as exc:
        raise TunnelError("worker reported invalid connection state") from exc
    if (
        pid <= 1
        or not _INTERFACE.fullmatch(interface)
        or parsed_address.version != 4
        or transport not in {"dtls", "cstp-fallback"}
    ):
        raise TunnelError("worker reported invalid connection state")
    return TunnelSession(pid, gateway, interface, address, transport)


def _cancel_and_confirm(worker: Worker) -> None:
    worker.write_frame(Frame(MessageType.CANCEL))
    while True:
        frame = worker.read_frame(timeout=15)
        if frame.type == MessageType.DISCONNECTED:
            return
        if frame.type == MessageType.STAGE and frame.fields[0] in _STAGES:
            continue
        if (
            frame.type == MessageType.FAILED
            and frame.fields[0] in _STAGES
            and frame.fields[1] in _FAILURES
        ):
            continue
        raise TunnelError("worker cleanup protocol was invalid")


def run_tunnel(
    profile: OrganizationProfile,
    settings: MachineSettings,
    *,
    on_connected: Callable[
        [TunnelSession, tuple[HealthCheckResult, ...]], None
    ],
    store: TunnelStore | None = None,
) -> TunnelSession:
    store = store or TunnelStore()
    _require_readiness(profile, settings)
    if store.load(profile.gateway.host) is not None:
        raise TunnelError("a Meraki OpenConnect tunnel is already recorded")
    if gateway_tls_pin(profile.gateway.host) != settings.server_cert_pin:
        raise TunnelError("gateway certificate pin changed; refusing connection")

    worker = _start_worker()
    connected: TunnelSession | None = None
    completed = False
    resolver_installed = False
    try:
        while True:
            frame = worker.read_frame()
            if frame.type == MessageType.STAGE:
                if frame.fields[0] not in _STAGES:
                    raise TunnelError("worker reported an invalid stage")
                continue
            if frame.type == MessageType.WEBVIEW_REQUIRED:
                if connected is not None or not _webview_url_is_allowed(
                    frame.fields[0], profile
                ):
                    raise TunnelError("worker requested an unexpected webview")
                token = _browser_token(
                    frame.fields[0], profile, settings.browser_settings
                )
                worker.write_frame(
                    Frame(
                        MessageType.WEBVIEW_RESULT,
                        (
                            f"https://{profile.gateway.host}"
                            f"{profile.authentication.final_path}",
                            token,
                        ),
                    )
                )
                token = ""
                continue
            if frame.type == MessageType.CONNECTED:
                if connected is not None:
                    raise TunnelError("worker repeated the connected event")
                connected = _session_from_frame(frame, profile.gateway.host)
                if not _verify_worker(connected.pid):
                    raise TunnelError("worker process identity could not be verified")
                resolver_installed = True
                try:
                    _run_privileged_operation("dns-connect")
                except _DnsSetupError as setup_error:
                    try:
                        _cancel_and_confirm(worker)
                        completed = True
                    except (BrokenPipeError, TunnelError, OSError):
                        pass
                    if setup_error.rollback_complete:
                        resolver_installed = False
                        store.clear()
                        raise setup_error
                    if _cleanup_resolver_best_effort():
                        resolver_installed = False
                        store.clear()
                    else:
                        store.save(connected)
                        raise TunnelError("VPN worker cleanup failed") from None
                    raise TunnelError("VPN worker cleanup failed") from None
                store.save(connected)
                checks = run_health_checks(
                    profile.health_checks, connected.interface
                )
                if not all(check.passed for check in checks):
                    _cancel_and_confirm(worker)
                    completed = True
                    if _cleanup_resolver_best_effort():
                        resolver_installed = False
                        store.clear()
                    raise TunnelError("tunnel verification failed")
                on_connected(connected, checks)
                continue
            if frame.type == MessageType.FAILED:
                stage, category = frame.fields
                if stage not in _STAGES or category not in _FAILURES:
                    raise TunnelError("worker reported an invalid failure")
                raise TunnelError(f"VPN worker failed at {stage}: {category}")
            if frame.type == MessageType.DISCONNECTED:
                if connected is None:
                    raise TunnelError("worker disconnected before establishing the tunnel")
                completed = True
                if resolver_installed:
                    _run_privileged_operation("dns-disconnect")
                    resolver_installed = False
                store.clear()
                return connected
            raise TunnelError("worker sent an unexpected message")
    except KeyboardInterrupt:
        try:
            _cancel_and_confirm(worker)
            completed = True
            if resolver_installed and _cleanup_resolver_best_effort():
                resolver_installed = False
            if not resolver_installed:
                store.clear()
        except (BrokenPipeError, TunnelError, OSError):
            pass
        raise TunnelError("connection cancelled") from None
    except EOFError as exc:
        raise TunnelError("VPN worker exited without cleanup confirmation") from exc
    finally:
        cleanup_failed = False
        if not completed:
            try:
                worker.write_frame(Frame(MessageType.CANCEL))
            except (BrokenPipeError, TunnelError, OSError):
                pass
            try:
                _run_privileged_operation("vpn-disconnect")
            except TunnelError:
                cleanup_failed = True
        if resolver_installed:
            if _cleanup_resolver_best_effort():
                resolver_installed = False
            else:
                cleanup_failed = True
        if not resolver_installed:
            try:
                store.clear()
            except OSError:
                cleanup_failed = True
        try:
            worker.close()
        except (OSError, TunnelError):
            cleanup_failed = True
        if cleanup_failed:
            raise TunnelError("VPN worker cleanup failed") from None


def disconnect_tunnel(store: TunnelStore | None = None) -> None:
    store = store or TunnelStore()
    try:
        _run_privileged_operation("vpn-disconnect")
    except TunnelError as exc:
        raise TunnelError("VPN worker could not be disconnected") from exc
    store.clear()
