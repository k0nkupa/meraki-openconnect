"""Bounded, profile-derived checks for a connected VPN interface."""

from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Literal, Protocol

from meraki_openconnect.profile import DnsCheck, HealthCheck, RouteCheck, TcpCheck


_INTERFACE = re.compile(r"utun[0-9]+\Z")
_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_DNS_LABEL = re.compile(r"_?[a-z0-9](?:[a-z0-9-]{0,60}[a-z0-9])?\Z")
_TIMEOUT_SECONDS = 10
_OUTPUT_LIMIT = 64 * 1024


class _Connection(Protocol):
    def close(self) -> None: ...


@dataclass(frozen=True)
class HealthCheckResult:
    type: Literal["route", "dns", "tcp"]
    target: str
    passed: bool


def _hostname_is_valid(value: str, *, allow_underscores: bool = False) -> bool:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 253
        or value != value.lower()
        or value.endswith(".")
    ):
        return False
    matcher = _DNS_LABEL if allow_underscores else _HOST_LABEL
    labels = value.split(".")
    return len(labels) >= 2 and all(matcher.fullmatch(label) for label in labels)


def _host_is_valid(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return _hostname_is_valid(value)
    return True


def _run(
    args: list[str],
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> subprocess.CompletedProcess[str] | None:
    try:
        result = runner(
            args,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if len(result.stdout.encode(errors="replace")) > _OUTPUT_LIMIT:
        return None
    return result


def _route_passed(
    check: RouteCheck,
    interface: str,
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> bool:
    try:
        target = str(ipaddress.ip_address(check.target))
    except ValueError:
        return False
    if target != check.target or not _INTERFACE.fullmatch(interface):
        return False
    result = _run(["/sbin/route", "-n", "get", target], runner)
    if result is None or result.returncode != 0:
        return False
    return re.search(
        rf"^\s*interface:\s*{re.escape(interface)}\s*$",
        result.stdout,
        re.MULTILINE,
    ) is not None


def _dns_passed(
    check: DnsCheck,
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> bool:
    allow_underscores = check.record_type == "SRV"
    if (
        check.record_type not in {"A", "AAAA", "SRV"}
        or not _hostname_is_valid(
            check.name, allow_underscores=allow_underscores
        )
    ):
        return False
    if check.record_type == "SRV":
        args = ["/usr/bin/dig", "+short", "SRV", check.name]
    else:
        args = [
            "/usr/bin/dscacheutil",
            "-q",
            "host",
            "-a",
            "name",
            check.name,
        ]
    result = _run(args, runner)
    if result is None or result.returncode != 0 or not result.stdout.strip():
        return False
    if check.record_type == "A":
        return "ip_address:" in result.stdout
    if check.record_type == "AAAA":
        return "ipv6_address:" in result.stdout
    return True


def _tcp_passed(
    check: TcpCheck,
    connector: Callable[..., _Connection],
) -> bool:
    if (
        not _host_is_valid(check.host)
        or type(check.port) is not int
        or not 1 <= check.port <= 65535
    ):
        return False
    try:
        connection = connector(
            (check.host, check.port), timeout=_TIMEOUT_SECONDS
        )
    except OSError:
        return False
    try:
        connection.close()
    except OSError:
        return False
    return True


def _target(check: HealthCheck) -> str:
    if isinstance(check, RouteCheck):
        try:
            return str(ipaddress.ip_address(check.target))
        except ValueError:
            return "invalid"
    if isinstance(check, DnsCheck):
        return check.name if _hostname_is_valid(
            check.name, allow_underscores=check.record_type == "SRV"
        ) else "invalid"
    return (
        f"{check.host}:{check.port}"
        if _host_is_valid(check.host)
        and type(check.port) is int
        and 1 <= check.port <= 65535
        else "invalid"
    )


def run_health_checks(
    checks: Iterable[HealthCheck],
    interface: str,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    connector: Callable[..., _Connection] = socket.create_connection,
) -> tuple[HealthCheckResult, ...]:
    """Run every required check in profile order without invoking a shell."""
    results: list[HealthCheckResult] = []
    for check in checks:
        if isinstance(check, RouteCheck):
            passed = _route_passed(check, interface, runner)
        elif isinstance(check, DnsCheck):
            passed = _dns_passed(check, runner)
        elif isinstance(check, TcpCheck):
            passed = _tcp_passed(check, connector)
        else:
            continue
        results.append(
            HealthCheckResult(check.type, _target(check), passed)
        )
    return tuple(results)
