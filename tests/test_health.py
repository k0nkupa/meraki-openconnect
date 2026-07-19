from __future__ import annotations

import socket
import subprocess

from meraki_openconnect.health import HealthCheckResult, run_health_checks
from meraki_openconnect.profile import DnsCheck, RouteCheck, TcpCheck


def test_health_checks_use_fixed_argv_timeout_and_profile_order() -> None:
    calls: list[tuple[list[str], dict[str, object]]] = []
    connections: list[tuple[tuple[str, int], float]] = []

    def runner(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append((args, kwargs))
        if args[0] == "/sbin/route":
            output = "route to: 192.0.2.53\ninterface: utun25\n"
        elif args[0] == "/usr/bin/dig":
            output = "0 0 443 service.internal.example.com.\n"
        else:
            output = "name: service.internal.example.com\nip_address: 192.0.2.10\n"
        return subprocess.CompletedProcess(args, 0, output, "")

    class Connection:
        def close(self) -> None:
            connections.append((("closed", 0), 0))

    def connector(address: tuple[str, int], timeout: float) -> Connection:
        connections.append((address, timeout))
        return Connection()

    checks = (
        RouteCheck("route", "192.0.2.53"),
        DnsCheck("dns", "service.internal.example.com", "A"),
        DnsCheck("dns", "_service._tcp.internal.example.com", "SRV"),
        TcpCheck("tcp", "192.0.2.10", 443),
    )

    assert run_health_checks(
        checks, "utun25", runner=runner, connector=connector
    ) == (
        HealthCheckResult("route", "192.0.2.53", True),
        HealthCheckResult("dns", "service.internal.example.com", True),
        HealthCheckResult(
            "dns", "_service._tcp.internal.example.com", True
        ),
        HealthCheckResult("tcp", "192.0.2.10:443", True),
    )
    assert [call[0] for call in calls] == [
        ["/sbin/route", "-n", "get", "192.0.2.53"],
        [
            "/usr/bin/dscacheutil",
            "-q",
            "host",
            "-a",
            "name",
            "service.internal.example.com",
        ],
        [
            "/usr/bin/dig",
            "+short",
            "SRV",
            "_service._tcp.internal.example.com",
        ],
    ]
    assert all(call[1]["timeout"] == 10 for call in calls)
    assert connections[0] == (("192.0.2.10", 443), 10)
    assert connections[-1] == (("closed", 0), 0)


def test_route_interface_mismatch_and_empty_dns_answers_fail() -> None:
    def runner(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        if args[0] == "/sbin/route":
            output = "interface: utun99\n"
        else:
            output = ""
        return subprocess.CompletedProcess(args, 0, output, "")

    results = run_health_checks(
        (
            RouteCheck("route", "192.0.2.53"),
            DnsCheck("dns", "service.internal.example.com", "A"),
            DnsCheck("dns", "service.internal.example.com", "AAAA"),
            DnsCheck("dns", "_service._tcp.internal.example.com", "SRV"),
        ),
        "utun25",
        runner=runner,
    )

    assert [result.passed for result in results] == [False, False, False, False]


def test_tcp_refusal_and_command_timeout_are_failed_not_raised() -> None:
    def runner(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(["fixed"], 10)

    def connector(*_args: object, **_kwargs: object) -> socket.socket:
        raise ConnectionRefusedError

    results = run_health_checks(
        (
            RouteCheck("route", "192.0.2.53"),
            TcpCheck("tcp", "service.internal.example.com", 443),
        ),
        "utun25",
        runner=runner,
        connector=connector,
    )

    assert results == (
        HealthCheckResult("route", "192.0.2.53", False),
        HealthCheckResult("tcp", "service.internal.example.com:443", False),
    )


def test_invalid_runtime_labels_fail_closed_without_executing() -> None:
    calls: list[object] = []
    invalid = (
        RouteCheck("route", "192.0.2.53;id"),
        DnsCheck("dns", "bad name.example.com", "A"),
        TcpCheck("tcp", "service.internal.example.com", 0),
    )

    results = run_health_checks(
        invalid,
        "utun25;id",
        runner=lambda *args, **kwargs: calls.append((args, kwargs)),
        connector=lambda *args, **kwargs: calls.append((args, kwargs)),
    )

    assert all(not result.passed for result in results)
    assert calls == []
