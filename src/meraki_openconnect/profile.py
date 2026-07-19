"""Strict, non-secret organization profile parsing and canonicalization."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal
from urllib.parse import unquote, urlsplit

from meraki_openconnect.saml import SamlPolicy


_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_DNS_LABEL = re.compile(r"_?[a-z0-9](?:[a-z0-9-]{0,60}[a-z0-9])?\Z")
_COOKIE_NAME = re.compile(r"[A-Za-z0-9!#$%&'*+.^_`|~-]{1,127}\Z")
_SECRET_LIKE = (
    "assertion",
    "cookie",
    "credential",
    "password",
    "secret",
    "token",
    "totp",
)


class ProfileError(ValueError):
    """An organization profile is malformed or outside the supported policy."""


@dataclass(frozen=True)
class Organization:
    display_name: str


@dataclass(frozen=True)
class Gateway:
    host: str


@dataclass(frozen=True)
class AuthenticationPolicy:
    type: Literal["meraki-entra-saml"]
    idp_host: str
    issuer: str
    destination: str
    login_path: str
    final_path: str
    token_cookie_name: str


@dataclass(frozen=True)
class SplitDnsRule:
    domain: str
    nameservers: tuple[str, ...]


@dataclass(frozen=True)
class RouteCheck:
    type: Literal["route"]
    target: str


@dataclass(frozen=True)
class DnsCheck:
    type: Literal["dns"]
    name: str
    record_type: Literal["A", "AAAA", "SRV"]


@dataclass(frozen=True)
class TcpCheck:
    type: Literal["tcp"]
    host: str
    port: int


HealthCheck = RouteCheck | DnsCheck | TcpCheck


def _object(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProfileError("profile contains an invalid object")
    return value


def _array(value: Any, *, maximum: int) -> list[Any]:
    if not isinstance(value, list) or len(value) > maximum:
        raise ProfileError("profile contains an invalid collection")
    return value


def _require_keys(value: dict[str, Any], allowed: frozenset[str]) -> None:
    keys = set(value)
    unknown = keys - allowed
    if any(any(fragment in key.lower() for fragment in _SECRET_LIKE) for key in unknown):
        raise ProfileError("profile contains a forbidden secret-like field")
    if unknown or keys != allowed:
        raise ProfileError("profile contains an unknown or missing field")


def _string(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise ProfileError("profile contains an invalid string")
    if any(unicodedata.category(character) == "Cc" for character in value):
        raise ProfileError("profile contains an invalid string")
    return value


def _display_name(value: Any) -> str:
    name = _string(value)
    if len(name) > 80 or not name.isprintable():
        raise ProfileError("profile contains an invalid organization name")
    return name


def _canonical_hostname(value: Any, *, allow_underscores: bool = False) -> str:
    hostname = _string(value)
    if len(hostname) > 253 or hostname != hostname.lower() or hostname.endswith("."):
        raise ProfileError("profile contains an invalid hostname")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise ProfileError("profile contains an invalid hostname")
    matcher = _DNS_LABEL if allow_underscores else _HOST_LABEL
    labels = hostname.split(".")
    if len(labels) < 2 or any(not matcher.fullmatch(label) for label in labels):
        raise ProfileError("profile contains an invalid hostname")
    return hostname


def _ip_address(value: Any) -> str:
    address = _string(value)
    try:
        return str(ipaddress.ip_address(address))
    except ValueError as exc:
        raise ProfileError("profile contains an invalid IP address") from exc


def _https_url(value: Any) -> tuple[str, str]:
    url = _string(value)
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise ProfileError("profile contains an invalid HTTPS endpoint") from exc
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
        or parsed.fragment
        or not parsed.path.startswith("/")
    ):
        raise ProfileError("profile contains an invalid HTTPS endpoint")
    hostname = _canonical_hostname(parsed.hostname)
    if parsed.netloc not in {hostname, f"{hostname}:443"}:
        raise ProfileError("profile contains an invalid HTTPS endpoint")
    return url, hostname


def _absolute_path(value: Any) -> str:
    path = _string(value)
    parsed = urlsplit(path)
    decoded = unquote(path)
    if (
        not path.startswith("/")
        or path.startswith("//")
        or parsed.scheme
        or parsed.netloc
        or parsed.query
        or parsed.fragment
        or "\\" in path
        or decoded != path
        or "//" in path
        or any(segment in {".", ".."} for segment in path.split("/"))
    ):
        raise ProfileError("profile contains an invalid endpoint path")
    return path


def _cookie_name(value: Any) -> str:
    name = _string(value)
    if not _COOKIE_NAME.fullmatch(name):
        raise ProfileError("profile contains an invalid authentication field")
    return name


def _authentication(value: Any) -> AuthenticationPolicy:
    raw = _object(value)
    _require_keys(
        raw,
        frozenset(
            {
                "type",
                "idp_host",
                "issuer",
                "destination",
                "login_path",
                "final_path",
                "token_cookie_name",
            }
        ),
    )
    auth_type = _string(raw["type"])
    if auth_type != "meraki-entra-saml":
        raise ProfileError("profile contains an unsupported authentication type")
    idp_host = _canonical_hostname(raw["idp_host"])
    issuer, _ = _https_url(raw["issuer"])
    destination, destination_host = _https_url(raw["destination"])
    if destination_host != idp_host:
        raise ProfileError("profile contains an invalid identity-provider endpoint")
    return AuthenticationPolicy(
        type="meraki-entra-saml",
        idp_host=idp_host,
        issuer=issuer,
        destination=destination,
        login_path=_absolute_path(raw["login_path"]),
        final_path=_absolute_path(raw["final_path"]),
        token_cookie_name=_cookie_name(raw["token_cookie_name"]),
    )


def _split_dns(value: Any) -> tuple[SplitDnsRule, ...]:
    rules: list[SplitDnsRule] = []
    for item in _array(value, maximum=16):
        raw = _object(item)
        _require_keys(raw, frozenset({"domain", "nameservers"}))
        nameservers = _array(raw["nameservers"], maximum=3)
        if not nameservers:
            raise ProfileError("profile contains an invalid DNS rule")
        rules.append(
            SplitDnsRule(
                domain=_canonical_hostname(raw["domain"]),
                nameservers=tuple(_ip_address(server) for server in nameservers),
            )
        )
    return tuple(rules)


def _health_checks(value: Any) -> tuple[HealthCheck, ...]:
    checks: list[HealthCheck] = []
    for item in _array(value, maximum=32):
        raw = _object(item)
        check_type = _string(raw.get("type"))
        if check_type == "route":
            _require_keys(raw, frozenset({"type", "target"}))
            checks.append(RouteCheck(type="route", target=_ip_address(raw["target"])))
        elif check_type == "dns":
            _require_keys(raw, frozenset({"type", "name", "record_type"}))
            record_type = _string(raw["record_type"])
            if record_type not in {"A", "AAAA", "SRV"}:
                raise ProfileError("profile contains an invalid DNS record type")
            checks.append(
                DnsCheck(
                    type="dns",
                    name=_canonical_hostname(raw["name"], allow_underscores=True),
                    record_type=record_type,
                )
            )
        elif check_type == "tcp":
            _require_keys(raw, frozenset({"type", "host", "port"}))
            host_value = _string(raw["host"])
            try:
                host = _ip_address(host_value)
            except ProfileError:
                host = _canonical_hostname(host_value)
            port = raw["port"]
            if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
                raise ProfileError("profile contains an invalid TCP port")
            checks.append(TcpCheck(type="tcp", host=host, port=port))
        else:
            if any(
                any(fragment in key.lower() for fragment in _SECRET_LIKE)
                for key in set(raw) - {"type"}
            ):
                raise ProfileError("profile contains a forbidden secret-like field")
            raise ProfileError("profile contains an unsupported health-check type")
    return tuple(checks)


@dataclass(frozen=True)
class OrganizationProfile:
    schema_version: Literal[1]
    organization: Organization
    gateway: Gateway
    authentication: AuthenticationPolicy
    split_dns: tuple[SplitDnsRule, ...]
    health_checks: tuple[HealthCheck, ...]

    @classmethod
    def load(cls, path: Path) -> OrganizationProfile:
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ProfileError("could not read profile") from exc
        payload = _object(raw)
        _require_keys(
            payload,
            frozenset(
                {
                    "schema_version",
                    "organization",
                    "gateway",
                    "authentication",
                    "split_dns",
                    "health_checks",
                }
            ),
        )
        schema_version = payload["schema_version"]
        if type(schema_version) is not int or schema_version != 1:
            raise ProfileError("profile contains an unsupported schema version")

        organization_raw = _object(payload["organization"])
        _require_keys(organization_raw, frozenset({"display_name"}))
        organization = Organization(
            display_name=_display_name(organization_raw["display_name"])
        )

        gateway_raw = _object(payload["gateway"])
        _require_keys(gateway_raw, frozenset({"host"}))
        gateway = Gateway(host=_canonical_hostname(gateway_raw["host"]))

        return cls(
            schema_version=1,
            organization=organization,
            gateway=gateway,
            authentication=_authentication(payload["authentication"]),
            split_dns=_split_dns(payload["split_dns"]),
            health_checks=_health_checks(payload["health_checks"]),
        )

    def canonical_bytes(self) -> bytes:
        payload = {
            "schema_version": self.schema_version,
            "organization": {"display_name": self.organization.display_name},
            "gateway": {"host": self.gateway.host},
            "authentication": {
                "type": self.authentication.type,
                "idp_host": self.authentication.idp_host,
                "issuer": self.authentication.issuer,
                "destination": self.authentication.destination,
                "login_path": self.authentication.login_path,
                "final_path": self.authentication.final_path,
                "token_cookie_name": self.authentication.token_cookie_name,
            },
            "split_dns": [
                {"domain": rule.domain, "nameservers": list(rule.nameservers)}
                for rule in self.split_dns
            ],
            "health_checks": [self._health_check_payload(check) for check in self.health_checks],
        }
        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")

    @staticmethod
    def _health_check_payload(check: HealthCheck) -> dict[str, Any]:
        if isinstance(check, RouteCheck):
            return {"type": check.type, "target": check.target}
        if isinstance(check, DnsCheck):
            return {
                "type": check.type,
                "name": check.name,
                "record_type": check.record_type,
            }
        return {"type": check.type, "host": check.host, "port": check.port}

    def profile_digest(self) -> str:
        return f"sha256:{hashlib.sha256(self.canonical_bytes()).hexdigest()}"

    @property
    def saml_policy(self) -> SamlPolicy:
        return SamlPolicy(
            entra_host=self.authentication.idp_host,
            issuer=self.authentication.issuer,
            destination=self.authentication.destination,
        )
