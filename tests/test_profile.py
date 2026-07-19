from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from meraki_openconnect.profile import (
    DnsCheck,
    OrganizationProfile,
    ProfileError,
    RouteCheck,
    SplitDnsRule,
    TcpCheck,
)


EXAMPLE_PROFILE: dict[str, Any] = {
    "schema_version": 1,
    "organization": {"display_name": "Example Organization"},
    "gateway": {"host": "vpn.example.com"},
    "authentication": {
        "type": "meraki-entra-saml",
        "idp_host": "login.microsoftonline.com",
        "issuer": "https://vpn.example.com/saml/sp/metadata/SAML",
        "destination": (
            "https://login.microsoftonline.com/"
            "00000000-0000-0000-0000-000000000000/saml2"
        ),
        "login_path": "/saml/sp/login",
        "final_path": "/saml/sp/login_final",
        "token_cookie_name": "acSamlv2Token",
    },
    "split_dns": [
        {"domain": "internal.example.com", "nameservers": ["192.0.2.53"]},
    ],
    "health_checks": [
        {"type": "route", "target": "192.0.2.53"},
        {
            "type": "dns",
            "name": "service.internal.example.com",
            "record_type": "A",
        },
        {"type": "tcp", "host": "192.0.2.10", "port": 443},
    ],
}

REPOSITORY_EXAMPLE = Path(__file__).parents[1] / "examples" / "profile.example.json"


def _write_profile(tmp_path: Path, payload: dict[str, Any]) -> Path:
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(payload))
    return path


def _changed(path: tuple[str | int, ...], value: Any) -> dict[str, Any]:
    payload = copy.deepcopy(EXAMPLE_PROFILE)
    target: Any = payload
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value
    return payload


def test_loads_and_canonicalizes_complete_profile(tmp_path: Path) -> None:
    profile = OrganizationProfile.load(_write_profile(tmp_path, EXAMPLE_PROFILE))

    assert profile.schema_version == 1
    assert profile.organization.display_name == "Example Organization"
    assert profile.gateway.host == "vpn.example.com"
    assert profile.split_dns == (
        SplitDnsRule("internal.example.com", ("192.0.2.53",)),
    )
    assert profile.health_checks == (
        RouteCheck("route", "192.0.2.53"),
        DnsCheck("dns", "service.internal.example.com", "A"),
        TcpCheck("tcp", "192.0.2.10", 443),
    )
    assert json.loads(profile.canonical_bytes()) == EXAMPLE_PROFILE
    expected = hashlib.sha256(profile.canonical_bytes()).hexdigest()
    assert profile.profile_digest() == f"sha256:{expected}"
    assert profile.saml_policy.entra_host == "login.microsoftonline.com"
    assert profile.saml_policy.issuer == EXAMPLE_PROFILE["authentication"]["issuer"]
    assert profile.saml_policy.destination == EXAMPLE_PROFILE["authentication"]["destination"]


def test_canonical_bytes_are_stable_and_compact(tmp_path: Path) -> None:
    payload = dict(reversed(list(EXAMPLE_PROFILE.items())))
    profile = OrganizationProfile.load(_write_profile(tmp_path, payload))

    assert profile.canonical_bytes() == json.dumps(
        EXAMPLE_PROFILE,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def test_accepts_exact_token_cookie_schema_key(tmp_path: Path) -> None:
    profile = OrganizationProfile.load(_write_profile(tmp_path, EXAMPLE_PROFILE))

    assert profile.authentication.token_cookie_name == "acSamlv2Token"


def test_repository_example_is_the_canonical_reserved_profile() -> None:
    profile = OrganizationProfile.load(REPOSITORY_EXAMPLE)

    assert json.loads(profile.canonical_bytes()) == EXAMPLE_PROFILE


def test_rejects_unknown_field_without_echoing_it(tmp_path: Path) -> None:
    rejected = "deployment_label_should_not_echo"
    payload = copy.deepcopy(EXAMPLE_PROFILE)
    payload[rejected] = "value"

    with pytest.raises(ProfileError) as caught:
        OrganizationProfile.load(_write_profile(tmp_path, payload))

    assert rejected not in str(caught.value)


@pytest.mark.parametrize(
    "container_path",
    [
        (),
        ("organization",),
        ("gateway",),
        ("authentication",),
        ("split_dns", 0),
        ("health_checks", 0),
        ("health_checks", 1),
        ("health_checks", 2),
    ],
)
def test_rejects_unknown_secret_like_keys_at_every_level(
    tmp_path: Path, container_path: tuple[str | int, ...]
) -> None:
    payload = copy.deepcopy(EXAMPLE_PROFILE)
    target: Any = payload
    for part in container_path:
        target = target[part]
    rejected_key = "password_material_should_not_echo"
    target[rejected_key] = "rejected-secret-value"

    with pytest.raises(ProfileError, match="forbidden secret-like field") as caught:
        OrganizationProfile.load(_write_profile(tmp_path, payload))

    assert rejected_key not in str(caught.value)
    assert "rejected-secret-value" not in str(caught.value)


@pytest.mark.parametrize(
    ("path", "rejected"),
    [
        (("schema_version",), 2),
        (("schema_version",), 1.0),
        (("organization", "display_name"), ""),
        (("organization", "display_name"), "x" * 81),
        (("organization", "display_name"), "Example\nOrganization"),
        (("gateway", "host"), "https://vpn.example.com"),
        (("gateway", "host"), "192.0.2.10"),
        (("gateway", "host"), "VPN.example.com"),
        (("authentication", "type"), "generic-saml"),
        (("authentication", "idp_host"), "192.0.2.20"),
        (("authentication", "issuer"), "http://vpn.example.com/saml"),
        (("authentication", "issuer"), "https://user@vpn.example.com/saml"),
        (("authentication", "issuer"), "https://vpn.example.com:444/saml"),
        (("authentication", "issuer"), "https://vpn.example.com/saml#fragment"),
        (
            ("authentication", "destination"),
            "https://other.example.com/tenant/saml2",
        ),
        (("authentication", "login_path"), "../saml/login"),
        (("authentication", "login_path"), "/saml/../login"),
        (("authentication", "login_path"), "/saml/login?query=1"),
        (("authentication", "final_path"), "https://vpn.example.com/final"),
        (("authentication", "final_path"), "/saml\\final"),
        (("authentication", "token_cookie_name"), "cookie name"),
        (("authentication", "token_cookie_name"), "cookie;name"),
        (("authentication", "token_cookie_name"), "a" * 128),
        (("split_dns", 0, "domain"), "internal.example.com."),
        (("split_dns", 0, "nameservers"), ["resolver.example.com"]),
        (("health_checks", 0, "target"), "vpn.example.com"),
        (("health_checks", 1, "record_type"), "CNAME"),
        (("health_checks", 2, "host"), "https://service.example.com"),
        (("health_checks", 2, "port"), 0),
        (("health_checks", 2, "port"), 65536),
        (("health_checks", 2, "port"), "443"),
        (("health_checks", 2, "port"), True),
    ],
)
def test_rejects_invalid_profile_values_without_echoing_them(
    tmp_path: Path, path: tuple[str | int, ...], rejected: Any
) -> None:
    payload = _changed(path, rejected)

    with pytest.raises(ProfileError) as caught:
        OrganizationProfile.load(_write_profile(tmp_path, payload))

    if isinstance(rejected, str) and rejected:
        assert rejected not in str(caught.value)


@pytest.mark.parametrize(
    "payload",
    [
        {**EXAMPLE_PROFILE, "split_dns": EXAMPLE_PROFILE["split_dns"] * 17},
        _changed(("split_dns", 0, "nameservers"), ["192.0.2.1"] * 4),
        {**EXAMPLE_PROFILE, "health_checks": EXAMPLE_PROFILE["health_checks"] * 11},
    ],
)
def test_rejects_profile_collection_limits(
    tmp_path: Path, payload: dict[str, Any]
) -> None:
    with pytest.raises(ProfileError):
        OrganizationProfile.load(_write_profile(tmp_path, payload))


@pytest.mark.parametrize("payload", [[], "profile", None, {"schema_version": 1}])
def test_rejects_invalid_or_incomplete_document(tmp_path: Path, payload: Any) -> None:
    with pytest.raises(ProfileError):
        OrganizationProfile.load(_write_profile(tmp_path, payload))


def test_rejects_invalid_json_without_exposing_parser_input(tmp_path: Path) -> None:
    path = tmp_path / "profile.json"
    rejected = "private-value-should-not-echo"
    path.write_text('{"schema_version": 1, "value": "' + rejected)

    with pytest.raises(ProfileError, match="could not read profile") as caught:
        OrganizationProfile.load(path)

    assert rejected not in str(caught.value)
