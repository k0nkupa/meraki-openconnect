from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

import meraki_openconnect.root_policy as root_policy
from meraki_openconnect.profile import OrganizationProfile
from meraki_openconnect.root_policy import (
    CORE_PROTOCOL_VERSION,
    compute_policy_digest,
    render_root_policy,
)
from meraki_openconnect.settings import SettingsError


EXAMPLE_PATH = Path(__file__).parents[1] / "examples" / "profile.example.json"
EXAMPLE_PROFILE = OrganizationProfile.load(EXAMPLE_PATH)
EXAMPLE_PAYLOAD: dict[str, Any] = json.loads(EXAMPLE_PROFILE.canonical_bytes())
PIN = "pin-sha256:" + "A" * 43 + "="


def test_root_policy_is_deterministic_and_allowlisted() -> None:
    rendered = render_root_policy(EXAMPLE_PROFILE, PIN)

    assert rendered.text.splitlines() == [
        "SCHEMA=1",
        f"DIGEST={rendered.digest}",
        "GATEWAY=vpn.example.com",
        f"SERVERCERT={PIN}",
        "LOGIN_PATH=/saml/sp/login",
        "FINAL_PATH=/saml/sp/login_final",
        "TOKEN_COOKIE=acSamlv2Token",
        "DNS_RULE_COUNT=1",
        "DNS_0_DOMAIN=internal.example.com",
        "DNS_0_SERVER_COUNT=1",
        "DNS_0_SERVER_0=192.0.2.53",
    ]
    assert rendered.text.endswith("\n")
    assert rendered.text.count("\n") == 11
    for forbidden in ('"', "'", "$", "`", "\\", "\0"):
        assert forbidden not in rendered.text


def test_policy_digest_uses_exact_version_profile_and_pin_bytes() -> None:
    payload = b"\0".join(
        (
            str(CORE_PROTOCOL_VERSION).encode("ascii"),
            EXAMPLE_PROFILE.profile_digest().encode("ascii"),
            PIN.encode("ascii"),
        )
    )

    assert compute_policy_digest(EXAMPLE_PROFILE, PIN) == (
        "sha256:" + hashlib.sha256(payload).hexdigest()
    )


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("organization", "display_name"), "Another Organization"),
        (("gateway", "host"), "other.example.com"),
        (("authentication", "issuer"), "https://other.example.com/saml/metadata"),
        (("authentication", "login_path"), "/other/login"),
        (("authentication", "final_path"), "/other/final"),
        (("authentication", "token_cookie_name"), "DifferentCookie"),
        (("split_dns", 0, "domain"), "other.internal.example.com"),
        (("split_dns", 0, "nameservers"), ["192.0.2.54"]),
        (("health_checks", 0, "target"), "192.0.2.54"),
    ],
)
def test_any_profile_change_changes_policy_digest(
    tmp_path: Path, path: tuple[str | int, ...], value: Any
) -> None:
    payload = copy.deepcopy(EXAMPLE_PAYLOAD)
    target: Any = payload
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value
    candidate = tmp_path / "profile.json"
    candidate.write_text(json.dumps(payload))
    changed = OrganizationProfile.load(candidate)

    assert compute_policy_digest(changed, PIN) != compute_policy_digest(
        EXAMPLE_PROFILE, PIN
    )


def test_pin_change_changes_policy_digest() -> None:
    assert compute_policy_digest(
        EXAMPLE_PROFILE, "pin-sha256:" + "B" * 42 + "A="
    ) != compute_policy_digest(EXAMPLE_PROFILE, PIN)


def test_core_protocol_version_change_changes_policy_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = compute_policy_digest(EXAMPLE_PROFILE, PIN)

    monkeypatch.setattr(root_policy, "CORE_PROTOCOL_VERSION", 2)

    assert compute_policy_digest(EXAMPLE_PROFILE, PIN) != original


def test_renderer_rejects_invalid_pin() -> None:
    with pytest.raises(SettingsError):
        render_root_policy(EXAMPLE_PROFILE, "pin-sha256:not base64")
