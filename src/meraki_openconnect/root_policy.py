"""Deterministic rendering for the root-owned native policy snapshot."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from meraki_openconnect.profile import OrganizationProfile
from meraki_openconnect.settings import normalize_server_cert_pin


CORE_PROTOCOL_VERSION = 1


@dataclass(frozen=True)
class RenderedRootPolicy:
    text: str
    digest: str


def compute_policy_digest(
    profile: OrganizationProfile, server_cert_pin: str
) -> str:
    normalized_pin = normalize_server_cert_pin(server_cert_pin)
    payload = b"\0".join(
        (
            str(CORE_PROTOCOL_VERSION).encode("ascii"),
            profile.profile_digest().encode("ascii"),
            normalized_pin.encode("ascii"),
        )
    )
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def render_root_policy(
    profile: OrganizationProfile, server_cert_pin: str
) -> RenderedRootPolicy:
    normalized_pin = normalize_server_cert_pin(server_cert_pin)
    digest = compute_policy_digest(profile, normalized_pin)
    lines = [
        "SCHEMA=1",
        f"DIGEST={digest}",
        f"GATEWAY={profile.gateway.host}",
        f"SERVERCERT={normalized_pin}",
        f"LOGIN_PATH={profile.authentication.login_path}",
        f"FINAL_PATH={profile.authentication.final_path}",
        f"TOKEN_COOKIE={profile.authentication.token_cookie_name}",
        f"DNS_RULE_COUNT={len(profile.split_dns)}",
    ]
    for rule_index, rule in enumerate(profile.split_dns):
        lines.append(f"DNS_{rule_index}_DOMAIN={rule.domain}")
        lines.append(
            f"DNS_{rule_index}_SERVER_COUNT={len(rule.nameservers)}"
        )
        for server_index, nameserver in enumerate(rule.nameservers):
            lines.append(
                f"DNS_{rule_index}_SERVER_{server_index}={nameserver}"
            )
    return RenderedRootPolicy(text="\n".join(lines) + "\n", digest=digest)
