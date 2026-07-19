"""End-to-end SAML authentication using the configured Chrome profile."""

from __future__ import annotations

import asyncio
import logging
import structlog
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import urlsplit

from meraki_openconnect.authenticator import BrowserAuthRequest, build_moc_authenticator
from meraki_openconnect.callback import TokenCallback
from meraki_openconnect.chrome import (
    build_extension_start_url,
    open_in_chrome_profile,
)
from meraki_openconnect.pin import gateway_tls_evidence
from meraki_openconnect.profile import OrganizationProfile
from meraki_openconnect.settings import BrowserSettings


@dataclass(frozen=True)
class AuthenticationResult:
    session_token: str
    server_cert_pin: str


class AuthenticationError(RuntimeError):
    """The browser request did not match the validated organization profile."""


def _discard_upstream_log(
    _logger: object, _method_name: str, _event_dict: dict[str, object]
) -> None:
    raise structlog.DropEvent


def _validate_browser_request(
    profile: OrganizationProfile, request: BrowserAuthRequest
) -> None:
    destination = urlsplit(profile.authentication.destination)
    try:
        login = urlsplit(request.login_url)
        login_port = login.port
    except ValueError as exc:
        raise AuthenticationError("browser authentication request is invalid") from exc
    expected_final = (
        f"https://{profile.gateway.host}{profile.authentication.final_path}"
    )
    if (
        login.scheme != "https"
        or login.hostname != profile.authentication.idp_host
        or login_port not in (None, 443)
        or login.username is not None
        or login.password is not None
        or login.path != destination.path
        or login.fragment
        or request.final_url != expected_final
        or request.token_cookie_name
        != profile.authentication.token_cookie_name
    ):
        raise AuthenticationError("browser authentication request is invalid")


def _silence_upstream_debug_logging() -> None:
    """Upstream records can contain response previews, handles, and SSO tokens."""
    disabled_level = logging.CRITICAL
    upstream_logger = logging.getLogger("openconnect_saml")
    upstream_logger.setLevel(disabled_level)
    upstream_logger.disabled = True
    structlog.configure(
        processors=[_discard_upstream_log],
        wrapper_class=structlog.make_filtering_bound_logger(disabled_level),
        cache_logger_on_first_use=False,
    )


async def authenticate(
    profile: OrganizationProfile,
    browser: BrowserSettings,
    *,
    expected_server_cert_pin: str | None = None,
) -> AuthenticationResult:
    """Complete browser SAML and return an in-memory Cisco session token."""
    _silence_upstream_debug_logging()
    tls_evidence = gateway_tls_evidence(profile.gateway.host)
    server_cert_pin = tls_evidence.spki_pin
    if (
        expected_server_cert_pin is not None
        and expected_server_cert_pin != server_cert_pin
    ):
        raise AuthenticationError(
            "gateway certificate pin changed; refusing authentication"
        )
    from openconnect_saml.config import HostProfile

    async def browser_authenticate(request: BrowserAuthRequest) -> str:
        _validate_browser_request(profile, request)
        bootstrap = {
            "gatewayOrigin": f"https://{profile.gateway.host}",
            "profileDigest": profile.profile_digest(),
            "loginOrigin": f"https://{profile.authentication.idp_host}",
            "loginUrl": request.login_url,
            "finalUrl": request.final_url,
            "cookieName": request.token_cookie_name,
            "cookies": [asdict(cookie) for cookie in request.cookies],
        }
        with TokenCallback(bootstrap) as callback:
            start_url = build_extension_start_url(browser.extension_id)
            open_in_chrome_profile(
                start_url, browser.chrome_profile_directory
            )
            token = await asyncio.to_thread(callback.wait)
        if gateway_tls_evidence(profile.gateway.host).spki_pin != server_cert_pin:
            raise AuthenticationError(
                "gateway certificate pin changed during authentication"
            )
        return token

    host = HostProfile(
        address=profile.gateway.host,
        user_group="",
        name=profile.organization.display_name,
    )
    authenticator = build_moc_authenticator(
        host,
        policy=profile.saml_policy,
        browser_authenticate=browser_authenticate,
        leaf_sha256=tls_evidence.leaf_sha256,
        expected_login_url=(
            f"https://{profile.gateway.host}{profile.authentication.login_path}"
        ),
    )
    response: Any = await authenticator.authenticate("meraki-openconnect")
    return AuthenticationResult(
        session_token=str(response.session_token),
        server_cert_pin=server_cert_pin,
    )
