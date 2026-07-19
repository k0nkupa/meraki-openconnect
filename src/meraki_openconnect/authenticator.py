"""Meraki-specific SAML redirect capture without patching site-packages."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urljoin, urlsplit

from requests.adapters import HTTPAdapter

from meraki_openconnect.saml import SamlPolicy, SamlRewriteError, rewrite_force_authn


class MerakiAuthenticationError(RuntimeError):
    """The gateway did not return the expected SAML redirect."""


@dataclass(frozen=True)
class GatewayCookie:
    name: str
    value: str
    domain: str
    path: str
    secure: bool
    expires: int | None
    host_only: bool


@dataclass(frozen=True)
class BrowserBootstrap:
    login_url: str
    cookies: tuple[GatewayCookie, ...]


@dataclass(frozen=True)
class BrowserAuthRequest:
    login_url: str
    final_url: str
    token_cookie_name: str
    cookies: tuple[GatewayCookie, ...]


class _Response(Protocol):
    status_code: int
    url: str
    headers: object

    def close(self) -> None: ...


class _Session(Protocol):
    cookies: object

    def get(self, url: str, **kwargs: object) -> _Response: ...


class _FingerprintAdapter(HTTPAdapter):
    """Require an exact CA-verified leaf certificate before HTTP bytes are sent."""

    def __init__(self, leaf_sha256: str) -> None:
        self._leaf_sha256 = leaf_sha256
        super().__init__()

    def init_poolmanager(
        self, connections: int, maxsize: int, block: bool = False, **pool_kwargs: Any
    ) -> None:
        pool_kwargs["assert_fingerprint"] = self._leaf_sha256
        super().init_poolmanager(connections, maxsize, block, **pool_kwargs)

    def proxy_manager_for(self, proxy: str, **proxy_kwargs: Any) -> Any:
        proxy_kwargs["assert_fingerprint"] = self._leaf_sha256
        return super().proxy_manager_for(proxy, **proxy_kwargs)


def _mount_leaf_pin(session: Any, leaf_sha256: str) -> None:
    session.mount("https://", _FingerprintAdapter(leaf_sha256))


def _belongs_to_gateway(cookie_domain: str, gateway_host: str) -> bool:
    domain = cookie_domain.lstrip(".").lower()
    return gateway_host == domain or gateway_host.endswith(f".{domain}")


def _gateway_cookies(session: _Session, gateway_host: str) -> tuple[GatewayCookie, ...]:
    cookies: list[GatewayCookie] = []
    for cookie in session.cookies:  # type: ignore[union-attr]
        domain = str(cookie.domain)
        if _belongs_to_gateway(domain, gateway_host):
            cookies.append(
                GatewayCookie(
                    name=str(cookie.name),
                    value=str(cookie.value),
                    domain=domain,
                    path=str(cookie.path or "/"),
                    secure=bool(cookie.secure),
                    expires=int(cookie.expires) if cookie.expires is not None else None,
                    host_only=not bool(cookie.domain_specified),
                )
            )
    return tuple(cookies)


def _same_https_origin(first: str, second: str) -> bool:
    try:
        left = urlsplit(first)
        right = urlsplit(second)
        return (
            left.scheme == "https"
            and right.scheme == "https"
            and left.hostname == right.hostname
            and (left.port or 443) == (right.port or 443)
            and left.username is None
            and left.password is None
            and right.username is None
            and right.password is None
        )
    except ValueError:
        return False


def capture_meraki_redirect(
    session: _Session,
    login_url: str,
    policy: SamlPolicy,
    *,
    expected_login_url: str,
    timeout: float,
) -> BrowserBootstrap:
    """Capture Meraki's bodyless 303, rewrite it, and retain scoped cookies in memory."""
    if login_url != expected_login_url:
        raise MerakiAuthenticationError("gateway login URL does not match the profile")
    gateway_host = urlsplit(login_url).hostname
    if not gateway_host or urlsplit(login_url).scheme != "https":
        raise MerakiAuthenticationError("gateway login URL must be HTTPS")

    response = session.get(
        login_url,
        allow_redirects=False,
        stream=True,
        timeout=timeout,
    )
    try:
        if response.status_code != 303:
            raise MerakiAuthenticationError(
                f"expected Meraki SAML redirect, received HTTP {response.status_code}"
            )
        location = getattr(response.headers, "get", lambda _key: None)("Location")
        if not isinstance(location, str) or not location:
            raise MerakiAuthenticationError("Meraki redirect has no Location header")
        try:
            rewritten_url = rewrite_force_authn(urljoin(response.url, location), policy)
        except SamlRewriteError as exc:
            raise MerakiAuthenticationError(str(exc)) from exc
        return BrowserBootstrap(
            login_url=rewritten_url,
            cookies=_gateway_cookies(session, gateway_host),
        )
    finally:
        response.close()


def _openconnect_imports() -> tuple[Any, Any, Any]:
    from openconnect_saml.authenticator import Authenticator, create_probe_session

    return Authenticator, create_probe_session, None


def build_moc_authenticator(
    host: Any,
    *,
    policy: SamlPolicy,
    browser_authenticate: Callable[[BrowserAuthRequest], Awaitable[str]],
    leaf_sha256: str,
    expected_login_url: str,
    timeout: float = 30,
) -> Any:
    """Build an upstream authenticator with the local streaming/browser hooks."""
    Authenticator, create_probe_session, _ = _openconnect_imports()

    class MerakiAuthenticator(Authenticator):
        def _detect_authentication_target_url(self) -> None:
            gateway_url = str(self.host.vpn_url)
            probe_session = create_probe_session(
                self.proxy, ssl_legacy=self.ssl_legacy, verify_tls=self.verify_tls
            )
            _mount_leaf_pin(probe_session, leaf_sha256)
            response = probe_session.get(
                gateway_url, timeout=self.timeout, stream=True
            )
            try:
                response.raise_for_status()
                if not _same_https_origin(gateway_url, str(response.url)):
                    raise MerakiAuthenticationError(
                        "gateway probe changed the token submission redirect origin"
                    )
                self.host.address = response.url
            finally:
                response.close()

        async def _authenticate_in_browser(self, auth_request_response: Any, _display_mode: Any) -> str:
            bootstrap = capture_meraki_redirect(
                self.session,
                str(auth_request_response.login_url),
                policy,
                expected_login_url=expected_login_url,
                timeout=self.timeout,
            )
            return await browser_authenticate(
                BrowserAuthRequest(
                    login_url=bootstrap.login_url,
                    final_url=str(auth_request_response.login_final_url),
                    token_cookie_name=str(auth_request_response.token_cookie_name),
                    cookies=bootstrap.cookies,
                )
            )

    authenticator = MerakiAuthenticator(
        host, version="4.7.00136", timeout=timeout
    )
    _mount_leaf_pin(authenticator.session, leaf_sha256)
    return authenticator
