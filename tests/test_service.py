import asyncio
from types import SimpleNamespace

import structlog
import pytest

from pathlib import Path

from meraki_openconnect.authenticator import BrowserAuthRequest
from meraki_openconnect.profile import OrganizationProfile
from meraki_openconnect.pin import TlsPeerEvidence
from meraki_openconnect.settings import BrowserSettings

from meraki_openconnect.service import (
    AuthenticationError,
    _silence_upstream_debug_logging,
    authenticate,
    _validate_browser_request,
)


PROFILE = OrganizationProfile.load(
    Path(__file__).parents[1] / "examples" / "profile.example.json"
)


def test_upstream_debug_logging_is_suppressed(capsys):
    _silence_upstream_debug_logging()

    structlog.get_logger("openconnect_saml.authenticator").debug("must-not-appear")

    captured = capsys.readouterr()
    assert "must-not-appear" not in captured.out
    assert "must-not-appear" not in captured.err


def test_upstream_error_payload_logging_is_suppressed(capsys):
    _silence_upstream_debug_logging()

    structlog.get_logger("openconnect_saml.authenticator").error(
        "upstream failure",
        raw_preview="secret-response-preview",
        response="secret-token",
    )

    captured = capsys.readouterr()
    assert "secret-response-preview" not in captured.out
    assert "secret-response-preview" not in captured.err
    assert "secret-token" not in captured.out
    assert "secret-token" not in captured.err


def test_upstream_critical_payload_logging_is_suppressed(capsys):
    _silence_upstream_debug_logging()

    structlog.get_logger("openconnect_saml.authenticator").critical(
        "upstream failure",
        raw_preview="critical-secret-preview",
    )

    captured = capsys.readouterr()
    assert "critical-secret-preview" not in captured.out
    assert "critical-secret-preview" not in captured.err


def test_expected_pin_mismatch_stops_before_authenticator_creation(monkeypatch):
    events: list[str] = []
    monkeypatch.setattr(
        "meraki_openconnect.service.gateway_tls_evidence",
        lambda _gateway: events.append("pin")
        or TlsPeerEvidence("pin-sha256:changed", "b" * 64),
        raising=False,
    )
    monkeypatch.setattr(
        "meraki_openconnect.service.build_moc_authenticator",
        lambda *_args, **_kwargs: events.append("authenticator"),
    )

    with pytest.raises(AuthenticationError, match="certificate pin changed"):
        asyncio.run(
            authenticate(
                PROFILE,
                BrowserSettings("Profile 1", "a" * 32),
                expected_server_cert_pin="pin-sha256:expected",
            )
        )

    assert events == ["pin"]


def test_browser_token_is_rejected_if_gateway_spki_changes_during_authentication(
    monkeypatch,
):
    expected_pin = "pin-sha256:" + "A" * 43 + "="
    changed_pin = "pin-sha256:" + "B" * 43 + "="
    evidence = iter(
        (
            TlsPeerEvidence(expected_pin, "a" * 64),
            TlsPeerEvidence(changed_pin, "b" * 64),
        )
    )
    events: list[str] = []
    monkeypatch.setattr(
        "meraki_openconnect.service.gateway_tls_evidence",
        lambda _gateway: events.append("pin") or next(evidence),
        raising=False,
    )

    class Callback:
        def __init__(self, _bootstrap):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def wait(self):
            events.append("token-created")
            return "secret-session-token"

    monkeypatch.setattr("meraki_openconnect.service.TokenCallback", Callback)
    monkeypatch.setattr(
        "meraki_openconnect.service.open_in_chrome_profile",
        lambda *_args: events.append("chrome"),
    )

    def build_authenticator(
        _host, *, policy, browser_authenticate, leaf_sha256, expected_login_url
    ):
        assert leaf_sha256 == "a" * 64
        assert expected_login_url == "https://vpn.example.com/saml/sp/login"

        class Authenticator:
            async def authenticate(self, _display_mode):
                token = await browser_authenticate(
                    BrowserAuthRequest(
                        login_url=(
                            PROFILE.authentication.destination
                            + "?SAMLRequest=test"
                        ),
                        final_url=(
                            f"https://{PROFILE.gateway.host}"
                            f"{PROFILE.authentication.final_path}"
                        ),
                        token_cookie_name=(
                            PROFILE.authentication.token_cookie_name
                        ),
                        cookies=(),
                    )
                )
                events.append(("accepted-token", token))
                return SimpleNamespace(session_token=token)

        return Authenticator()

    monkeypatch.setattr(
        "meraki_openconnect.service.build_moc_authenticator", build_authenticator
    )

    with pytest.raises(AuthenticationError, match="changed during authentication"):
        asyncio.run(
            authenticate(
                PROFILE,
                BrowserSettings("Profile 1", "a" * 32),
                expected_server_cert_pin=expected_pin,
            )
        )

    assert events == ["pin", "chrome", "token-created", "pin"]


def test_browser_request_must_match_profile_before_chrome() -> None:
    request = BrowserAuthRequest(
        login_url=PROFILE.authentication.destination + "?SAMLRequest=test",
        final_url="https://vpn.example.com/saml/sp/login_final",
        token_cookie_name="acSamlv2Token",
        cookies=(),
    )

    _validate_browser_request(PROFILE, request)

    with pytest.raises(AuthenticationError):
        _validate_browser_request(
            PROFILE,
            BrowserAuthRequest(
                login_url="https://evil.example/saml2?SAMLRequest=test",
                final_url=request.final_url,
                token_cookie_name=request.token_cookie_name,
                cookies=(),
            ),
        )
    with pytest.raises(AuthenticationError):
        _validate_browser_request(
            PROFILE,
            BrowserAuthRequest(
                login_url=request.login_url,
                final_url="https://vpn.example.com/other",
                token_cookie_name=request.token_cookie_name,
                cookies=(),
            ),
        )
    with pytest.raises(AuthenticationError):
        _validate_browser_request(
            PROFILE,
            BrowserAuthRequest(
                login_url=request.login_url,
                final_url=request.final_url,
                token_cookie_name="OtherCookie",
                cookies=(),
            ),
        )
