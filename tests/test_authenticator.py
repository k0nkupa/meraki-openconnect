import base64
import hashlib
import http.server
import ssl
import subprocess
import threading
import zlib
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlencode

import pytest
import requests

import meraki_openconnect.authenticator as authenticator_module
from meraki_openconnect.authenticator import (
    MerakiAuthenticationError,
    build_moc_authenticator,
    capture_meraki_redirect,
)
from meraki_openconnect.saml import SamlPolicy


ISSUER = "https://vpn.example.com/saml/sp"
DESTINATION = "https://login.microsoftonline.com/example/saml2"


def _entra_redirect() -> str:
    xml = (
        b'<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        b'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_abc" '
        b'Destination="https://login.microsoftonline.com/example/saml2" ForceAuthn="true">'
        b"<saml:Issuer>https://vpn.example.com/saml/sp</saml:Issuer>"
        b"</samlp:AuthnRequest>"
    )
    compressor = zlib.compressobj(wbits=-15)
    request = base64.b64encode(compressor.compress(xml) + compressor.flush()).decode()
    return "https://login.microsoftonline.com/example/saml2?" + urlencode(
        [("RelayState", "keep"), ("SAMLRequest", request)]
    )


@dataclass
class FakeCookie:
    name: str
    value: str
    domain: str
    path: str = "/"
    secure: bool = True
    expires: int | None = None
    domain_specified: bool = False


class FakeResponse:
    status_code = 303
    url = "https://vpn.example.com/saml/sp/login"

    def __init__(self):
        self.headers = {"Location": _entra_redirect()}
        self.closed = False

    def close(self):
        self.closed = True

    def raise_for_status(self):
        return None


class FakeSession:
    def __init__(self):
        self.cookies = [
            FakeCookie("webvpn", "cookie-for-test", ".example.com"),
        ]
        self.response = FakeResponse()
        self.calls: list[tuple[str, dict[str, object]]] = []

    def get(self, url: str, **kwargs: object) -> FakeResponse:
        self.calls.append((url, kwargs))
        return self.response


def test_capture_meraki_redirect_streams_closes_and_preserves_gateway_cookie():
    session = FakeSession()
    policy = SamlPolicy(
        entra_host="login.microsoftonline.com",
        issuer=ISSUER,
        destination=DESTINATION,
    )

    bootstrap = capture_meraki_redirect(
        session,
        "https://vpn.example.com/saml/sp/login",
        policy,
        expected_login_url="https://vpn.example.com/saml/sp/login",
        timeout=30,
    )

    assert session.calls == [
        (
            "https://vpn.example.com/saml/sp/login",
            {"allow_redirects": False, "stream": True, "timeout": 30},
        )
    ]
    assert session.response.closed is True
    assert "ForceAuthn%3D%22false%22" not in bootstrap.login_url
    assert bootstrap.cookies[0].name == "webvpn"
    assert bootstrap.cookies[0].value == "cookie-for-test"
    assert bootstrap.cookies[0].host_only is True


def test_capture_rejects_unconfigured_gateway_login_before_network_request():
    session = FakeSession()
    policy = SamlPolicy(
        entra_host="login.microsoftonline.com",
        issuer=ISSUER,
        destination=DESTINATION,
    )

    with pytest.raises(MerakiAuthenticationError, match="login URL"):
        capture_meraki_redirect(
            session,
            "https://alternate.example.com/saml/sp/login",
            policy,
            expected_login_url="https://vpn.example.com/saml/sp/login",
            timeout=30,
        )

    assert session.calls == []


def test_probe_redirect_cannot_change_token_submission_origin(monkeypatch):
    class FakeAuthenticator:
        def __init__(self, host, *, version, timeout):
            self.host = host
            self.proxy = None
            self.ssl_legacy = False
            self.verify_tls = True
            self.timeout = timeout
            self.session = SimpleNamespace(mount=lambda *_args: None)

    class ProbeResponse:
        url = "https://evil.example/auth"

        def __init__(self):
            self.closed = False

        def raise_for_status(self):
            return None

        def close(self):
            self.closed = True

    response = ProbeResponse()

    class ProbeSession:
        def mount(self, *_args):
            return None

        def get(self, *_args, **_kwargs):
            return response

    monkeypatch.setattr(
        "meraki_openconnect.authenticator._openconnect_imports",
        lambda: (FakeAuthenticator, lambda *_args, **_kwargs: ProbeSession(), None),
    )
    host = SimpleNamespace(
        vpn_url="https://vpn.example.com/",
        address="vpn.example.com",
    )
    policy = SamlPolicy(
        entra_host="login.microsoftonline.com",
        issuer=ISSUER,
        destination=DESTINATION,
    )
    authenticator = build_moc_authenticator(
        host,
        policy=policy,
        browser_authenticate=lambda _request: None,
        leaf_sha256="a" * 64,
        expected_login_url="https://vpn.example.com/saml/sp/login",
    )

    with pytest.raises(MerakiAuthenticationError, match="redirect origin"):
        authenticator._detect_authentication_target_url()

    assert host.address == "vpn.example.com"
    assert response.closed is True


def test_authenticator_mounts_leaf_pin_on_token_and_probe_sessions(monkeypatch):
    mounted_sessions = []

    class MountingSession:
        def __init__(self):
            self.mounts = []
            mounted_sessions.append(self)

        def mount(self, prefix, adapter):
            self.mounts.append((prefix, adapter))

        def get(self, *_args, **_kwargs):
            response = FakeResponse()
            response.url = "https://vpn.example.com/saml/sp/login"
            return response

    class FakeAuthenticator:
        def __init__(self, host, *, version, timeout):
            self.host = host
            self.proxy = None
            self.ssl_legacy = False
            self.verify_tls = True
            self.timeout = timeout
            self.session = MountingSession()

    monkeypatch.setattr(
        "meraki_openconnect.authenticator._openconnect_imports",
        lambda: (FakeAuthenticator, lambda *_args, **_kwargs: MountingSession(), None),
    )
    host = SimpleNamespace(
        vpn_url="https://vpn.example.com/saml/sp/login",
        address="vpn.example.com",
    )
    policy = SamlPolicy(
        entra_host="login.microsoftonline.com",
        issuer=ISSUER,
        destination=DESTINATION,
    )

    authenticator = build_moc_authenticator(
        host,
        policy=policy,
        browser_authenticate=lambda _request: None,
        leaf_sha256="a" * 64,
        expected_login_url="https://vpn.example.com/saml/sp/login",
    )
    authenticator._detect_authentication_target_url()

    assert len(mounted_sessions) == 2
    assert all(session.mounts[0][0] == "https://" for session in mounted_sessions)
    assert all(
        session.mounts[0][1]._leaf_sha256 == "a" * 64
        for session in mounted_sessions
    )


def test_leaf_fingerprint_mismatch_blocks_post_before_body_is_sent(
    tmp_path: Path,
):
    adapter_type = getattr(authenticator_module, "_FingerprintAdapter", None)
    assert adapter_type is not None, "fingerprint-pinned HTTPS transport is missing"

    certificate = tmp_path / "certificate.pem"
    private_key = tmp_path / "private-key.pem"
    subprocess.run(
        [
            "/usr/bin/openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(private_key),
            "-out",
            str(certificate),
            "-subj",
            "/CN=localhost",
            "-days",
            "1",
        ],
        capture_output=True,
        check=True,
    )
    received_bodies: list[bytes] = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            received_bodies.append(self.rfile.read(length))
            self.send_response(200)
            self.end_headers()

        def log_message(self, _format, *_args):
            return None

    class QuietServer(http.server.ThreadingHTTPServer):
        def handle_error(self, _request, _client_address):
            return None

    server = QuietServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certificate, private_key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    session = requests.Session()
    session.mount(
        "https://",
        adapter_type(hashlib.sha256(b"different-leaf").hexdigest()),
    )
    try:
        with pytest.raises(requests.exceptions.SSLError):
            session.post(
                f"https://127.0.0.1:{server.server_port}/token",
                data=b"secret-session-token",
                timeout=3,
                verify=False,
            )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)

    assert received_bodies == []
