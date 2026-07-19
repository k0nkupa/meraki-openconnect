import base64
import zlib
from urllib.parse import parse_qsl, urlencode, urlsplit

import pytest

import meraki_openconnect.saml as saml
from meraki_openconnect.saml import SamlPolicy, SamlRewriteError, rewrite_force_authn


ISSUER = "https://vpn.example.com/saml/sp"
DESTINATION = "https://login.microsoftonline.com/example/saml2"


def _policy() -> SamlPolicy:
    return SamlPolicy(
        entra_host="login.microsoftonline.com",
        issuer=ISSUER,
        destination=DESTINATION,
    )


def _raw_deflate(xml: bytes) -> bytes:
    compressor = zlib.compressobj(wbits=-15)
    return compressor.compress(xml) + compressor.flush()


def _authn_request() -> bytes:
    return (
        b'<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        b'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_abc" '
        b'Destination="https://login.microsoftonline.com/example/saml2" ForceAuthn="true">'
        b"<saml:Issuer>https://vpn.example.com/saml/sp</saml:Issuer>"
        b"</samlp:AuthnRequest>"
    )


def _redirect_url_from_compressed(compressed: bytes) -> str:
    encoded = base64.b64encode(compressed).decode()
    return "https://login.microsoftonline.com/example/saml2?" + urlencode(
        [("RelayState", "keep-me"), ("SAMLRequest", encoded), ("extra", "1")]
    )


def _redirect_url(xml: bytes) -> str:
    return _redirect_url_from_compressed(_raw_deflate(xml))


def _decode_request(url: str) -> bytes:
    request = dict(parse_qsl(urlsplit(url).query))["SAMLRequest"]
    return zlib.decompress(base64.b64decode(request), -15)


def test_rewrites_only_force_authn_and_preserves_query_order():
    original = _authn_request()
    policy = _policy()

    rewritten = rewrite_force_authn(_redirect_url(original), policy)

    assert _decode_request(rewritten) == original.replace(b'ForceAuthn="true"', b'ForceAuthn="false"')
    assert [key for key, _ in parse_qsl(urlsplit(rewritten).query)] == [
        "RelayState",
        "SAMLRequest",
        "extra",
    ]
    assert dict(parse_qsl(urlsplit(rewritten).query))["RelayState"] == "keep-me"
    assert dict(parse_qsl(urlsplit(rewritten).query))["extra"] == "1"


def test_rejects_malformed_base64_request():
    policy = _policy()

    with pytest.raises(SamlRewriteError, match="raw-DEFLATE/base64"):
        rewrite_force_authn(
            "https://login.microsoftonline.com/example/saml2?SAMLRequest=not%40base64",
            policy,
        )


@pytest.mark.parametrize(
    ("url", "message"),
    [
        (
            "https://login.microsoftonline.com/example/saml2?SAMLRequest=x&Signature=y",
            "signed redirect",
        ),
        (
            "http://login.microsoftonline.com/example/saml2?SAMLRequest=x",
            "allowlisted Entra endpoint",
        ),
    ],
)
def test_rejects_unapproved_redirect_shape(url: str, message: str):
    policy = _policy()

    with pytest.raises(SamlRewriteError, match=message):
        rewrite_force_authn(url, policy)


def test_rejects_truncated_deflate_stream_even_when_xml_is_complete():
    truncated = _raw_deflate(_authn_request())[:-1]

    with pytest.raises(SamlRewriteError, match="raw-DEFLATE/base64"):
        rewrite_force_authn(_redirect_url_from_compressed(truncated), _policy())


def test_rejects_data_after_deflate_stream_without_reflecting_it():
    rejected_marker = b"private-trailing-data"
    payload = _raw_deflate(_authn_request()) + rejected_marker

    with pytest.raises(SamlRewriteError, match="raw-DEFLATE/base64") as error:
        rewrite_force_authn(_redirect_url_from_compressed(payload), _policy())

    assert rejected_marker.decode() not in str(error.value)


def test_bounds_final_inflater_flush_before_rejecting_oversized_output(monkeypatch):
    class FlushBoundProbe:
        eof = True
        unconsumed_tail = b""
        unused_data = b""

        def decompress(self, compressed: bytes, max_length: int) -> bytes:
            assert compressed == b"compressed"
            assert max_length == saml._MAX_INFLATED_BYTES + 1
            return b"x" * saml._MAX_INFLATED_BYTES

        def flush(self, max_length=None) -> bytes:
            assert max_length == 1, "inflater flush must have a one-byte hard bound"
            return b"y"

    monkeypatch.setattr(saml.zlib, "decompressobj", lambda *, wbits: FlushBoundProbe())
    encoded = base64.b64encode(b"compressed").decode()

    with pytest.raises(SamlRewriteError, match="allowed size"):
        saml._inflate_raw_deflate(encoded)
