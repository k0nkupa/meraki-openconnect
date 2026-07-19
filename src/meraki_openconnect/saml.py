"""Fail-closed helpers for the Meraki-to-Entra SAML redirect."""

from __future__ import annotations

import base64
import re
import zlib
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from lxml import etree


_MAX_INFLATED_BYTES = 256 * 1024
_AUTHN_REQUEST_TAG = "{urn:oasis:names:tc:SAML:2.0:protocol}AuthnRequest"
_FORCE_AUTHN = re.compile(br"\bForceAuthn=(?P<quote>[\"'])true(?P=quote)")


class SamlRewriteError(ValueError):
    """The redirect is not the narrowly approved SAML request shape."""


@dataclass(frozen=True)
class SamlPolicy:
    entra_host: str
    issuer: str
    destination: str


def _inflate_raw_deflate(encoded: str) -> bytes:
    try:
        compressed = base64.b64decode(encoded, validate=True)
        inflater = zlib.decompressobj(wbits=-15)
        data = inflater.decompress(compressed, _MAX_INFLATED_BYTES + 1)
        if len(data) > _MAX_INFLATED_BYTES or inflater.unconsumed_tail:
            raise SamlRewriteError("SAMLRequest exceeds the allowed size")
        data += inflater.flush(_MAX_INFLATED_BYTES + 1 - len(data))
    except (ValueError, zlib.error) as exc:
        raise SamlRewriteError("SAMLRequest is not valid raw-DEFLATE/base64") from exc
    if len(data) > _MAX_INFLATED_BYTES or inflater.unconsumed_tail:
        raise SamlRewriteError("SAMLRequest exceeds the allowed size")
    if not inflater.eof or inflater.unused_data:
        raise SamlRewriteError("SAMLRequest is not valid raw-DEFLATE/base64")
    return data


def _validate_xml(xml: bytes, policy: SamlPolicy) -> None:
    try:
        root = etree.fromstring(
            xml,
            parser=etree.XMLParser(
                resolve_entities=False,
                no_network=True,
                load_dtd=False,
                recover=False,
                huge_tree=False,
            ),
        )
    except etree.XMLSyntaxError as exc:
        raise SamlRewriteError("SAMLRequest is not valid XML") from exc
    if root.tag != _AUTHN_REQUEST_TAG:
        raise SamlRewriteError("SAMLRequest is not an AuthnRequest")
    if root.get("Destination") != policy.destination:
        raise SamlRewriteError("SAMLRequest destination is not allowlisted")
    issuer = root.find("{urn:oasis:names:tc:SAML:2.0:assertion}Issuer")
    if issuer is None or issuer.text != policy.issuer:
        raise SamlRewriteError("SAMLRequest issuer is not allowlisted")
    if root.xpath(".//*[local-name()='Signature']"):
        raise SamlRewriteError("signed SAMLRequest must not be modified")
    force_authn = root.xpath(".//@ForceAuthn")
    if force_authn != ["true"]:
        raise SamlRewriteError("SAMLRequest must contain exactly one ForceAuthn=true")


def rewrite_force_authn(url: str, policy: SamlPolicy) -> str:
    """Return an equivalent redirect with only ForceAuthn true changed to false."""
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != policy.entra_host
        or parsed.port not in (None, 443)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise SamlRewriteError("redirect URL is not the allowlisted Entra endpoint")

    pairs = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
    if any(key in {"Signature", "SigAlg"} for key, _ in pairs):
        raise SamlRewriteError("signed redirect must not be modified")
    request_indexes = [index for index, (key, _) in enumerate(pairs) if key == "SAMLRequest"]
    if len(request_indexes) != 1:
        raise SamlRewriteError("redirect must contain exactly one SAMLRequest")

    index = request_indexes[0]
    xml = _inflate_raw_deflate(pairs[index][1])
    _validate_xml(xml, policy)
    rewritten_xml, substitutions = _FORCE_AUTHN.subn(
        lambda match: b'ForceAuthn=' + match.group("quote") + b"false" + match.group("quote"),
        xml,
    )
    if substitutions != 1:
        raise SamlRewriteError("SAMLRequest ForceAuthn source is ambiguous")

    compressor = zlib.compressobj(wbits=-15)
    rewritten_request = base64.b64encode(
        compressor.compress(rewritten_xml) + compressor.flush()
    ).decode("ascii")
    pairs[index] = ("SAMLRequest", rewritten_request)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(pairs), ""))
