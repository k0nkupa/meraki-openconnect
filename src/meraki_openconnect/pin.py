"""Verified TLS public-key pin capture for OpenConnect."""

from __future__ import annotations

import base64
import hashlib
import re
import subprocess
from dataclasses import dataclass

from cryptography import x509


OPENSSL = "/opt/homebrew/bin/openssl"
_HOSTNAME = re.compile(r"[a-z0-9][a-z0-9.-]{0,252}\Z", re.IGNORECASE)
_TLS_TIMEOUT_SECONDS = 10


class PinError(RuntimeError):
    """A TLS peer could not be verified and pinned."""


@dataclass(frozen=True)
class TlsPeerEvidence:
    spki_pin: str
    leaf_sha256: str
    spki_sha1: str

    def matches_pin(self, saved_pin: str) -> bool:
        scheme, _, digest = saved_pin.partition(":")
        if scheme == "sha1":
            return self.spki_sha1 == digest.lower()
        if scheme == "sha256":
            spki_sha256 = base64.b64decode(self.spki_pin.removeprefix("pin-sha256:"))
            return spki_sha256.hex() == digest.lower()
        return self.spki_pin == saved_pin


def pin_change_summary(gateway: str, saved_pin: str, observed_pin: str) -> str:
    return (
        f"Gateway: {gateway}\n"
        f"Saved public-key fingerprint: {saved_pin}\n"
        f"Observed public-key fingerprint: {observed_pin}\n"
        "Approve only after verifying that your organization intended this change."
    )


def _verified_leaf(gateway: str) -> bytes:
    if not _HOSTNAME.fullmatch(gateway):
        raise PinError("gateway hostname is invalid")
    try:
        certificate = subprocess.run(
            [
                OPENSSL,
                "s_client",
                "-connect",
                f"{gateway}:443",
                "-servername",
                gateway,
                "-verify_hostname",
                gateway,
                "-verify_return_error",
            ],
            input=b"",
            capture_output=True,
            check=True,
            timeout=_TLS_TIMEOUT_SECONDS,
        ).stdout
        certificate_der = subprocess.run(
            [OPENSSL, "x509", "-outform", "DER"],
            input=certificate,
            capture_output=True,
            check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise PinError("gateway TLS certificate verification failed") from exc
    if not certificate_der:
        raise PinError("gateway TLS certificate is incomplete")
    return certificate_der


def gateway_tls_evidence(gateway: str) -> TlsPeerEvidence:
    """Return SPKI and leaf-certificate hashes after CA and hostname verification."""
    return _certificate_evidence(_verified_leaf(gateway))


def gateway_tls_evidence_for_exact_dns(gateway: str) -> TlsPeerEvidence:
    """Return the peer's fingerprints after verifying the chain and exact DNS SAN."""
    certificate_der = _verified_leaf(gateway)
    try:
        leaf = x509.load_der_x509_certificate(certificate_der)
        names = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        dns_names = ()
    except (
        ValueError,
        x509.InvalidVersion,
        x509.DuplicateExtension,
        x509.UnsupportedGeneralNameType,
    ) as exc:
        raise PinError("could not read the verified gateway certificate") from exc
    else:
        dns_names = names.value.get_values_for_type(x509.DNSName)
    if not any(name.lower() == gateway.lower() for name in dns_names):
        raise PinError(
            "gateway TLS certificate lacks an exact DNS subject alternative name"
        )
    return _certificate_evidence(certificate_der)


def _certificate_evidence(certificate_der: bytes) -> TlsPeerEvidence:
    try:
        public_key = subprocess.run(
            [OPENSSL, "x509", "-inform", "DER", "-pubkey", "-noout"],
            input=certificate_der,
            capture_output=True,
            check=True,
        ).stdout
        public_key_der = subprocess.run(
            [OPENSSL, "pkey", "-pubin", "-outform", "DER"],
            input=public_key,
            capture_output=True,
            check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise PinError("gateway TLS certificate verification failed") from exc
    if not public_key_der:
        raise PinError("gateway TLS certificate is incomplete")
    encoded = base64.b64encode(hashlib.sha256(public_key_der).digest()).decode("ascii")
    return TlsPeerEvidence(
        spki_pin=f"pin-sha256:{encoded}",
        leaf_sha256=hashlib.sha256(certificate_der).hexdigest(),
        spki_sha1=hashlib.sha1(public_key_der).hexdigest(),
    )


def gateway_tls_pin(gateway: str) -> str:
    """Return the SHA-256 SPKI pin after system-trust hostname verification."""
    return gateway_tls_evidence(gateway).spki_pin
