"""Verified TLS public-key pin capture for OpenConnect."""

from __future__ import annotations

import base64
import hashlib
import re
import subprocess
from dataclasses import dataclass


OPENSSL = "/opt/homebrew/bin/openssl"
_HOSTNAME = re.compile(r"[a-z0-9][a-z0-9.-]{0,252}\Z", re.IGNORECASE)


class PinError(RuntimeError):
    """A TLS peer could not be verified and pinned."""


@dataclass(frozen=True)
class TlsPeerEvidence:
    spki_pin: str
    leaf_sha256: str


def gateway_tls_evidence(gateway: str) -> TlsPeerEvidence:
    """Return SPKI and leaf-certificate hashes after CA and hostname verification."""
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
        ).stdout
        public_key = subprocess.run(
            [OPENSSL, "x509", "-pubkey", "-noout"],
            input=certificate,
            capture_output=True,
            check=True,
        ).stdout
        certificate_der = subprocess.run(
            [OPENSSL, "x509", "-outform", "DER"],
            input=certificate,
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
    if not public_key_der or not certificate_der:
        raise PinError("gateway TLS certificate is incomplete")
    encoded = base64.b64encode(hashlib.sha256(public_key_der).digest()).decode("ascii")
    return TlsPeerEvidence(
        spki_pin=f"pin-sha256:{encoded}",
        leaf_sha256=hashlib.sha256(certificate_der).hexdigest(),
    )


def gateway_tls_pin(gateway: str) -> str:
    """Return the SHA-256 SPKI pin after system-trust hostname verification."""
    return gateway_tls_evidence(gateway).spki_pin
