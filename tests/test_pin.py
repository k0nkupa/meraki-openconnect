import subprocess
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from meraki_openconnect.pin import (
    PinError,
    gateway_tls_evidence,
    gateway_tls_evidence_for_exact_dns,
    gateway_tls_pin,
)


def test_gateway_tls_pin_uses_a_verified_sni_probe(monkeypatch):
    commands: list[list[str]] = []

    def runner(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        commands.append(args)
        if args[1] == "s_client":
            assert kwargs["input"] == b""
            return subprocess.CompletedProcess(args, 0, stdout=b"certificate")
        if args[1:4] == ["x509", "-outform", "DER"]:
            return subprocess.CompletedProcess(args, 0, stdout=b"certificate-der")
        if args[1] == "x509":
            assert kwargs["input"] == b"certificate-der"
            return subprocess.CompletedProcess(args, 0, stdout=b"public-key")
        if args[1] == "pkey":
            assert kwargs["input"] == b"public-key"
            return subprocess.CompletedProcess(args, 0, stdout=b"der-public-key")
        raise AssertionError(args)

    monkeypatch.setattr("meraki_openconnect.pin.subprocess.run", runner)

    pin = gateway_tls_pin("vpn.example.test")

    assert pin == "pin-sha256:MMt+OI7NVCrMMda3AJVp3kOBvW17x86anbdPZwv6g8k="
    assert commands[0] == [
        "/opt/homebrew/bin/openssl",
        "s_client",
        "-connect",
        "vpn.example.test:443",
        "-servername",
        "vpn.example.test",
        "-verify_hostname",
        "vpn.example.test",
        "-verify_return_error",
    ]


def test_gateway_tls_evidence_binds_spki_and_leaf_certificate(monkeypatch):
    commands: list[list[str]] = []

    def runner(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        commands.append(args)
        if args[1] == "s_client":
            return subprocess.CompletedProcess(args, 0, stdout=b"certificate-pem")
        if args[1:4] == ["x509", "-outform", "DER"]:
            assert kwargs["input"] == b"certificate-pem"
            return subprocess.CompletedProcess(args, 0, stdout=b"certificate-der")
        if args[1] == "x509":
            assert kwargs["input"] == b"certificate-der"
            return subprocess.CompletedProcess(args, 0, stdout=b"public-key")
        if args[1] == "pkey":
            return subprocess.CompletedProcess(args, 0, stdout=b"der-public-key")
        raise AssertionError(args)

    monkeypatch.setattr("meraki_openconnect.pin.subprocess.run", runner)

    evidence = gateway_tls_evidence("vpn.example.test")

    assert evidence.spki_pin == (
        "pin-sha256:MMt+OI7NVCrMMda3AJVp3kOBvW17x86anbdPZwv6g8k="
    )
    assert evidence.leaf_sha256 == (
        "03f48c90a8e6886eab083a748a07cdbbae80c034c57ae76a11635ad852d913e3"
    )


@pytest.mark.parametrize(
    ("subject_alt_names", "expected"),
    [
        ((x509.DNSName("VPN.example.com"),), True),
        ((x509.DNSName("*.example.com"),), False),
        ((x509.UniformResourceIdentifier("https://example.com/,DNS:vpn.example.com"),), False),
        ((), False),
    ],
)
def test_rotation_requires_exact_dns_san(monkeypatch, subject_alt_names, expected):
    key = ec.generate_private_key(ec.SECP256R1())
    identity = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "vpn.example.com")])
    now = datetime.now(UTC)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(identity)
        .issuer_name(identity)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=1))
    )
    if subject_alt_names:
        leaf = leaf.add_extension(x509.SubjectAlternativeName(subject_alt_names), critical=False)
    verified_der = leaf.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)
    calls = []

    def runner(args, **kwargs):
        calls.append(args)
        if args[1] == "s_client":
            assert "-verify_return_error" in args
            return subprocess.CompletedProcess(args, 0, stdout=b"verified-PEM")
        if args[1:4] == ["x509", "-outform", "DER"]:
            assert kwargs["input"] == b"verified-PEM"
            return subprocess.CompletedProcess(args, 0, stdout=verified_der)
        if args[1] == "x509":
            assert kwargs["input"] == verified_der
            return subprocess.CompletedProcess(args, 0, stdout=b"public-key")
        return subprocess.CompletedProcess(args, 0, stdout=b"der-public-key")

    monkeypatch.setattr("meraki_openconnect.pin.subprocess.run", runner)

    if expected:
        assert gateway_tls_evidence_for_exact_dns("vpn.example.com").spki_pin == (
            "pin-sha256:MMt+OI7NVCrMMda3AJVp3kOBvW17x86anbdPZwv6g8k="
        )
    else:
        with pytest.raises(PinError, match="exact DNS subject alternative name"):
            gateway_tls_evidence_for_exact_dns("vpn.example.com")

    assert sum(call[1] == "s_client" for call in calls) == 1
