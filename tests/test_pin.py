import subprocess

import meraki_openconnect.pin as pin_module
from meraki_openconnect.pin import gateway_tls_pin


def test_gateway_tls_pin_uses_a_verified_sni_probe(monkeypatch):
    commands: list[list[str]] = []

    def runner(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        commands.append(args)
        if args[1] == "s_client":
            assert kwargs["input"] == b""
            return subprocess.CompletedProcess(args, 0, stdout=b"certificate")
        if args[1] == "x509":
            assert kwargs["input"] == b"certificate"
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
    evidence_function = getattr(pin_module, "gateway_tls_evidence", None)
    assert evidence_function is not None, "TLS evidence capture is missing"
    commands: list[list[str]] = []

    def runner(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        commands.append(args)
        if args[1] == "s_client":
            return subprocess.CompletedProcess(args, 0, stdout=b"certificate-pem")
        if args[1:4] == ["x509", "-outform", "DER"]:
            assert kwargs["input"] == b"certificate-pem"
            return subprocess.CompletedProcess(args, 0, stdout=b"certificate-der")
        if args[1] == "x509":
            assert kwargs["input"] == b"certificate-pem"
            return subprocess.CompletedProcess(args, 0, stdout=b"public-key")
        if args[1] == "pkey":
            return subprocess.CompletedProcess(args, 0, stdout=b"der-public-key")
        raise AssertionError(args)

    monkeypatch.setattr("meraki_openconnect.pin.subprocess.run", runner)

    evidence = evidence_function("vpn.example.test")

    assert evidence.spki_pin == (
        "pin-sha256:MMt+OI7NVCrMMda3AJVp3kOBvW17x86anbdPZwv6g8k="
    )
    assert evidence.leaf_sha256 == (
        "03f48c90a8e6886eab083a748a07cdbbae80c034c57ae76a11635ad852d913e3"
    )
