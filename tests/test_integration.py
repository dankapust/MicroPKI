"""Sprint 2 integration tests: intermediate CA, issue-cert, chain validation, negative cases."""

import subprocess
import sys
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID


def _run(*args):
    import sys
    from io import StringIO
    from micropki.cli import main
    stdout = StringIO()
    stderr = StringIO()
    old_stdout, old_stderr, old_argv = sys.stdout, sys.stderr, sys.argv
    sys.stdout, sys.stderr, sys.argv = stdout, stderr, ["micropki"] + [str(a) for a in args]
    try:
        exit_code = main() or 0
    except SystemExit as e:
        exit_code = e.code if e.code is not None else 0
    except Exception as e:
        stderr.write(str(e))
        exit_code = 1
    finally:
        sys.stdout, sys.stderr, sys.argv = old_stdout, old_stderr, old_argv
    return exit_code, stdout.getvalue(), stderr.getvalue()


@pytest.fixture(scope="module")
def pki_dir(tmp_path_factory, run_cli):
    """Set up Root CA + Intermediate CA once for the module."""
    base = tmp_path_factory.mktemp("pki_s2")
    secrets = base / "secrets"
    secrets.mkdir()
    (secrets / "root.pass").write_bytes(b"rootpass")
    (secrets / "inter.pass").write_bytes(b"interpass")
    out = base / "pki"

    code, _, err = run_cli(
        "ca", "init",
        "--subject", "/CN=Test Root CA",
        "--key-type", "rsa", "--key-size", "4096",
        "--passphrase-file", str(secrets / "root.pass"),
        "--out-dir", str(out),
    )
    assert code == 0, err

    code, _, err = run_cli(
        "ca", "issue-intermediate",
        "--root-cert", str(out / "certs" / "ca.cert.pem"),
        "--root-key", str(out / "private" / "ca.key.pem"),
        "--root-pass-file", str(secrets / "root.pass"),
        "--subject", "CN=Test Intermediate CA,O=MicroPKI",
        "--key-type", "rsa", "--key-size", "4096",
        "--passphrase-file", str(secrets / "inter.pass"),
        "--out-dir", str(out),
        "--validity-days", "1825",
        "--pathlen", "0",
    )
    assert code == 0, err
    return base


def test_intermediate_cert_exists(pki_dir):
    assert (pki_dir / "pki" / "certs" / "intermediate.cert.pem").exists()
    assert (pki_dir / "pki" / "private" / "intermediate.key.pem").exists()


def test_intermediate_policy_updated(pki_dir):
    policy = (pki_dir / "pki" / "policy.txt").read_text(encoding="utf-8")
    assert "Intermediate CA" in policy
    assert "Path Length Constraint" in policy


def test_intermediate_extensions(pki_dir):
    """Verify Intermediate CA has correct BC, KU, SKI, AKI (PKI-7)."""
    cert_data = (pki_dir / "pki" / "certs" / "intermediate.cert.pem").read_bytes()
    cert = x509.load_pem_x509_certificate(cert_data)

    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert bc.critical is True
    assert bc.value.ca is True
    assert bc.value.path_length == 0

    ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
    assert ku.critical is True
    assert ku.value.key_cert_sign is True
    assert ku.value.crl_sign is True

    cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)


def test_issue_server_cert(pki_dir):
    out = pki_dir / "pki" / "certs"
    code, _, err = _run(
        "ca", "issue-cert",
        "--ca-cert", str(pki_dir / "pki" / "certs" / "intermediate.cert.pem"),
        "--ca-key", str(pki_dir / "pki" / "private" / "intermediate.key.pem"),
        "--ca-pass-file", str(pki_dir / "secrets" / "inter.pass"),
        "--template", "server",
        "--subject", "CN=example.com,O=MicroPKI",
        "--san", "dns:example.com",
        "--san", "dns:www.example.com",
        "--san", "ip:192.168.1.10",
        "--out-dir", str(out),
    )
    assert code == 0, err
    assert (out / "example.com.cert.pem").exists()
    assert (out / "example.com.key.pem").exists()

    cert_data = (out / "example.com.cert.pem").read_bytes()
    cert = x509.load_pem_x509_certificate(cert_data)

    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert bc.value.ca is False

    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    assert ExtendedKeyUsageOID.SERVER_AUTH in eku.value

    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    dns_names = san.value.get_values_for_type(x509.DNSName)
    assert "example.com" in dns_names
    assert "www.example.com" in dns_names


def test_issue_client_cert(pki_dir):
    out = pki_dir / "pki" / "certs"
    code, _, err = _run(
        "ca", "issue-cert",
        "--ca-cert", str(pki_dir / "pki" / "certs" / "intermediate.cert.pem"),
        "--ca-key", str(pki_dir / "pki" / "private" / "intermediate.key.pem"),
        "--ca-pass-file", str(pki_dir / "secrets" / "inter.pass"),
        "--template", "client",
        "--subject", "CN=Alice Smith",
        "--san", "email:alice@example.com",
        "--out-dir", str(out),
    )
    assert code == 0, err
    assert (out / "Alice_Smith.cert.pem").exists()

    cert_data = (out / "Alice_Smith.cert.pem").read_bytes()
    cert = x509.load_pem_x509_certificate(cert_data)
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    assert ExtendedKeyUsageOID.CLIENT_AUTH in eku.value


def test_issue_code_signing_cert(pki_dir):
    out = pki_dir / "pki" / "certs"
    code, _, err = _run(
        "ca", "issue-cert",
        "--ca-cert", str(pki_dir / "pki" / "certs" / "intermediate.cert.pem"),
        "--ca-key", str(pki_dir / "pki" / "private" / "intermediate.key.pem"),
        "--ca-pass-file", str(pki_dir / "secrets" / "inter.pass"),
        "--template", "code_signing",
        "--subject", "CN=MicroPKI Code Signer",
        "--out-dir", str(out),
    )
    assert code == 0, err
    assert (out / "MicroPKI_Code_Signer.cert.pem").exists()

    cert_data = (out / "MicroPKI_Code_Signer.cert.pem").read_bytes()
    cert = x509.load_pem_x509_certificate(cert_data)
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    assert ExtendedKeyUsageOID.CODE_SIGNING in eku.value


def test_verify_chain(pki_dir):
    out = pki_dir / "pki"
    code, stdout, err = _run(
        "ca", "verify-chain",
        "--leaf", str(out / "certs" / "example.com.cert.pem"),
        "--intermediate", str(out / "certs" / "intermediate.cert.pem"),
        "--root", str(out / "certs" / "ca.cert.pem"),
    )
    assert code == 0, err
    assert "OK" in stdout


def test_server_cert_without_san_fails(pki_dir):
    """Server certificate without SAN must fail."""
    out = pki_dir / "pki" / "certs"
    code, _, err = _run(
        "ca", "issue-cert",
        "--ca-cert", str(pki_dir / "pki" / "certs" / "intermediate.cert.pem"),
        "--ca-key", str(pki_dir / "pki" / "private" / "intermediate.key.pem"),
        "--ca-pass-file", str(pki_dir / "secrets" / "inter.pass"),
        "--template", "server",
        "--subject", "CN=noSAN.com",
        "--out-dir", str(out),
    )
    assert code != 0
    assert "SAN" in err or "san" in err.lower()


def test_server_cert_with_email_san_fails(pki_dir):
    """Server cert with email SAN (unsupported type) must fail."""
    out = pki_dir / "pki" / "certs"
    code, _, err = _run(
        "ca", "issue-cert",
        "--ca-cert", str(pki_dir / "pki" / "certs" / "intermediate.cert.pem"),
        "--ca-key", str(pki_dir / "pki" / "private" / "intermediate.key.pem"),
        "--ca-pass-file", str(pki_dir / "secrets" / "inter.pass"),
        "--template", "server",
        "--subject", "CN=badsan.com",
        "--san", "email:bad@example.com",
        "--out-dir", str(out),
    )
    assert code != 0
    assert "not allowed" in err.lower() or "email" in err.lower()


def test_wrong_passphrase_fails(pki_dir):
    """Incorrect passphrase must fail."""
    wrong_pass = pki_dir / "secrets" / "wrong.pass"
    wrong_pass.write_bytes(b"wrongpassword")
    out = pki_dir / "pki" / "certs"
    code, _, err = _run(
        "ca", "issue-cert",
        "--ca-cert", str(pki_dir / "pki" / "certs" / "intermediate.cert.pem"),
        "--ca-key", str(pki_dir / "pki" / "private" / "intermediate.key.pem"),
        "--ca-pass-file", str(wrong_pass),
        "--template", "code_signing",
        "--subject", "CN=WrongPass",
        "--out-dir", str(out),
    )
    assert code != 0
