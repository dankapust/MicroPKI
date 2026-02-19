"""CLI and CA init integration: negative cases, overwrite, verify (TEST-4, TEST-1)."""

import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest


def _run_micropki(*args):
    """Run micropki CLI via `python -m micropki`; return (returncode, stdout, stderr)."""
    result = subprocess.run(
        [sys.executable, "-m", "micropki"] + list(args),
        capture_output=True,
        text=True,
        cwd=Path(__file__).resolve().parent.parent,
    )
    return result.returncode, result.stdout, result.stderr


def test_cli_ca_init_missing_subject():
    """Missing --subject exits non-zero with clear error (TEST-4)."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pass") as f:
        f.write(b"pass")
        pass_path = f.name
    try:
        code, out, err = _run_micropki(
            "ca", "init",
            "--passphrase-file", pass_path,
            "--key-type", "rsa", "--key-size", "4096",
        )
        assert code != 0
        assert "subject" in err.lower() or "required" in err.lower()
    finally:
        Path(pass_path).unlink(missing_ok=True)


def test_cli_ca_init_invalid_key_type_ecc_with_256():
    """--key-type ecc with --key-size 256 must fail (TEST-4)."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pass") as f:
        f.write(b"pass")
        pass_path = f.name
    try:
        code, out, err = _run_micropki(
            "ca", "init",
            "--subject", "/CN=Test",
            "--key-type", "ecc", "--key-size", "256",
            "--passphrase-file", pass_path,
        )
        assert code != 0
        assert "384" in err or "key-size" in err.lower()
    finally:
        Path(pass_path).unlink(missing_ok=True)


def test_cli_ca_init_invalid_dn():
    """Invalid DN syntax exits non-zero (TEST-4)."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pass") as f:
        f.write(b"pass")
        pass_path = f.name
    try:
        code, _, err = _run_micropki(
            "ca", "init",
            "--subject", "CN=,O=Bad",  # empty value
            "--key-type", "rsa", "--key-size", "4096",
            "--passphrase-file", pass_path,
        )
        assert code != 0
        assert "subject" in err.lower() or "DN" in err.lower() or "invalid" in err.lower()
    finally:
        Path(pass_path).unlink(missing_ok=True)


def test_cli_ca_init_nonexistent_passphrase_file():
    """Non-existent --passphrase-file exits non-zero (TEST-4)."""
    code, out, err = _run_micropki(
        "ca", "init",
        "--subject", "/CN=Test",
        "--key-type", "rsa", "--key-size", "4096",
        "--passphrase-file", "/nonexistent/ca.pass",
    )
    assert code != 0
    assert "passphrase" in err.lower() or "exist" in err.lower() or "read" in err.lower()


def test_cli_ca_init_and_verify_self_signed(tmp_path):
    """Full flow: ca init, then ca verify (TEST-1 self-consistency)."""
    pass_file = tmp_path / "ca.pass"
    pass_file.write_bytes(b"secret")
    out_dir = tmp_path / "pki"

    code, _, err = _run_micropki(
        "ca", "init",
        "--subject", "/CN=Demo Root CA",
        "--key-type", "rsa", "--key-size", "4096",
        "--passphrase-file", str(pass_file),
        "--out-dir", str(out_dir),
        "--validity-days", "365",
    )
    assert code == 0, err
    cert_path = out_dir / "certs" / "ca.cert.pem"
    assert cert_path.exists()
    assert (out_dir / "private" / "ca.key.pem").exists()
    assert (out_dir / "policy.txt").exists()

    code2, _, err2 = _run_micropki("ca", "verify", "--cert", str(cert_path))
    assert code2 == 0, err2


def test_cli_ca_init_ecc(tmp_path):
    """ECC P-384 init succeeds and produces valid cert (PKI-1, PKI-2)."""
    pass_file = tmp_path / "ca.pass"
    pass_file.write_bytes(b"secret")
    out_dir = tmp_path / "pki"

    code, _, err = _run_micropki(
        "ca", "init",
        "--subject", "CN=ECC Root CA,O=MicroPKI",
        "--key-type", "ecc", "--key-size", "384",
        "--passphrase-file", str(pass_file),
        "--out-dir", str(out_dir),
    )
    assert code == 0, err
    cert_path = out_dir / "certs" / "ca.cert.pem"
    assert cert_path.exists()

    code2, _, err2 = _run_micropki("ca", "verify", "--cert", str(cert_path))
    assert code2 == 0, err2


def test_cli_ca_init_log_file(tmp_path):
    """--log-file writes log entries with ISO 8601, level, mandatory events (LOG-1, LOG-2)."""
    pass_file = tmp_path / "ca.pass"
    pass_file.write_bytes(b"secret")
    out_dir = tmp_path / "pki"
    log_file = tmp_path / "logs" / "ca-init.log"

    code, _, err = _run_micropki(
        "ca", "init",
        "--subject", "/CN=Log Test",
        "--key-type", "rsa", "--key-size", "4096",
        "--passphrase-file", str(pass_file),
        "--out-dir", str(out_dir),
        "--log-file", str(log_file),
    )
    assert code == 0, err
    assert log_file.exists()
    log_text = log_file.read_text(encoding="utf-8")
    assert "Starting key generation" in log_text
    assert "Key generation completed" in log_text
    assert "Starting certificate signing" in log_text
    assert "Certificate signing completed" in log_text
    assert "Saved private key" in log_text
    assert "Saved certificate" in log_text
    assert "policy" in log_text.lower()
    # Passphrase must NOT appear in logs (LOG-3)
    assert "secret" not in log_text


def test_cli_ca_init_unwritable_outdir():
    """Unwritable --out-dir exits non-zero (TEST-4)."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pass") as f:
        f.write(b"pass")
        pass_path = f.name
    try:
        code, _, err = _run_micropki(
            "ca", "init",
            "--subject", "/CN=Test",
            "--key-type", "rsa", "--key-size", "4096",
            "--passphrase-file", pass_path,
            "--out-dir", "Z:\\nonexistent\\impossible\\path",
        )
        assert code != 0
    finally:
        Path(pass_path).unlink(missing_ok=True)


def test_cli_ca_init_refuse_overwrite_without_force(tmp_path):
    """Without --force, overwriting existing key/cert should fail (CLI-6)."""
    pass_file = tmp_path / "ca.pass"
    pass_file.write_bytes(b"secret")
    out_dir = tmp_path / "pki"
    (out_dir / "private").mkdir(parents=True)
    (out_dir / "certs").mkdir(parents=True)
    (out_dir / "private" / "ca.key.pem").write_text("existing")
    (out_dir / "certs" / "ca.cert.pem").write_text("existing")

    code, _, err = _run_micropki(
        "ca", "init",
        "--subject", "/CN=Test",
        "--key-type", "rsa", "--key-size", "4096",
        "--passphrase-file", str(pass_file),
        "--out-dir", str(out_dir),
    )
    assert code != 0
    assert "overwrite" in err.lower() or "exist" in err.lower()


def test_cli_ca_init_with_force_overwrites(tmp_path):
    """With --force, existing key/cert can be overwritten."""
    pass_file = tmp_path / "ca.pass"
    pass_file.write_bytes(b"secret")
    out_dir = tmp_path / "pki"
    (out_dir / "private").mkdir(parents=True)
    (out_dir / "certs").mkdir(parents=True)
    (out_dir / "private" / "ca.key.pem").write_text("old")
    (out_dir / "certs" / "ca.cert.pem").write_text("old")

    code, _, err = _run_micropki(
        "ca", "init", "--force",
        "--subject", "/CN=Test",
        "--key-type", "rsa", "--key-size", "4096",
        "--passphrase-file", str(pass_file),
        "--out-dir", str(out_dir),
    )
    assert code == 0, err
    assert (out_dir / "private" / "ca.key.pem").read_bytes().startswith(b"-----BEGIN")
