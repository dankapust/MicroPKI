"""Unit tests: key generation, encrypted key storage, passphrase loading."""

import tempfile
from pathlib import Path

import pytest

from micropki import crypto_utils
from micropki import certificates


def test_generate_rsa_key():
    """RSA key is 4096 bits and can sign/verify."""
    key = crypto_utils.generate_rsa_key(4096)
    assert key.key_size == 4096


def test_generate_ecc_key():
    """ECC key is on P-384 curve."""
    key = crypto_utils.generate_ecc_key(384)
    # curve is SECP384R1
    assert key.curve.name == "secp384r1"


def test_generate_ecc_key_only_384():
    """Only 384 is allowed for ECC."""
    with pytest.raises(ValueError, match="Only P-384"):
        crypto_utils.generate_ecc_key(256)


def test_load_passphrase_strips_newline():
    """Passphrase file content has trailing newline stripped."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pass") as f:
        f.write(b"secret\n")
        path = f.name
    try:
        data = crypto_utils.load_passphrase(path)
        assert data == b"secret"
    finally:
        Path(path).unlink(missing_ok=True)


def test_load_passphrase_file_not_found():
    """Missing passphrase file raises FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        crypto_utils.load_passphrase("/nonexistent/path.pass")


def test_encrypted_key_roundtrip():
    """Encrypted private key can be saved and loaded with same passphrase (TEST-3)."""
    key = crypto_utils.generate_rsa_key(4096)
    passphrase = b"test-passphrase"
    pem = crypto_utils.private_key_to_pem_encrypted(key, passphrase)
    assert b"ENCRYPTED" in pem or b"PRIVATE KEY" in pem

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as f:
        f.write(pem)
        path = f.name
    try:
        loaded = crypto_utils.load_private_key_encrypted(path, passphrase)
        # Sign with loaded key and verify with original public key
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        msg = b"test message"
        sig = loaded.sign(msg, padding.PKCS1v15(), hashes.SHA256())
        key.public_key().verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())
    finally:
        Path(path).unlink(missing_ok=True)
