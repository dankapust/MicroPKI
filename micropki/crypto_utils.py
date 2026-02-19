"""PEM/DER conversions, key generation, encrypted key storage. No custom crypto."""

import os
from pathlib import Path
from typing import Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.backends import default_backend


def load_passphrase(path: str) -> bytes:
    """
    Read passphrase from file. Strips trailing newline.
    Content must not be logged or echoed.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Passphrase file not found: {path}")
    if not p.is_file():
        raise ValueError(f"Not a file: {path}")
    data = p.read_bytes()
    return data.rstrip(b"\n\r")


def generate_rsa_key(bits: int = 4096) -> rsa.RSAPrivateKey:
    """Generate RSA key pair using secure RNG. Required: 4096 bits for Root CA."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits,
        backend=default_backend(),
    )


def generate_ecc_key(curve_bits: int = 384):
    """Generate ECC key on NIST P-384 (secp384r1). curve_bits must be 384."""
    if curve_bits != 384:
        raise ValueError("Only P-384 (384 bits) is supported for ECC")
    return ec.generate_private_key(ec.SECP384R1(), default_backend())


def private_key_to_pem_encrypted(
    key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey],
    passphrase: bytes,
) -> bytes:
    """Serialize private key to PEM with AES (BestAvailableEncryption)."""
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
    )


def write_private_key_pem(path: str, key, passphrase: bytes, logger=None) -> None:
    """Write encrypted private key to path with 0o600. Create parent dirs if needed."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    pem = private_key_to_pem_encrypted(key, passphrase)
    path_obj = Path(path)
    path_obj.write_bytes(pem)
    try:
        path_obj.chmod(0o600)
    except OSError:
        if logger:
            logger.warning("Could not set file permissions 0o600 on %s (e.g. Windows)", path)
    if logger:
        logger.info("Saved private key to %s", str(Path(path).resolve()))


def ensure_private_dir_permissions(dir_path: str, logger=None) -> None:
    """Create directory with 0o700 if needed; set permissions when supported."""
    p = Path(dir_path)
    p.mkdir(parents=True, exist_ok=True)
    try:
        p.chmod(0o700)
    except OSError:
        if logger:
            logger.warning("Could not set directory permissions 0o700 on %s (e.g. Windows)", dir_path)


def cert_to_pem(cert) -> bytes:
    """Serialize X.509 certificate to PEM (RFC 7468)."""
    return cert.public_bytes(serialization.Encoding.PEM)


def load_private_key_encrypted(path: str, passphrase: bytes):
    """Load PKCS#8 encrypted private key from PEM file."""
    data = Path(path).read_bytes()
    return serialization.load_pem_private_key(
        data,
        password=passphrase,
        backend=default_backend(),
    )


def load_certificate_pem(path: str):
    """Load X.509 certificate from PEM file."""
    from cryptography import x509
    data = Path(path).read_bytes()
    return x509.load_pem_x509_certificate(data, default_backend())
