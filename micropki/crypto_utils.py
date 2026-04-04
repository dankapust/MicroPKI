"""PEM/DER conversions, key generation, encrypted key storage, common crypto helpers."""

from __future__ import annotations

import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa


def make_serial() -> int:
    """CSPRNG serial number, ≤159 bits, positive (RFC 5280)."""
    serial = int.from_bytes(os.urandom(19), "big")
    return serial if serial > 0 else 1


def signing_algorithm(key) -> hashes.HashAlgorithm:
    """SHA-256 for RSA keys, SHA-384 for ECC keys."""
    if isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        return hashes.SHA256()
    return hashes.SHA384()


def generate_key(key_type: str, key_size: int):
    """
    Generate RSA or ECC key pair.
    Supported: rsa/4096, rsa/2048, ecc/384 (P-384), ecc/256 (P-256).
    """
    if key_type == "rsa":
        return rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    if key_type == "ecc":
        curves = {256: ec.SECP256R1(), 384: ec.SECP384R1()}
        curve = curves.get(key_size)
        if curve is None:
            raise ValueError(f"Unsupported ECC curve size: {key_size}. Must be 256 or 384.")
        return ec.generate_private_key(curve)
    raise ValueError(f"Unsupported key type: {key_type}")


def verify_cert_signature(cert: x509.Certificate, issuer_cert: x509.Certificate) -> None:
    """Verify cert's signature against issuer's public key (RSA or ECC)."""
    pub = issuer_cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        pub.verify(cert.signature, cert.tbs_certificate_bytes,
                    padding.PKCS1v15(), cert.signature_hash_algorithm)
    else:
        pub.verify(cert.signature, cert.tbs_certificate_bytes,
                    ec.ECDSA(cert.signature_hash_algorithm))


def is_rsa_key(key) -> bool:
    """Check if key (private or public) is RSA."""
    return isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey))


def load_passphrase(path: str) -> bytes:
    """Read passphrase from file, strip trailing newline. Never log content."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Passphrase file not found: {path}")
    if not p.is_file():
        raise ValueError(f"Not a file: {path}")
    return p.read_bytes().rstrip(b"\n\r")


def generate_rsa_key(bits: int = 4096) -> rsa.RSAPrivateKey:
    return generate_key("rsa", bits)


def generate_ecc_key(curve_bits: int = 384):
    if curve_bits not in (256, 384):
        raise ValueError("Only P-256 (256) and P-384 (384) are supported for ECC")
    return generate_key("ecc", curve_bits)


def private_key_to_pem_encrypted(key, passphrase: bytes) -> bytes:
    """Serialize private key to PEM with AES (BestAvailableEncryption / PKCS#8)."""
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
    )


def private_key_to_pem_unencrypted(key) -> bytes:
    """Serialize private key to PEM without encryption (for end-entity keys)."""
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def cert_to_pem(cert) -> bytes:
    """Serialize X.509 certificate to PEM (RFC 7468)."""
    return cert.public_bytes(serialization.Encoding.PEM)


def _set_permissions(path_obj: Path, mode: int, logger=None) -> None:
    try:
        path_obj.chmod(mode)
    except OSError:
        if logger:
            logger.warning("Could not set permissions %04o on %s (e.g. Windows)", mode, path_obj)


def write_private_key_pem(path: str, key, passphrase: bytes, logger=None) -> None:
    """Write encrypted private key to path with 0o600."""
    path_obj = Path(path)
    path_obj.parent.mkdir(parents=True, exist_ok=True)
    path_obj.write_bytes(private_key_to_pem_encrypted(key, passphrase))
    _set_permissions(path_obj, 0o600, logger)
    if logger:
        logger.info("Saved private key to %s", str(path_obj.resolve()))


def write_private_key_unencrypted(path: str, key, logger=None) -> None:
    """Write unencrypted private key with 0o600 and a warning."""
    path_obj = Path(path)
    path_obj.parent.mkdir(parents=True, exist_ok=True)
    path_obj.write_bytes(private_key_to_pem_unencrypted(key))
    _set_permissions(path_obj, 0o600, logger)
    if logger:
        logger.warning("Private key stored UNENCRYPTED at %s", str(path_obj.resolve()))


def ensure_private_dir_permissions(dir_path: str, logger=None) -> None:
    """Create directory with 0o700 if needed."""
    p = Path(dir_path)
    p.mkdir(parents=True, exist_ok=True)
    _set_permissions(p, 0o700, logger)


def load_private_key_encrypted(path: str, passphrase: bytes):
    """Load PKCS#8 encrypted private key from PEM file."""
    data = Path(path).read_bytes()
    return serialization.load_pem_private_key(data, password=passphrase)


def load_certificate_pem(path: str) -> x509.Certificate:
    data = Path(path).read_bytes()
    return x509.load_pem_x509_certificate(data)


def load_csr_pem(path: str) -> x509.CertificateSigningRequest:
    data = Path(path).read_bytes()
    return x509.load_pem_x509_csr(data)
