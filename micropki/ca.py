"""Root CA: key generation, self-signed certificate, policy file, verification."""

from pathlib import Path
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from . import certificates
from . import crypto_utils
from . import logger as log_module


def init_root_ca(
    subject: str,
    key_type: str,
    key_size: int,
    passphrase: bytes,
    out_dir: str,
    validity_days: int,
    log_file: str | None = None,
    force: bool = False,
) -> None:
    """
    Create self-signed Root CA: generate key, build cert, write encrypted key,
    cert PEM, and policy.txt. Creates private/, certs/ under out_dir.
    """
    logger = log_module.setup_logging(log_file)

    out = Path(out_dir)
    private_dir = out / "private"
    certs_dir = out / "certs"
    key_path = private_dir / "ca.key.pem"
    cert_path = certs_dir / "ca.cert.pem"
    policy_path = out / "policy.txt"

    if not force:
        for p in (key_path, cert_path):
            if p.exists():
                logger.error("Refusing to overwrite existing file: %s (use --force to override)", p)
                raise FileExistsError(f"File exists: {p}")

    # Key generation
    logger.info("Starting key generation (type=%s, size=%s)", key_type, key_size)
    if key_type == "rsa":
        key = crypto_utils.generate_rsa_key(key_size)
    else:
        key = crypto_utils.generate_ecc_key(key_size)
    logger.info("Key generation completed successfully")

    # Certificate
    logger.info("Starting certificate signing")
    cert = certificates.build_self_signed_root_ca(
        subject_dn=subject,
        private_key=key,
        validity_days=validity_days,
        key_type=key_type,
        key_size=key_size,
    )
    logger.info("Certificate signing completed successfully")

    # Dirs and permissions
    crypto_utils.ensure_private_dir_permissions(str(private_dir), logger=logger)
    certs_dir.mkdir(parents=True, exist_ok=True)

    # Save key (write_private_key_pem logs the path internally)
    crypto_utils.write_private_key_pem(str(key_path), key, passphrase, logger=logger)

    # Save cert
    pem = crypto_utils.cert_to_pem(cert)
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    cert_path.write_bytes(pem)
    logger.info("Saved certificate to %s", str(cert_path.resolve()))

    # Policy document (serial as hex)
    algo_desc = f"RSA-{key_size}" if key_type == "rsa" else "ECC-P384"
    policy_content = _build_policy_content(
        subject=subject,
        serial_hex=f"{cert.serial_number:x}",
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        key_algo=algo_desc,
    )
    policy_path.write_text(policy_content, encoding="utf-8")
    logger.info("Generated policy document at %s", str(policy_path.resolve()))


def _build_policy_content(
    subject: str,
    serial_hex: str,
    not_before: datetime,
    not_after: datetime,
    key_algo: str,
) -> str:
    """Build policy.txt content (POL-1)."""
    created = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return f"""MicroPKI Certificate Policy Document
=====================================
Policy Version: 1.0
Creation Date: {created}

CA Name (Subject DN): {subject}
Certificate Serial Number (hex): {serial_hex}
Validity Period:
  NotBefore: {not_before.strftime('%Y-%m-%d %H:%M:%S UTC')}
  NotAfter:  {not_after.strftime('%Y-%m-%d %H:%M:%S UTC')}
Key Algorithm and Size: {key_algo}

Purpose: Root CA for MicroPKI demonstration. This CA is the trust anchor
for the MicroPKI PKI. Use only in non-production or lab environments.
"""


def verify_certificate(cert_path: str, log_file: str | None = None) -> bool:
    """
    Verify certificate using itself as trust anchor (self-signed).
    Returns True if valid. Logs and raises on failure.
    """
    logger = log_module.setup_logging(log_file)
    cert = crypto_utils.load_certificate_pem(cert_path)
    pub = cert.public_key()
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            pub.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        else:
            pub.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm),
            )
    except Exception as e:
        logger.error("Certificate signature verification failed: %s", e)
        raise
    logger.info("Certificate verification succeeded: %s", cert_path)
    return True
