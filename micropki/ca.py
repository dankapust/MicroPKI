"""CA operations: Root init, Intermediate CA, end-entity issuance, verification."""

from __future__ import annotations

import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography.x509.oid import NameOID

from . import certificates
from . import crypto_utils
from . import csr as csr_module
from . import logger as log_module
from . import repository
from . import serial
from . import templates as tmpl


# ---------------------------------------------------------------------------
# Key generation helper (deduplicates rsa/ecc branching)
# ---------------------------------------------------------------------------

def _gen_key(key_type: str, key_size: int, logger, label: str = ""):
    logger.info("Starting key generation%s (type=%s, size=%s)",
                f" for {label}" if label else "", key_type, key_size)
    key = crypto_utils.generate_key(key_type, key_size)
    logger.info("Key generation completed successfully")
    return key


# ---------------------------------------------------------------------------
# Sprint 1: Root CA
# ---------------------------------------------------------------------------

def init_root_ca(
    subject: str, key_type: str, key_size: int,
    passphrase: bytes, out_dir: str, validity_days: int,
    log_file: str | None = None, force: bool = False,
) -> None:
    """Create self-signed Root CA: key, cert, policy.txt."""
    logger = log_module.setup_logging(log_file)
    out = Path(out_dir)
    key_path = out / "private" / "ca.key.pem"
    cert_path = out / "certs" / "ca.cert.pem"
    policy_path = out / "policy.txt"

    _check_overwrite([key_path, cert_path], force, logger)

    key = _gen_key(key_type, key_size, logger)

    logger.info("Starting certificate signing")
    cert = certificates.build_self_signed_root_ca(
        subject_dn=subject, private_key=key,
        validity_days=validity_days, key_type=key_type, key_size=key_size,
    )
    logger.info("Certificate signing completed successfully")

    _save_ca_artifacts(out, key_path, cert_path, key, passphrase, cert, logger)

    # Insert Root CA into DB
    try:
        repository.insert_certificate(
            serial_number=cert.serial_number,
            subject=cert.subject.rfc4514_string(),
            issuer=cert.issuer.rfc4514_string(),
            not_before=cert.not_valid_before_utc.isoformat(),
            not_after=cert.not_valid_after_utc.isoformat(),
            cert_pem=cert_path.read_text(encoding="utf-8"),
            status="valid",
            db_path=out / "micropki.db",
            log_file=log_file
        )
    except Exception as e:
        logger.warning("Could not insert Root CA into DB: %s", e)

    algo_desc = f"RSA-{key_size}" if key_type == "rsa" else "ECC-P384"
    policy_path.write_text(_build_root_policy(
        subject, f"{cert.serial_number:x}",
        cert.not_valid_before_utc, cert.not_valid_after_utc, algo_desc,
    ), encoding="utf-8")
    logger.info("Generated policy document at %s", str(policy_path.resolve()))


# ---------------------------------------------------------------------------
# Sprint 2: Intermediate CA
# ---------------------------------------------------------------------------

def issue_intermediate_ca(
    root_cert_path: str, root_key_path: str, root_passphrase: bytes,
    subject: str, key_type: str, key_size: int,
    passphrase: bytes, out_dir: str, validity_days: int,
    pathlen: int = 0, log_file: str | None = None, force: bool = False,
) -> None:
    """Generate Intermediate CA: key, CSR, Root signs it, save, update policy."""
    logger = log_module.setup_logging(log_file)
    out = Path(out_dir)
    key_path = out / "private" / "intermediate.key.pem"
    cert_path = out / "certs" / "intermediate.cert.pem"
    policy_path = out / "policy.txt"

    _check_overwrite([key_path, cert_path], force, logger)

    root_cert = crypto_utils.load_certificate_pem(root_cert_path)
    root_key = crypto_utils.load_private_key_encrypted(root_key_path, root_passphrase)

    inter_key = _gen_key(key_type, key_size, logger, "Intermediate CA")

    logger.info("Generating Intermediate CA CSR")
    inter_csr = csr_module.generate_intermediate_csr(subject, inter_key, pathlen)
    logger.info("Intermediate CA CSR generated")

    logger.info("Signing Intermediate CA certificate with Root CA")
    inter_cert = csr_module.sign_intermediate_csr(
        inter_csr, root_cert, root_key, validity_days, pathlen,
    )
    logger.info("Intermediate CA certificate signed (serial=%x)", inter_cert.serial_number)

    _save_ca_artifacts(out, key_path, cert_path, inter_key, passphrase, inter_cert, logger)

    # Insert Intermediate CA into DB
    try:
        repository.insert_certificate(
            serial_number=inter_cert.serial_number,
            subject=inter_cert.subject.rfc4514_string(),
            issuer=inter_cert.issuer.rfc4514_string(),
            not_before=inter_cert.not_valid_before_utc.isoformat(),
            not_after=inter_cert.not_valid_after_utc.isoformat(),
            cert_pem=cert_path.read_text(encoding="utf-8"),
            status="valid",
            db_path=out / "micropki.db",
            log_file=log_file
        )
    except Exception as e:
        logger.warning("Could not insert Intermediate CA into DB: %s", e)

    algo_desc = f"RSA-{key_size}" if key_type == "rsa" else "ECC-P384"
    _append_intermediate_policy(
        policy_path, subject, f"{inter_cert.serial_number:x}",
        inter_cert.not_valid_before_utc, inter_cert.not_valid_after_utc,
        algo_desc, pathlen, root_cert.subject.rfc4514_string(),
    )
    logger.info("Updated policy document at %s", str(policy_path.resolve()))


# ---------------------------------------------------------------------------
# Sprint 2: End-entity certificates
# ---------------------------------------------------------------------------

def issue_end_entity(
    ca_cert_path: str, ca_key_path: str, ca_passphrase: bytes,
    template: str, subject: str, san_strings: list[str],
    out_dir: str, validity_days: int,
    csr_path: str | None = None, log_file: str | None = None,
) -> None:
    """Issue end-entity certificate using a template. Optionally sign external CSR."""
    logger = log_module.setup_logging(log_file)

    ca_cert = crypto_utils.load_certificate_pem(ca_cert_path)
    ca_key = crypto_utils.load_private_key_encrypted(ca_key_path, ca_passphrase)

    san_names = tmpl.parse_san_list(san_strings) if san_strings else []
    tmpl.validate_san_for_template(template, san_names)

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    base_name = _safe_filename(_extract_cn(subject))

    if csr_path:
        ext_csr = crypto_utils.load_csr_pem(csr_path)
        if not ext_csr.is_signature_valid:
            raise ValueError("CSR signature verification failed")
        public_key = ext_csr.public_key()
        leaf_key = None
    else:
        logger.info("Generating key pair for end-entity certificate")
        is_rsa_ca = crypto_utils.is_rsa_key(ca_key)
        leaf_key = crypto_utils.generate_key("rsa", 2048) if is_rsa_ca else crypto_utils.generate_key("ecc", 256)
        public_key = leaf_key.public_key()
        logger.info("Key pair generated for %s", subject)

    ext = tmpl.get_template_extensions(template, san_names, is_rsa=crypto_utils.is_rsa_key(public_key))

    logger.info("Issuing %s certificate for %s", template, subject)
    cert = csr_module.issue_end_entity_cert(
        subject_dn=subject, public_key=public_key,
        ca_cert=ca_cert, ca_key=ca_key,
        validity_days=validity_days, template_ext=ext,
    )
    san_desc = ", ".join(san_strings) if san_strings else "none"
    logger.info(
        "Certificate issued: serial=%x, subject=%s, template=%s, SANs=[%s], issued=%s",
        cert.serial_number, subject, template, san_desc,
        datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )

    cert_file = out / f"{base_name}.cert.pem"
    cert_file.write_bytes(crypto_utils.cert_to_pem(cert))
    logger.info("Saved certificate to %s", str(cert_file.resolve()))

    # Insert certificate into database
    try:
        # Determine DB path relative to out_dir
        # If out_dir is 'pki/certs', DB should be in 'pki/micropki.db'
        db_path = out.parent / "micropki.db" if out.name == "certs" else out / "micropki.db"
        
        repository.insert_certificate(
            serial_number=cert.serial_number,
            subject=cert.subject.rfc4514_string(),
            issuer=cert.issuer.rfc4514_string(),
            not_before=cert.not_valid_before_utc.isoformat(),
            not_after=cert.not_valid_after_utc.isoformat(),
            cert_pem=cert_file.read_text(encoding="utf-8"),
            status="valid",
            created_at=datetime.now(timezone.utc).isoformat(),
            db_path=db_path,
            log_file=log_file
        )
        logger.info("Certificate inserted into database: serial=%x, subject=%s", cert.serial_number, cert.subject)
    except Exception as e:
        logger.error("Failed to insert certificate into database: %s", e)
        # Not raising here to still allow key saving if issuance succeeded
        print(f"Warning: Failed to store certificate in the database: {e}", file=sys.stderr)

    if leaf_key is not None:
        key_file = out / f"{base_name}.key.pem"
        crypto_utils.write_private_key_unencrypted(str(key_file), leaf_key, logger=logger)


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def verify_certificate(cert_path: str, log_file: str | None = None) -> bool:
    """Verify self-signed certificate."""
    logger = log_module.setup_logging(log_file)
    cert = crypto_utils.load_certificate_pem(cert_path)
    try:
        crypto_utils.verify_cert_signature(cert, cert)
    except Exception as e:
        logger.error("Certificate signature verification failed: %s", e)
        raise
    logger.info("Certificate verification succeeded: %s", cert_path)
    return True


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _check_overwrite(paths: list[Path], force: bool, logger) -> None:
    if force:
        return
    for p in paths:
        if p.exists():
            logger.error("Refusing to overwrite: %s (use --force)", p)
            raise FileExistsError(f"File exists: {p}")


def _save_ca_artifacts(out: Path, key_path: Path, cert_path: Path,
                       key, passphrase: bytes, cert, logger) -> None:
    crypto_utils.ensure_private_dir_permissions(str(key_path.parent), logger=logger)
    crypto_utils.write_private_key_pem(str(key_path), key, passphrase, logger=logger)
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    cert_path.write_bytes(crypto_utils.cert_to_pem(cert))
    logger.info("Saved certificate to %s", str(cert_path.resolve()))


def _extract_cn(subject_dn: str) -> str:
    name = certificates.parse_subject_dn(subject_dn)
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return attrs[0].value if attrs else "cert"


def _safe_filename(name: str) -> str:
    safe = re.sub(r'[^\w.\-]', '_', name).strip('_')
    return safe or "cert"


def _build_root_policy(subject, serial_hex, not_before, not_after, key_algo) -> str:
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


def _append_intermediate_policy(policy_path, subject, serial_hex,
                                not_before, not_after, key_algo, pathlen, issuer_dn) -> None:
    section = f"""
Intermediate CA
---------------
CA Name (Subject DN): {subject}
Certificate Serial Number (hex): {serial_hex}
Validity Period:
  NotBefore: {not_before.strftime('%Y-%m-%d %H:%M:%S UTC')}
  NotAfter:  {not_after.strftime('%Y-%m-%d %H:%M:%S UTC')}
Key Algorithm and Size: {key_algo}
Path Length Constraint: {pathlen}
Issuer (Root CA) DN: {issuer_dn}
"""
    with open(policy_path, "a", encoding="utf-8") as f:
        f.write(section)
