"""Revocation module handling certificate revocation logic and reason codes."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from cryptography.x509 import ReasonFlags

from . import database
from . import repository
from .logger import setup_logging

REASON_MAPPING = {
    "unspecified": ReasonFlags.unspecified,
    "keyCompromise": ReasonFlags.key_compromise,
    "cACompromise": ReasonFlags.ca_compromise,
    "affiliationChanged": ReasonFlags.affiliation_changed,
    "superseded": ReasonFlags.superseded,
    "cessationOfOperation": ReasonFlags.cessation_of_operation,
    "certificateHold": ReasonFlags.certificate_hold,
    "removeFromCRL": ReasonFlags.remove_from_crl,
    "privilegeWithdrawn": ReasonFlags.privilege_withdrawn,
    "aACompromise": ReasonFlags.aa_compromise,
}

def parse_reason(reason_str: str) -> ReasonFlags:
    """Parse a reason string into a cryptography ReasonFlags enum."""
    reason_lower = reason_str.lower()
    for k, v in REASON_MAPPING.items():
        if k.lower() == reason_lower:
            return v
    raise ValueError(f"Unsupported revocation reason: {reason_str}")

def get_reason_string(reason_str: str) -> str:
    """Return the exact case-sensitive reason string from REASON_MAPPING if valid."""
    reason_lower = reason_str.lower()
    for k in REASON_MAPPING:
        if k.lower() == reason_lower:
            return k
    raise ValueError(f"Unsupported revocation reason: {reason_str}")

def revoke(db_path: str | Path, serial_hex: str, reason_str: str, log_file: str | None = None) -> bool:
    """
    Revoke a certificate in the database.
    Returns:
        True if successfully revoked.
        False if already revoked.
    Raises:
        ValueError if certificate not found or reason invalid.
    """
    log = setup_logging(log_file)
    try:
        reason_exact = get_reason_string(reason_str)
    except ValueError as e:
        log.error("Invalid revocation reason: %s", reason_str)
        raise e

    try:
        serial_number = int(serial_hex, 16)
    except ValueError:
        log.error("Invalid serial number hex: %s", serial_hex)
        raise ValueError(f"Invalid serial number format: {serial_hex}")

    cert_data = repository.get_certificate_by_serial(serial_number, db_path=db_path)
    if not cert_data:
        log.error("Certificate not found for revocation: %s", serial_hex)
        raise ValueError(f"Certificate not found: {serial_hex}")

    if cert_data["status"] == "revoked":
        log.warning("Certificate %s is already revoked.", serial_hex)
        return False

    revocation_date = datetime.now(timezone.utc).isoformat()
    updated = database.set_certificate_revoked(db_path, serial_hex, reason_exact, revocation_date)
    
    if updated:
        log.info("Successfully revoked certificate %s with reason %s at %s", serial_hex, reason_exact, revocation_date)
    else:
        log.warning("Certificate %s is already revoked.", serial_hex)

    return updated


def check_revocation(db_path: str | Path, serial_hex: str) -> dict:
    """
    Check the revocation status of a certificate.
    Returns a dict with status, reason, and date.
    """
    try:
        serial_number = int(serial_hex, 16)
    except ValueError:
        raise ValueError(f"Invalid serial number format: {serial_hex}")

    cert_data = repository.get_certificate_by_serial(serial_number, db_path=db_path)
    if not cert_data:
        raise ValueError(f"Certificate not found: {serial_hex}")

    return {
        "serial": serial_hex,
        "status": cert_data["status"],
        "reason": cert_data.get("revocation_reason"),
        "date": cert_data.get("revocation_date")
    }

