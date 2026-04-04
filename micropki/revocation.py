"""Certificate revocation workflow (database updates, reason validation)."""

from __future__ import annotations

import sys
from typing import Literal

from . import database

_REASON_CANONICAL = {
    "unspecified": "unspecified",
    "keycompromise": "keyCompromise",
    "cacompromise": "cACompromise",
    "affiliationchanged": "affiliationChanged",
    "superseded": "superseded",
    "cessationofoperation": "cessationOfOperation",
    "certificatehold": "certificateHold",
    "removefromcrl": "removeFromCRL",
    "privilegewithdrawn": "privilegeWithdrawn",
    "aacompromise": "aACompromise",
}


def normalize_revocation_reason(reason: str | None) -> str:
    """Return canonical reason string or raise ValueError."""
    if reason is None or not str(reason).strip():
        return "unspecified"
    key = str(reason).strip().lower()
    if key not in _REASON_CANONICAL:
        raise ValueError(
            "Unsupported revocation reason; use one of: "
            + ", ".join(sorted({v for v in _REASON_CANONICAL.values()}))
        )
    return _REASON_CANONICAL[key]


def revoke_by_serial(
    db_path: str,
    serial_hex: str,
    reason: str | None,
    *,
    logger,
) -> Literal["ok", "already_revoked", "not_found"]:
    """
    Update certificate row to revoked. Returns outcome for CLI exit codes.
    Logs per LOG-9.
    """
    serial_hex = serial_hex.strip()
    try:
        canon_reason = normalize_revocation_reason(reason)
    except ValueError as e:
        logger.error("Revocation failed (invalid reason): %s", e)
        raise

    row = database.get_certificate_by_serial(db_path, serial_hex)
    if row is None:
        logger.error("Revocation failed: serial not found in database: %s", serial_hex.upper())
        return "not_found"

    if (row["status"] or "").lower() == "revoked":
        logger.warning(
            "Revocation skipped: certificate already revoked (serial=%s)",
            row["serial_hex"],
        )
        return "already_revoked"

    now = database.utc_now_iso()
    n = database.update_certificate_status(
        db_path,
        serial_hex,
        "revoked",
        revocation_reason=canon_reason,
        revocation_date=now,
    )
    if n == 0:
        logger.error("Revocation failed: update affected 0 rows (serial=%s)", serial_hex.upper())
        return "not_found"

    logger.info(
        "Certificate revoked: serial=%s reason=%s time=%s",
        row["serial_hex"],
        canon_reason,
        now,
    )
    return "ok"


def revocation_status_from_db_row(row) -> str:
    if row is None:
        return "not_found"
    return (row["status"] or "unknown").lower()


def confirm_or_abort(message: str, *, force: bool) -> bool:
    if force:
        return True
    if not sys.stdin.isatty():
        print("Error: not a TTY; use --force to revoke without confirmation.", file=sys.stderr)
        return False
    ans = input(f"{message} [y/N]: ").strip().lower()
    return ans in ("y", "yes")


