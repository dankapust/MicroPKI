"""CRL generation (RFC 5280) using cryptography CRL builders."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from . import crypto_utils
from . import database
from .csr import _build_aki_from_issuer


def _parse_iso_utc_z(s: str) -> datetime:
    if not s:
        return datetime.now(timezone.utc)
    t = s.replace("Z", "+00:00")
    dt = datetime.fromisoformat(t)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def reason_string_to_flag(reason: str | None) -> x509.ReasonFlags | None:
    """Map DB / CLI canonical string to ReasonFlags; None -> no extension."""
    if not reason:
        return None
    mapping = {
        "unspecified": x509.ReasonFlags.unspecified,
        "keyCompromise": x509.ReasonFlags.key_compromise,
        "cACompromise": x509.ReasonFlags.ca_compromise,
        "affiliationChanged": x509.ReasonFlags.affiliation_changed,
        "superseded": x509.ReasonFlags.superseded,
        "cessationOfOperation": x509.ReasonFlags.cessation_of_operation,
        "certificateHold": x509.ReasonFlags.certificate_hold,
        "removeFromCRL": x509.ReasonFlags.remove_from_crl,
        "privilegeWithdrawn": x509.ReasonFlags.privilege_withdrawn,
        "aACompromise": x509.ReasonFlags.aa_compromise,
    }
    return mapping.get(reason)


def _next_crl_number(conn: sqlite3.Connection, ca_subject: str) -> int:
    cur = conn.execute(
        "SELECT crl_number FROM crl_metadata WHERE ca_subject = ?",
        (ca_subject,),
    )
    row = cur.fetchone()
    if row is None:
        return 1
    return int(row["crl_number"]) + 1


def _save_crl_metadata(
    conn: sqlite3.Connection,
    *,
    ca_subject: str,
    crl_number: int,
    last_generated: str,
    next_update: str,
    crl_path: str,
) -> None:
    conn.execute(
        """
        INSERT INTO crl_metadata (ca_subject, crl_number, last_generated, next_update, crl_path)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(ca_subject) DO UPDATE SET
            crl_number = excluded.crl_number,
            last_generated = excluded.last_generated,
            next_update = excluded.next_update,
            crl_path = excluded.crl_path
        """,
        (ca_subject, crl_number, last_generated, next_update, crl_path),
    )


def build_crl(
    ca_cert: x509.Certificate,
    ca_key,
    revoked_rows,
    *,
    crl_number: int,
    this_update: datetime,
    next_update: datetime,
) -> x509.CertificateRevocationList:
    """Build and sign a full CRL (v2) with AKI and CRLNumber extensions."""
    algo = ca_cert.signature_hash_algorithm
    if algo is None:
        algo = crypto_utils.signing_algorithm(ca_key)

    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(this_update)
        .next_update(next_update)
    )

    aki = _build_aki_from_issuer(ca_cert)
    builder = builder.add_extension(aki, critical=False)
    builder = builder.add_extension(x509.CRLNumber(crl_number), critical=False)

    for row in revoked_rows:
        serial = int(row["serial_hex"], 16)
        rev_date = _parse_iso_utc_z(row["revocation_date"] or "")
        rb = (
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(rev_date)
        )
        flag = reason_string_to_flag(row["revocation_reason"])
        if flag is not None:
            rb = rb.add_extension(x509.CRLReason(flag), critical=False)
        builder = builder.add_revoked_certificate(rb.build())

    return builder.sign(ca_key, algo)


def generate_crl_for_ca(
    db_path: str,
    out_dir: str,
    ca_cert: x509.Certificate,
    ca_key,
    *,
    next_update_days: int,
    out_file: str | None,
    default_crl_filename: str | None,
    logger,
) -> tuple[str, int]:
    """
    Query revoked certs for this CA issuer DN, build CRL, write PEM, persist metadata.
    Returns (written_path, number_of_revoked_entries).
    """
    issuer_dn = ca_cert.subject.rfc4514_string()
    logger.info("Starting CRL generation for CA subject=%s", issuer_dn)
    revoked = database.list_revoked_by_issuer(db_path, issuer_dn)

    out_root = Path(out_dir)
    crl_dir = out_root / "crl"
    crl_dir.mkdir(parents=True, exist_ok=True)

    if out_file:
        out_path = Path(out_file)
        out_path.parent.mkdir(parents=True, exist_ok=True)
    else:
        fname = default_crl_filename or "intermediate.crl.pem"
        out_path = crl_dir / fname

    try:
        rel_for_meta = str(out_path.resolve().relative_to(out_root.resolve()))
    except ValueError:
        rel_for_meta = str(out_path.resolve())

    this_update = datetime.now(timezone.utc)
    next_update = this_update + timedelta(days=next_update_days)

    with database.connect(db_path) as conn:
        crl_no = _next_crl_number(conn, issuer_dn)
        crl_obj = build_crl(
            ca_cert,
            ca_key,
            revoked,
            crl_number=crl_no,
            this_update=this_update,
            next_update=next_update,
        )
        pem = crl_obj.public_bytes(serialization.Encoding.PEM)
        out_path.write_bytes(pem)

        _save_crl_metadata(
            conn,
            ca_subject=issuer_dn,
            crl_number=crl_no,
            last_generated=database.utc_now_iso(),
            next_update=next_update.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z"),
            crl_path=rel_for_meta,
        )
        conn.commit()

    logger.info(
        "CRL generated: ca=%s revoked_count=%d thisUpdate=%s nextUpdate=%s crlNumber=%d path=%s",
        issuer_dn,
        len(revoked),
        this_update.strftime("%Y-%m-%dT%H:%M:%SZ"),
        next_update.strftime("%Y-%m-%dT%H:%M:%SZ"),
        crl_no,
        str(out_path.resolve()),
    )
    return str(out_path.resolve()), len(revoked)

