"""SQLite database access for certificate lifecycle tracking."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def connect(db_path: str) -> sqlite3.Connection:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str) -> None:
    """Initialize schema (idempotent), indexes, and migrate to latest version."""
    with connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS certificates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                serial_hex TEXT UNIQUE NOT NULL,
                subject TEXT NOT NULL,
                issuer TEXT NOT NULL,
                not_before TEXT NOT NULL,
                not_after TEXT NOT NULL,
                cert_pem TEXT NOT NULL,
                status TEXT NOT NULL,
                revocation_reason TEXT,
                revocation_date TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_certificates_serial ON certificates(serial_hex)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_certificates_status ON certificates(status)")

        uv = conn.execute("PRAGMA user_version").fetchone()[0]
        if uv < 2:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS crl_metadata (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ca_subject TEXT NOT NULL UNIQUE,
                    crl_number INTEGER NOT NULL,
                    last_generated TEXT NOT NULL,
                    next_update TEXT NOT NULL,
                    crl_path TEXT NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_crl_metadata_ca_subject "
                "ON crl_metadata(ca_subject)"
            )
            conn.execute("PRAGMA user_version = 2")

        conn.commit()


def insert_certificate(
    db_path: str,
    *,
    serial_hex: str,
    subject: str,
    issuer: str,
    not_before: str,
    not_after: str,
    cert_pem: str,
    status: str = "valid",
) -> None:
    with connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO certificates
            (serial_hex, subject, issuer, not_before, not_after, cert_pem, status, revocation_reason, revocation_date, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?)
            """,
            (serial_hex.upper(), subject, issuer, not_before, not_after, cert_pem, status, utc_now_iso()),
        )
        conn.commit()


def get_certificate_by_serial(db_path: str, serial_hex: str):
    with connect(db_path) as conn:
        cur = conn.execute("SELECT * FROM certificates WHERE UPPER(serial_hex)=UPPER(?)", (serial_hex,))
        return cur.fetchone()


def list_certificates(
    db_path: str,
    *,
    status: str | None = None,
    issuer: str | None = None,
    not_before_from: str | None = None,
    not_after_to: str | None = None,
):
    query = "SELECT * FROM certificates WHERE 1=1"
    params: list[str] = []
    if status:
        query += " AND status = ?"
        params.append(status)
    if issuer:
        query += " AND issuer = ?"
        params.append(issuer)
    if not_before_from:
        query += " AND not_before >= ?"
        params.append(not_before_from)
    if not_after_to:
        query += " AND not_after <= ?"
        params.append(not_after_to)
    query += " ORDER BY created_at DESC"
    with connect(db_path) as conn:
        cur = conn.execute(query, params)
        return cur.fetchall()


def update_certificate_status(
    db_path: str,
    serial_hex: str,
    status: str,
    revocation_reason: str | None = None,
    revocation_date: str | None = None,
) -> int:
    """Update certificate status (e.g. revocation). Returns number of rows updated."""
    with connect(db_path) as conn:
        cur = conn.execute(
            """
            UPDATE certificates
            SET status = ?, revocation_reason = ?, revocation_date = ?
            WHERE UPPER(serial_hex) = UPPER(?)
            """,
            (status, revocation_reason, revocation_date, serial_hex),
        )
        conn.commit()
        return cur.rowcount


def get_revoked_certificates(db_path: str):
    with connect(db_path) as conn:
        cur = conn.execute("SELECT * FROM certificates WHERE status = 'revoked' ORDER BY revocation_date DESC")
        return cur.fetchall()


def list_revoked_by_issuer(db_path: str, issuer_dn: str):
    """All revoked certificates issued by CA with subject DN matching issuer field (RFC4514)."""
    with connect(db_path) as conn:
        cur = conn.execute(
            """
            SELECT * FROM certificates
            WHERE status = 'revoked' AND issuer = ?
            ORDER BY revocation_date ASC
            """,
            (issuer_dn,),
        )
        return cur.fetchall()


def get_crl_metadata_row(db_path: str, ca_subject: str):
    with connect(db_path) as conn:
        cur = conn.execute("SELECT * FROM crl_metadata WHERE ca_subject = ?", (ca_subject,))
        return cur.fetchone()
