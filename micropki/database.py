from __future__ import annotations
import sqlite3
from pathlib import Path
from .logger import setup_logging
def get_db_connection(db_path: str | Path) -> sqlite3.Connection:
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row  
    return conn
def init_database(db_path: str | Path, log_file: str | None = None) -> None:
    logger = setup_logging(log_file)
    conn = None
    try:
        conn = get_db_connection(db_path)
        conn.execute('''
            CREATE TABLE IF NOT EXISTS certificates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                serial_number TEXT UNIQUE NOT NULL,
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
        ''')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_serial ON certificates(serial_number)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_status ON certificates(status)')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS crl_metadata (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ca_subject TEXT NOT NULL,
                crl_number INTEGER NOT NULL,
                last_generated TEXT NOT NULL,
                next_update TEXT NOT NULL,
                crl_path TEXT NOT NULL
            )
        ''')
        conn.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_ca_subject ON crl_metadata(ca_subject)')
        conn.commit()
        logger.info("Database initialised successfully at %s", db_path)
    except sqlite3.Error as e:
        logger.error("Database initialisation failed: %s", e)
        raise
    finally:
        if conn:
            conn.close()
def set_certificate_revoked(db_path: str | Path, serial_number_hex: str, reason: str, revocation_date: str) -> bool:
    conn = get_db_connection(db_path)
    try:
        cur = conn.cursor()
        cur.execute("SELECT status FROM certificates WHERE serial_number = ?", (serial_number_hex,))
        row = cur.fetchone()
        if not row:
            return False
        if row["status"] == "revoked":
            return False
        cur.execute('''
            UPDATE certificates
            SET status = 'revoked', revocation_reason = ?, revocation_date = ?
            WHERE serial_number = ?
        ''', (reason, revocation_date, serial_number_hex))
        conn.commit()
        return True
    finally:
        conn.close()
def get_revoked_certificates_by_issuer(db_path: str | Path, issuer: str) -> list[dict]:
    conn = get_db_connection(db_path)
    try:
        cur = conn.cursor()
        cur.execute('''
            SELECT serial_number, revocation_reason, revocation_date
            FROM certificates
            WHERE issuer = ? AND status = 'revoked'
        ''', (issuer,))
        return [dict(row) for row in cur.fetchall()]
    finally:
        conn.close()
def get_crl_metadata(db_path: str | Path, ca_subject: str) -> dict | None:
    conn = get_db_connection(db_path)
    try:
        cur = conn.cursor()
        cur.execute('''
            SELECT crl_number, last_generated, next_update, crl_path
            FROM crl_metadata
            WHERE ca_subject = ?
        ''', (ca_subject,))
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()
def update_crl_metadata(db_path: str | Path, ca_subject: str, crl_number: int, 
                        last_generated: str, next_update: str, crl_path: str) -> None:
    conn = get_db_connection(db_path)
    try:
        cur = conn.cursor()
        cur.execute("SELECT id FROM crl_metadata WHERE ca_subject = ?", (ca_subject,))
        if cur.fetchone():
            cur.execute('''
                UPDATE crl_metadata
                SET crl_number = ?, last_generated = ?, next_update = ?, crl_path = ?
                WHERE ca_subject = ?
            ''', (crl_number, last_generated, next_update, crl_path, ca_subject))
        else:
            cur.execute('''
                INSERT INTO crl_metadata (ca_subject, crl_number, last_generated, next_update, crl_path)
                VALUES (?, ?, ?, ?, ?)
            ''', (ca_subject, crl_number, last_generated, next_update, crl_path))
        conn.commit()
    finally:
        conn.close()
