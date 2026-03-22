"""Unique serial number generation with DB uniqueness check."""

from __future__ import annotations

import secrets
import time

from . import database


def generate_serial_candidate() -> int:
    """
    64-bit composite serial:
    high 32 bits = current unix timestamp seconds
    low 32 bits = CSPRNG random
    """
    high = int(time.time()) & 0xFFFFFFFF
    low = secrets.randbits(32)
    serial = (high << 32) | low
    return serial if serial > 0 else 1


def serial_to_hex(serial: int) -> str:
    return f"{serial:X}"


def generate_unique_serial(db_path: str, max_attempts: int = 20) -> int:
    """
    Generate a serial unique against certificates.serial_hex.
    Falls back with retries in the improbable case of collision.
    """
    database.init_db(db_path)
    for _ in range(max_attempts):
        serial = generate_serial_candidate()
        hexv = serial_to_hex(serial)
        if database.get_certificate_by_serial(db_path, hexv) is None:
            return serial
    raise RuntimeError("Could not generate unique serial after retries")
