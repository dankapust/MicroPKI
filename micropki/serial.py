"""Unique serial number generator for certificates."""

from __future__ import annotations

import os
import time


def generate_serial() -> int:
    """
    Generate a unique 64-bit certificate serial number.
    High 32 bits: Unix timestamp (seconds).
    Low 32 bits: CSPRNG value.
    """
    timestamp_part = int(time.time()) & 0xFFFFFFFF
    random_part = int.from_bytes(os.urandom(4), "big")
    serial = (timestamp_part << 32) | random_part
    return serial


def serial_to_hex(serial: int) -> str:
    """Convert a serial number integer to a hex string."""
    return f"{serial:x}".upper()
