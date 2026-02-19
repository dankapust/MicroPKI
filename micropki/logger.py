"""Logging setup: file or stderr, ISO 8601 timestamps, no sensitive data."""

import logging
import sys
from datetime import datetime, timezone


def setup_logging(log_file: str | None = None) -> logging.Logger:
    """
    Configure root logger for MicroPKI.
    If log_file is set, append to file; otherwise log to stderr.
    Format: timestamp (ISO 8601 with ms), level, message.
    """
    root = logging.getLogger("micropki")
    root.setLevel(logging.DEBUG)

    for h in list(root.handlers):
        root.removeHandler(h)

    fmt = "%(asctime)s %(levelname)s %(message)s"

    class UtcFormatter(logging.Formatter):
        def formatTime(self, record, datefmt=None):
            dt = datetime.fromtimestamp(record.created, tz=timezone.utc)
            ms = getattr(record, "msecs", 0)
            return dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{int(ms):03d}Z"

    formatter = UtcFormatter(fmt)

    if log_file:
        from pathlib import Path
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        handler = logging.FileHandler(log_file, mode="a", encoding="utf-8")
    else:
        handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(formatter)
    root.addHandler(handler)

    return root
