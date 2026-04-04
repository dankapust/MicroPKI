"""HTTP repository server for certificates, CA PEMs, and CRL distribution."""

from __future__ import annotations

import email.utils
import hashlib
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from cryptography import x509

from . import database


def _is_hex(s: str) -> bool:
    try:
        int(s, 16)
        return True
    except ValueError:
        return False


def _crl_filename_for_ca_token(ca: str) -> str:
    c = (ca or "intermediate").strip().lower()
    if c == "root":
        return "root.crl.pem"
    if c in ("intermediate", "default", ""):
        return "intermediate.crl.pem"
    raise ValueError(f"Unsupported ca= parameter: {ca}")


def _crl_filename_from_subpath(segment: str) -> str | None:
    s = segment.strip().lower()
    if s in ("root.crl", "root.crl.pem", "root"):
        return "root.crl.pem"
    if s in ("intermediate.crl", "intermediate.crl.pem", "intermediate"):
        return "intermediate.crl.pem"
    return None


def create_server(host: str, port: int, db_path: str, cert_dir: str, logger, pki_dir: str | None = None):
    cert_dir_path = Path(cert_dir)
    pki_root = Path(pki_dir) if pki_dir else cert_dir_path.parent
    crl_dir_path = pki_root / "crl"

    class Handler(BaseHTTPRequestHandler):
        def _send_text(self, status: int, body: str, content_type: str = "text/plain") -> None:
            data = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(data)

        def _send_pem(self, status: int, pem_text: str) -> None:
            self._send_text(status, pem_text, "application/x-pem-file")

        def _send_crl_file(self, crl_path: Path) -> int:
            if not crl_path.is_file():
                self._send_text(404, "CRL not found")
                return 404
            data = crl_path.read_bytes()
            try:
                crl = x509.load_pem_x509_crl(data)
                next_u = crl.next_update_utc
            except Exception:
                next_u = None

            now = datetime.now(timezone.utc)
            if next_u is not None:
                delta = (next_u - now).total_seconds()
                max_age = max(60, int(delta))
            else:
                max_age = 3600

            mtime = crl_path.stat().st_mtime
            last_mod = email.utils.formatdate(mtime, usegmt=True)
            etag = hashlib.sha256(data).hexdigest()

            self.send_response(200)
            self.send_header("Content-Type", "application/pkix-crl")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Last-Modified", last_mod)
            self.send_header("Cache-Control", f"max-age={max_age}, public")
            self.send_header("ETag", f'"{etag}"')
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(data)
            return 200

        def log_message(self, fmt, *args):
            return

        def do_GET(self):
            parsed = urlparse(self.path)
            path = parsed.path
            client_ip = self.client_address[0] if self.client_address else "unknown"

            try:
                if path.startswith("/certificate/"):
                    serial_hex = path.split("/", 2)[2].strip()
                    if not serial_hex:
                        self._send_text(400, "Missing serial in URL path")
                        status = 400
                    elif not _is_hex(serial_hex):
                        self._send_text(400, "Invalid serial format; expected hex")
                        status = 400
                    else:
                        row = database.get_certificate_by_serial(db_path, serial_hex)
                        if row is None:
                            self._send_text(404, "Certificate not found")
                            status = 404
                        else:
                            self._send_pem(200, row["cert_pem"])
                            status = 200

                elif path == "/ca/root":
                    p = cert_dir_path / "ca.cert.pem"
                    if not p.exists():
                        self._send_text(404, "Root CA certificate not found")
                        status = 404
                    else:
                        self._send_pem(200, p.read_text(encoding="utf-8"))
                        status = 200

                elif path == "/ca/intermediate":
                    p = cert_dir_path / "intermediate.cert.pem"
                    if not p.exists():
                        self._send_text(404, "Intermediate CA certificate not found")
                        status = 404
                    else:
                        self._send_pem(200, p.read_text(encoding="utf-8"))
                        status = 200

                elif path == "/crl":
                    qs = parse_qs(parsed.query or "")
                    ca_vals = qs.get("ca") or ["intermediate"]
                    try:
                        fname = _crl_filename_for_ca_token(ca_vals[0])
                    except ValueError as e:
                        self._send_text(400, str(e))
                        status = 400
                    else:
                        status = self._send_crl_file(crl_dir_path / fname)

                elif path.startswith("/crl/"):
                    segment = path.split("/", 2)[2].strip()
                    fname = _crl_filename_from_subpath(segment)
                    if fname is None:
                        self._send_text(404, "Unknown CRL path")
                        status = 404
                    else:
                        status = self._send_crl_file(crl_dir_path / fname)

                elif path.startswith("/ca/"):
                    self._send_text(404, "Unknown CA level; use /ca/root or /ca/intermediate")
                    status = 404

                else:
                    self._send_text(404, "Not Found")
                    status = 404

            except Exception as e:
                self._send_text(500, f"Internal server error: {e}")
                status = 500

            logger.info("[HTTP] %s %s from %s -> %s", self.command, self.path, client_ip, status)

        def do_POST(self):
            self._send_text(405, "Method Not Allowed")
            client_ip = self.client_address[0] if self.client_address else "unknown"
            logger.info("[HTTP] %s %s from %s -> %s", self.command, self.path, client_ip, 405)

    return ThreadingHTTPServer((host, port), Handler)


def serve(host: str, port: int, db_path: str, cert_dir: str, logger, pki_dir: str | None = None):
    server = create_server(host, port, db_path, cert_dir, logger, pki_dir=pki_dir)
    logger.info("Repository server listening on http://%s:%s", host, port)
    server.serve_forever()
