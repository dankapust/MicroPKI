"""HTTP repository server for certificates and CA endpoints."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from . import database


def _is_hex(s: str) -> bool:
    try:
        int(s, 16)
        return True
    except ValueError:
        return False


def create_server(host: str, port: int, db_path: str, cert_dir: str, logger):
    cert_dir_path = Path(cert_dir)

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

        def log_message(self, fmt, *args):
            # Avoid default stdout logger; handled in do_GET.
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
                    self._send_text(501, "CRL generation not yet implemented", "application/pkix-crl")
                    status = 501

                elif path.startswith("/ca/"):
                    self._send_text(404, "Unknown CA level; use /ca/root or /ca/intermediate")
                    status = 404

                else:
                    self._send_text(404, "Not Found")
                    status = 404

            except Exception as e:
                self._send_text(500, f"Internal server error: {e}")
                status = 500

            logger.info("[HTTP] %s %s from %s -> %s", self.command, path, client_ip, status)

        def do_POST(self):
            self._send_text(405, "Method Not Allowed")
            client_ip = self.client_address[0] if self.client_address else "unknown"
            logger.info("[HTTP] %s %s from %s -> %s", self.command, self.path, client_ip, 405)

    return ThreadingHTTPServer((host, port), Handler)


def serve(host: str, port: int, db_path: str, cert_dir: str, logger):
    server = create_server(host, port, db_path, cert_dir, logger)
    logger.info("Repository server listening on http://%s:%s", host, port)
    server.serve_forever()
