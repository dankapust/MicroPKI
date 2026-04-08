"""HTTP repository server using FastAPI."""

from __future__ import annotations

import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

import fastapi
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware

from . import crypto_utils
from .database import get_db_connection
from .logger import setup_logging
from .repository import get_certificate_by_serial, list_certificates

app = FastAPI(title="MicroPKI Repository", version="1.0")

# Configure logging for the server
logger = None

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def init_server(log_file: str | None = None, cert_dir: str | Path = "./pki/certs"):
    """Initialise the server (logging, paths)."""
    global logger
    logger = setup_logging(log_file)
    global CERT_DIR
    CERT_DIR = Path(cert_dir)
    if not CERT_DIR.exists():
        logger.error("Certificate directory does not exist: %s", CERT_DIR)
        raise FileNotFoundError(f"Certificate directory not found: {CERT_DIR}")
    logger.info("Repository server initialised. Serving certificates from %s", CERT_DIR)

@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log every HTTP request."""
    start_time = datetime.now()
    response = await call_next(request)
    duration = (datetime.now() - start_time).total_seconds() * 1000
    if logger:
        logger.info("[HTTP] %s %s %s %d %dms", 
                    request.client.host, request.method, request.url.path, 
                    response.status_code, duration)
    return response

@app.get("/certificate/{serial_hex}")
async def get_certificate(serial_hex: str):
    """Retrieve a certificate by its serial number."""
    serial_hex = serial_hex.upper()
    try:
        serial_number = int(serial_hex, 16)
        cert_data = get_certificate_by_serial(serial_number)
    except Exception as e:
        if logger: logger.error("Database error in /certificate: %s", e)
        raise HTTPException(status_code=500, detail="Internal server error")
    
    if not cert_data:
        raise HTTPException(status_code=404, detail="Certificate not found")
    
    if cert_data["status"] == "revoked":
        raise HTTPException(status_code=410, detail="Certificate revoked")
    
    return PlainTextResponse(content=cert_data["cert_pem"], media_type="application/x-pem-file")


@app.get("/ca/{level}")
async def get_ca_certificate(level: str):
    """Retrieve the Root or Intermediate CA certificate."""
    if level not in ["root", "intermediate"]:
        raise HTTPException(status_code=400, detail="Invalid level. Use 'root' or 'intermediate'")
    
    filename = "ca.cert.pem" if level == "root" else "intermediate.cert.pem"
    cert_path = CERT_DIR / filename
    
    if not cert_path.exists():
        raise HTTPException(status_code=404, detail="CA certificate not found")
    
    try:
        cert_pem = cert_path.read_text(encoding="utf-8")
        return PlainTextResponse(content=cert_pem, media_type="application/x-pem-file")
    except Exception as e:
        if logger: logger.error("Error reading CA certificate file %s: %s", cert_path, e)
        raise HTTPException(status_code=500, detail="Error reading CA certificate")


@app.get("/crl")
async def get_crl(ca: str = "intermediate"):
    """Retrieve the current CRL for the specified CA."""
    if ca not in ["root", "intermediate"]:
        raise HTTPException(status_code=400, detail="Invalid CA. Use 'root' or 'intermediate'")
    
    filename = f"{ca}.crl.pem"
    crl_path = CERT_DIR.parent / "crl" / filename
    
    if not crl_path.exists():
        raise HTTPException(status_code=404, detail="CRL not found")
    
    try:
        crl_pem = crl_path.read_text(encoding="utf-8")
        # Compute ETag / Last-Modified simplisticly over file stat
        stat = crl_path.stat()
        headers = {
            "Content-Type": "application/pkix-crl",
            "Last-Modified": datetime.fromtimestamp(stat.st_mtime, timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT'),
            "Cache-Control": "max-age=3600"  # Example caching
        }
        return PlainTextResponse(content=crl_pem, media_type="application/pkix-crl", headers=headers)
    except Exception as e:
        if logger: logger.error("Error reading CRL file %s: %s", crl_path, e)
        raise HTTPException(status_code=500, detail="Error reading CRL file")


@app.get("/")
async def root():
    """Root endpoint for health check."""
    return {"message": "MicroPKI Repository is running", "status": "ok"}
