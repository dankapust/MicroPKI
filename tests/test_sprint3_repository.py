"""Sprint 3: repository API tests."""

from __future__ import annotations

import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from micropki import logger as log_module
from micropki import repository


def _run(*args):
    result = subprocess.run(
        [sys.executable, "-m", "micropki"] + list(args),
        capture_output=True,
        text=True,
        cwd=Path(__file__).resolve().parent.parent,
    )
    return result.returncode, result.stdout, result.stderr


def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _http_get(url: str):
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=3) as resp:
        return resp.status, resp.read().decode("utf-8")


@pytest.fixture(scope="module")
def repo_env(tmp_path_factory):
    base = tmp_path_factory.mktemp("pki_s3_repo")
    out = base / "pki"
    secrets = base / "secrets"
    certs = out / "certs"
    secrets.mkdir()
    (secrets / "root.pass").write_bytes(b"rootpass")
    (secrets / "inter.pass").write_bytes(b"interpass")
    db = out / "micropki.db"

    assert _run("db", "init", "--db-path", str(db))[0] == 0
    assert _run(
        "ca", "init", "--subject", "/CN=Repo Root", "--key-type", "rsa", "--key-size", "4096",
        "--passphrase-file", str(secrets / "root.pass"), "--out-dir", str(out), "--db-path", str(db),
    )[0] == 0
    assert _run(
        "ca", "issue-intermediate",
        "--root-cert", str(certs / "ca.cert.pem"),
        "--root-key", str(out / "private" / "ca.key.pem"),
        "--root-pass-file", str(secrets / "root.pass"),
        "--subject", "CN=Repo Intermediate,O=MicroPKI",
        "--key-type", "rsa", "--key-size", "4096",
        "--passphrase-file", str(secrets / "inter.pass"),
        "--out-dir", str(out), "--db-path", str(db),
    )[0] == 0
    assert _run(
        "ca", "issue-cert",
        "--ca-cert", str(certs / "intermediate.cert.pem"),
        "--ca-key", str(out / "private" / "intermediate.key.pem"),
        "--ca-pass-file", str(secrets / "inter.pass"),
        "--template", "server",
        "--subject", "CN=repo.example.com",
        "--san", "dns:repo.example.com",
        "--out-dir", str(certs), "--db-path", str(db),
    )[0] == 0

    return {"out": out, "certs": certs, "db": db}


def test_repository_endpoints(repo_env):
    port = _free_port()
    logger = log_module.setup_logging(None)
    server = repository.create_server("127.0.0.1", port, str(repo_env["db"]), str(repo_env["certs"]), logger)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    time.sleep(0.2)
    base = f"http://127.0.0.1:{port}"

    # /ca/root
    st, body = _http_get(f"{base}/ca/root")
    assert st == 200
    assert "BEGIN CERTIFICATE" in body

    # /ca/intermediate
    st, body = _http_get(f"{base}/ca/intermediate")
    assert st == 200
    assert "BEGIN CERTIFICATE" in body

    # /certificate/<serial>
    code, out, err = _run("ca", "list-certs", "--db-path", str(repo_env["db"]), "--format", "json")
    assert code == 0, err
    import json
    serial_hex = json.loads(out)[0]["serial_hex"]
    st, body = _http_get(f"{base}/certificate/{serial_hex}")
    assert st == 200
    assert "BEGIN CERTIFICATE" in body

    # /certificate/XYZ -> 400
    with pytest.raises(urllib.error.HTTPError) as e:
        _http_get(f"{base}/certificate/XYZ")
    assert e.value.code == 400

    # /crl -> 501
    with pytest.raises(urllib.error.HTTPError) as e2:
        _http_get(f"{base}/crl")
    assert e2.value.code == 501

    server.shutdown()
    server.server_close()
