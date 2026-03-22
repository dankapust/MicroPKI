"""CLI: ca/db/repo commands for MicroPKI."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import ca
from . import database
from . import crypto_utils
from . import logger as log_module
from . import repository


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _validate_file_exists(parser, path, label):
    if not path or not Path(path).is_file():
        parser.error(f"{label} must exist and be readable: {path}")


def _validate_passphrase_file(parser, path, label="--passphrase-file"):
    if not path:
        parser.error(f"{label} is required")
    p = Path(path)
    if not p.exists():
        parser.error(f"{label} must exist: {path}")
    if not p.is_file():
        parser.error(f"{label} is not a file: {path}")
    try:
        p.read_bytes()
    except OSError:
        parser.error(f"Cannot read {label}: {path}")


def _validate_subject(parser, args):
    subject = getattr(args, "subject", None)
    if not (subject or "").strip():
        parser.error("--subject is required and must be non-empty")
    try:
        from . import certificates
        certificates.parse_subject_dn(subject)
    except ValueError as e:
        parser.error(f"Invalid --subject DN: {e}")


def _validate_out_dir(parser, out_dir):
    out = Path(out_dir)
    if out.exists() and not out.is_dir():
        parser.error(f"--out-dir must be a directory: {out_dir}")
    try:
        out.mkdir(parents=True, exist_ok=True)
        test = out / ".micropki_write_test"
        test.write_text("")
        test.unlink()
    except OSError:
        parser.error(f"--out-dir must be writable: {out_dir}")


def _default_db_path_for_out_dir(out_dir: str) -> str:
    out = Path(out_dir)
    if out.name == "certs":
        return str(out.parent / "micropki.db")
    return str(out / "micropki.db")


def _validate_key_type_size(parser, key_type: str, key_size: int) -> None:
    key_type = (key_type or "").lower()
    if key_type == "rsa" and key_size not in (2048, 4096):
        parser.error("--key-size must be 2048 or 4096 for RSA")
    if key_type == "ecc" and key_size not in (256, 384):
        parser.error("--key-size must be 256 or 384 for ECC")


# ---------------------------------------------------------------------------
# ca init (Sprint 1)
# ---------------------------------------------------------------------------

def cmd_ca_init(args) -> int:
    parser = getattr(args, "_parser", argparse.ArgumentParser())
    log = log_module.setup_logging(getattr(args, "log_file", None))

    _validate_subject(parser, args)

    key_type = args.key_type.lower()
    if key_type == "rsa" and args.key_size != 4096:
        log.error("--key-size must be 4096 for RSA")
        parser.error("--key-size must be 4096 for RSA")
    if key_type == "ecc" and args.key_size != 384:
        log.error("--key-size must be 384 for ECC")
        parser.error("--key-size must be 384 for ECC")

    _validate_passphrase_file(parser, args.passphrase_file)
    out_dir = args.out_dir or "./pki"
    _validate_out_dir(parser, out_dir)

    if not isinstance(args.validity_days, int) or args.validity_days <= 0:
        parser.error("--validity-days must be a positive integer")

    try:
        passphrase = crypto_utils.load_passphrase(args.passphrase_file)
    except Exception as e:
        log.error("Cannot read passphrase file: %s", e)
        print("Error: could not read passphrase file.", file=sys.stderr)
        return 1

    try:
        ca.init_root_ca(
            subject=args.subject.strip(),
            key_type=key_type,
            key_size=args.key_size,
            passphrase=passphrase,
            out_dir=out_dir,
            validity_days=args.validity_days,
            db_path=args.db_path,
            log_file=args.log_file,
            force=getattr(args, "force", False),
        )
    except FileExistsError as e:
        print(str(e), file=sys.stderr)
        return 1
    except Exception as e:
        log.exception("CA init failed")
        print(f"Error: {e}", file=sys.stderr)
        return 1
    return 0


# ---------------------------------------------------------------------------
# ca issue-intermediate (Sprint 2)
# ---------------------------------------------------------------------------

def cmd_ca_issue_intermediate(args) -> int:
    parser = getattr(args, "_parser", argparse.ArgumentParser())
    log = log_module.setup_logging(getattr(args, "log_file", None))

    _validate_file_exists(parser, args.root_cert, "--root-cert")
    _validate_file_exists(parser, args.root_key, "--root-key")
    _validate_passphrase_file(parser, args.root_pass_file, "--root-pass-file")
    _validate_passphrase_file(parser, args.passphrase_file, "--passphrase-file")
    _validate_subject(parser, args)
    _validate_key_type_size(parser, args.key_type, args.key_size)
    if args.pathlen < 0:
        parser.error("--pathlen must be >= 0")
    out_dir = args.out_dir or "./pki"
    _validate_out_dir(parser, out_dir)

    try:
        root_pass = crypto_utils.load_passphrase(args.root_pass_file)
        inter_pass = crypto_utils.load_passphrase(args.passphrase_file)
    except Exception as e:
        log.error("Cannot read passphrase file: %s", e)
        print("Error: could not read passphrase file.", file=sys.stderr)
        return 1

    try:
        ca.issue_intermediate_ca(
            root_cert_path=args.root_cert,
            root_key_path=args.root_key,
            root_passphrase=root_pass,
            subject=args.subject.strip(),
            key_type=args.key_type.lower(),
            key_size=args.key_size,
            passphrase=inter_pass,
            out_dir=out_dir,
            validity_days=args.validity_days,
            pathlen=args.pathlen,
            db_path=args.db_path,
            log_file=args.log_file,
            force=getattr(args, "force", False),
        )
    except FileExistsError as e:
        print(str(e), file=sys.stderr)
        return 1
    except Exception as e:
        log.exception("issue-intermediate failed")
        print(f"Error: {e}", file=sys.stderr)
        return 1
    return 0


# ---------------------------------------------------------------------------
# ca issue-cert (Sprint 2)
# ---------------------------------------------------------------------------

def cmd_ca_issue_cert(args) -> int:
    parser = getattr(args, "_parser", argparse.ArgumentParser())
    log = log_module.setup_logging(getattr(args, "log_file", None))

    _validate_file_exists(parser, args.ca_cert, "--ca-cert")
    _validate_file_exists(parser, args.ca_key, "--ca-key")
    _validate_passphrase_file(parser, args.ca_pass_file, "--ca-pass-file")
    _validate_subject(parser, args)
    out_dir = args.out_dir or "./pki/certs"
    _validate_out_dir(parser, out_dir)

    try:
        ca_pass = crypto_utils.load_passphrase(args.ca_pass_file)
    except Exception as e:
        log.error("Cannot read passphrase file: %s", e)
        print("Error: could not read passphrase file.", file=sys.stderr)
        return 1

    try:
        ca.issue_end_entity(
            ca_cert_path=args.ca_cert,
            ca_key_path=args.ca_key,
            ca_passphrase=ca_pass,
            template=args.template,
            subject=args.subject.strip(),
            san_strings=args.san or [],
            out_dir=out_dir,
            validity_days=args.validity_days,
            csr_path=getattr(args, "csr", None),
            db_path=args.db_path,
            log_file=args.log_file,
        )
    except ValueError as e:
        log.error("Validation error: %s", e)
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        log.exception("issue-cert failed")
        print(f"Error: {e}", file=sys.stderr)
        return 1
    return 0


def cmd_ca_list_certs(args) -> int:
    log = log_module.setup_logging(getattr(args, "log_file", None))
    try:
        status_filter = args.status if args.status in ("valid", "revoked") else None
        rows = database.list_certificates(args.db_path, status=status_filter)
        if args.status == "expired":
            from datetime import datetime, timezone
            now = datetime.now(timezone.utc)
            rows = [r for r in rows if datetime.fromisoformat(r["not_after"].replace("Z", "+00:00")) < now]
    except Exception as e:
        log.error("Database query failed: %s", e)
        print(f"Error: {e}", file=sys.stderr)
        return 1

    if args.format == "json":
        import json
        print(json.dumps([dict(r) for r in rows], ensure_ascii=False, indent=2))
        return 0
    if args.format == "csv":
        print("serial,subject,expiration,status")
        for r in rows:
            print(f"{r['serial_hex']},{r['subject']},{r['not_after']},{r['status']}")
        return 0

    # table
    print(f"{'SERIAL':<20} {'STATUS':<8} {'EXPIRES':<22} SUBJECT")
    print("-" * 95)
    for r in rows:
        print(f"{r['serial_hex']:<20} {r['status']:<8} {r['not_after']:<22} {r['subject']}")
    return 0


def cmd_ca_show_cert(args) -> int:
    log = log_module.setup_logging(getattr(args, "log_file", None))
    serial_hex = args.serial.strip()
    try:
        int(serial_hex, 16)
    except ValueError:
        print("Error: serial must be hex", file=sys.stderr)
        return 1
    try:
        row = database.get_certificate_by_serial(args.db_path, serial_hex)
    except Exception as e:
        log.error("Database query failed: %s", e)
        print(f"Error: {e}", file=sys.stderr)
        return 1
    if row is None:
        print("Error: certificate not found", file=sys.stderr)
        return 1
    log.info("Certificate retrieval via ca show-cert: serial=%s", serial_hex.upper())
    print(row["cert_pem"])
    return 0


# ---------------------------------------------------------------------------
# ca verify (Sprint 1)
# ---------------------------------------------------------------------------

def cmd_ca_verify(args) -> int:
    cert_path = getattr(args, "cert", None)
    if not cert_path or not Path(cert_path).exists():
        log = log_module.setup_logging(getattr(args, "log_file", None))
        log.error("Certificate file not found: %s", cert_path)
        print(f"Error: certificate file not found: {cert_path}", file=sys.stderr)
        return 1
    try:
        ca.verify_certificate(cert_path, log_file=args.log_file)
        return 0
    except Exception as e:
        print(f"Verification failed: {e}", file=sys.stderr)
        return 1


# ---------------------------------------------------------------------------
# ca verify-chain (Sprint 2, TEST-7)
# ---------------------------------------------------------------------------

def cmd_ca_verify_chain(args) -> int:
    log = log_module.setup_logging(getattr(args, "log_file", None))
    from . import chain as chain_module

    for p in [args.leaf, args.root] + (args.intermediate or []):
        if not Path(p).is_file():
            log.error("File not found: %s", p)
            print(f"Error: file not found: {p}", file=sys.stderr)
            return 1

    try:
        leaf = crypto_utils.load_certificate_pem(args.leaf)
        root = crypto_utils.load_certificate_pem(args.root)
        intermediates = [crypto_utils.load_certificate_pem(p) for p in (args.intermediate or [])]
        chain_module.validate_chain(leaf, intermediates, root)
        log.info("Chain validation succeeded: leaf=%s", args.leaf)
        print("Chain validation: OK")
        return 0
    except Exception as e:
        log.error("Chain validation failed: %s", e)
        print(f"Chain validation failed: {e}", file=sys.stderr)
        return 1


def cmd_db_init(args) -> int:
    log = log_module.setup_logging(getattr(args, "log_file", None))
    try:
        database.init_db(args.db_path)
        log.info("Database initialization succeeded: %s", args.db_path)
        print(f"Database ready: {args.db_path}")
        return 0
    except Exception as e:
        log.error("Database initialization failed: %s", e)
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_repo_serve(args) -> int:
    log = log_module.setup_logging(getattr(args, "log_file", None))
    try:
        database.init_db(args.db_path)
        repository.serve(args.host, args.port, args.db_path, args.cert_dir, log)
        return 0
    except KeyboardInterrupt:
        print("\nRepository server stopped")
        return 0
    except Exception as e:
        log.error("Repository server failed: %s", e)
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_repo_status(args) -> int:
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.0)
    try:
        s.connect((args.host, args.port))
        print(f"Repository server appears RUNNING on {args.host}:{args.port}")
        return 0
    except OSError:
        print(f"Repository server NOT reachable on {args.host}:{args.port}")
        return 1
    finally:
        s.close()


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(prog="micropki", description="MicroPKI - minimal PKI")
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    ca_parser = subparsers.add_parser("ca", help="CA operations")
    ca_sub = ca_parser.add_subparsers(dest="ca_command")
    db_parser = subparsers.add_parser("db", help="Database operations")
    db_sub = db_parser.add_subparsers(dest="db_command")
    repo_parser = subparsers.add_parser("repo", help="Repository server operations")
    repo_sub = repo_parser.add_subparsers(dest="repo_command")

    # --- ca init ---
    p = ca_sub.add_parser("init", help="Create self-signed Root CA")
    p.set_defaults(_parser=p, _run=cmd_ca_init)
    p.add_argument("--subject", required=True)
    p.add_argument("--key-type", default="rsa", choices=["rsa", "ecc"])
    p.add_argument("--key-size", type=int, default=4096)
    p.add_argument("--passphrase-file", required=True)
    p.add_argument("--out-dir", default="./pki")
    p.add_argument("--validity-days", type=int, default=3650)
    p.add_argument("--log-file", default=None)
    p.add_argument("--force", action="store_true")
    p.add_argument("--db-path", default="./pki/micropki.db", help="SQLite DB path (default: ./pki/micropki.db)")

    # --- ca issue-intermediate ---
    p = ca_sub.add_parser("issue-intermediate", help="Create Intermediate CA signed by Root")
    p.set_defaults(_parser=p, _run=cmd_ca_issue_intermediate)
    p.add_argument("--root-cert", required=True, help="Root CA cert PEM")
    p.add_argument("--root-key", required=True, help="Root CA encrypted key PEM")
    p.add_argument("--root-pass-file", required=True, help="Root CA passphrase file")
    p.add_argument("--subject", required=True)
    p.add_argument("--key-type", default="rsa", choices=["rsa", "ecc"])
    p.add_argument("--key-size", type=int, default=4096)
    p.add_argument("--passphrase-file", required=True, help="Intermediate CA passphrase file")
    p.add_argument("--out-dir", default="./pki")
    p.add_argument("--validity-days", type=int, default=1825)
    p.add_argument("--pathlen", type=int, default=0)
    p.add_argument("--log-file", default=None)
    p.add_argument("--force", action="store_true")
    p.add_argument("--db-path", default="./pki/micropki.db", help="SQLite DB path (default: ./pki/micropki.db)")

    # --- ca issue-cert ---
    p = ca_sub.add_parser("issue-cert", help="Issue end-entity certificate")
    p.set_defaults(_parser=p, _run=cmd_ca_issue_cert)
    p.add_argument("--ca-cert", required=True, help="Issuing CA cert PEM")
    p.add_argument("--ca-key", required=True, help="Issuing CA encrypted key PEM")
    p.add_argument("--ca-pass-file", required=True, help="Issuing CA passphrase file")
    p.add_argument("--template", required=True, choices=["server", "client", "code_signing"])
    p.add_argument("--subject", required=True)
    p.add_argument("--san", action="append", help="SAN entry (e.g. dns:example.com, ip:1.2.3.4, email:a@b.c)")
    p.add_argument("--out-dir", default="./pki/certs")
    p.add_argument("--validity-days", type=int, default=365)
    p.add_argument("--csr", default=None, help="External CSR PEM (optional)")
    p.add_argument("--log-file", default=None)
    p.add_argument("--db-path", default=None, help="SQLite DB path (default: inferred from --out-dir)")

    # --- ca verify ---
    p = ca_sub.add_parser("verify", help="Verify certificate (self-signed)")
    p.set_defaults(_run=cmd_ca_verify)
    p.add_argument("--cert", required=True)
    p.add_argument("--log-file", default=None)

    # --- ca list-certs ---
    p = ca_sub.add_parser("list-certs", help="List certificates from database")
    p.set_defaults(_run=cmd_ca_list_certs)
    p.add_argument("--db-path", default="./pki/micropki.db")
    p.add_argument("--status", choices=["valid", "revoked", "expired"], default=None)
    p.add_argument("--format", choices=["table", "json", "csv"], default="table")
    p.add_argument("--log-file", default=None)

    # --- ca show-cert ---
    p = ca_sub.add_parser("show-cert", help="Show certificate PEM by serial")
    p.set_defaults(_run=cmd_ca_show_cert)
    p.add_argument("serial")
    p.add_argument("--db-path", default="./pki/micropki.db")
    p.add_argument("--log-file", default=None)

    # --- ca verify-chain ---
    p = ca_sub.add_parser("verify-chain", help="Validate full certificate chain")
    p.set_defaults(_run=cmd_ca_verify_chain)
    p.add_argument("--leaf", required=True, help="Leaf certificate PEM")
    p.add_argument("--intermediate", action="append", help="Intermediate cert(s) PEM")
    p.add_argument("--root", required=True, help="Root CA cert PEM")
    p.add_argument("--log-file", default=None)

    # --- db init ---
    p = db_sub.add_parser("init", help="Initialize SQLite database schema")
    p.set_defaults(_run=cmd_db_init)
    p.add_argument("--db-path", default="./pki/micropki.db")
    p.add_argument("--log-file", default=None)

    # --- repo serve ---
    p = repo_sub.add_parser("serve", help="Start HTTP repository server")
    p.set_defaults(_run=cmd_repo_serve)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--db-path", default="./pki/micropki.db")
    p.add_argument("--cert-dir", default="./pki/certs")
    p.add_argument("--log-file", default=None)

    p = repo_sub.add_parser("status", help="Check repository server port availability")
    p.set_defaults(_run=cmd_repo_status)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8080)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "ca":
        if not getattr(args, "ca_command", None):
            ca_parser.print_help()
            sys.exit(0)
        if getattr(args, "db_path", None) is None and getattr(args, "out_dir", None):
            args.db_path = _default_db_path_for_out_dir(args.out_dir)
        run = getattr(args, "_run", None)
        if run:
            sys.exit(run(args))

    if args.command == "db":
        if not getattr(args, "db_command", None):
            db_parser.print_help()
            sys.exit(0)
        run = getattr(args, "_run", None)
        if run:
            sys.exit(run(args))

    if args.command == "repo":
        if not getattr(args, "repo_command", None):
            repo_parser.print_help()
            sys.exit(0)
        run = getattr(args, "_run", None)
        if run:
            sys.exit(run(args))

    sys.exit(0)


if __name__ == "__main__":
    main()
