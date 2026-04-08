"""CLI: micropki ca init|issue-intermediate|issue-cert|verify|verify-chain."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import ca
from . import crypto_utils
from . import database
from . import logger as log_module
from . import repository
from . import serial


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


# ---------------------------------------------------------------------------
# ca revoke (Sprint 4)
# ---------------------------------------------------------------------------

def cmd_ca_revoke(args) -> int:
    log = log_module.setup_logging(getattr(args, "log_file", None))
    from . import revocation
    try:
        if not args.force:
            ans = input(f"Are you sure you want to revoke {args.serial}? [y/N]: ")
            if ans.lower() != 'y':
                print("Aborted.")
                return 0
        revocation.revoke(args.db_path, args.serial, args.reason, log_file=args.log_file)
        print(f"Revoked {args.serial}")
        return 0
    except Exception as e:
        log.error("Revocation failed: %s", e)
        print(f"Error: {e}", file=sys.stderr)
        return 1


# ---------------------------------------------------------------------------
# ca gen-crl (Sprint 4)
# ---------------------------------------------------------------------------

def cmd_ca_gen_crl(args) -> int:
    log = log_module.setup_logging(getattr(args, "log_file", None))
    from . import crl
    
    parser = getattr(args, "_parser", argparse.ArgumentParser())
    _validate_file_exists(parser, args.ca_cert, "--ca-cert")
    _validate_file_exists(parser, args.ca_key, "--ca-key")
    _validate_passphrase_file(parser, args.ca_pass_file, "--ca-pass-file")

    try:
        ca_pass = crypto_utils.load_passphrase(args.ca_pass_file)
    except Exception as e:
        log.error("Cannot read passphrase file: %s", e)
        print("Error: could not read passphrase file.", file=sys.stderr)
        return 1

    try:
        out_path = crl.generate_crl(
            ca_cert_path=args.ca_cert,
            ca_key_path=args.ca_key,
            ca_passphrase=ca_pass,
            out_dir=args.out_dir,
            db_path=args.db_path,
            next_update_days=args.next_update,
            out_file=getattr(args, "out_file", None),
            log_file=args.log_file
        )
        print(f"CRL generated at {out_path}")
        return 0
    except Exception as e:
        log.error("CRL generation failed: %s", e)
        print(f"Error: {e}", file=sys.stderr)
        return 1


# ---------------------------------------------------------------------------
# ca check-revoked (Sprint 4, CLI-20)
# ---------------------------------------------------------------------------

def cmd_ca_check_revoked(args) -> int:
    log = log_module.setup_logging(getattr(args, "log_file", None))
    from . import revocation
    try:
        status_info = revocation.check_revocation(args.db_path, args.serial)
        print(f"Certificate {status_info['serial']}:")
        print(f"  Status: {status_info['status']}")
        if status_info['status'] == 'revoked':
            print(f"  Reason: {status_info['reason']}")
            print(f"  Date:   {status_info['date']}")
        return 0
    except Exception as e:
        log.error("Check revocation failed: %s", e)
        print(f"Error: {e}", file=sys.stderr)
        return 1



# --- commands missing from original, some might be unimplemented but need parser
def cmd_db_init(args):
    from . import database
    db_path = getattr(args, "db_path", "./pki/micropki.db")
    log_file = getattr(args, "log_file", None)
    log = log_module.setup_logging(log_file)
    try:
        database.init_database(db_path)
        log.info("Database initialized at %s", db_path)
        return 0
    except Exception as e:
        log.error("Database initialization failed: %s", e)
        print(f"Error: {e}", file=sys.stderr)
        return 1

def cmd_ca_list_certs(args):
    from . import repository
    try:
        certs = repository.list_certificates(status=getattr(args, "status", None), db_path=args.db_path)
        if not certs:
            print("No certificates found.", file=sys.stderr)
            return 0
        
        print(f"{'SERIAL':<40} | {'STATUS':<10} | {'NOT AFTER':<20} | {'SUBJECT'}")
        print("-" * 100)
        for cert in certs:
            print(f"{cert['serial_number']:<40} | {cert['status']:<10} | {cert['not_after'][:19]:<20} | {cert['subject']}")
        return 0
    except Exception as e:
        print(f"Error listing certificates: {e}", file=sys.stderr)
        return 1

def cmd_ca_show_cert(args):
    from . import repository
    try:
        serial_number = int(args.serial, 16)
        cert = repository.get_certificate_by_serial(serial_number, db_path=args.db_path)
        if not cert:
            print(f"Certificate not found: {args.serial}", file=sys.stderr)
            return 1
        
        for k, v in cert.items():
            print(f"{k}: {v}")
        return 0
    except ValueError:
        print(f"Invalid serial format: {args.serial}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error showing certificate: {e}", file=sys.stderr)
        return 1

def cmd_repo_serve(args):
    pass # Implemented in repo.py maybe? Will fix below.


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(prog="micropki", description="MicroPKI - minimal PKI")
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    ca_parser = subparsers.add_parser("ca", help="CA operations")
    ca_sub = ca_parser.add_subparsers(dest="ca_command")

    # --- db init ---
    p = subparsers.add_parser("db", help="Database operations")
    db_sub = p.add_subparsers(dest="db_command")
    p_init = db_sub.add_parser("init", help="Initialise the certificate database")
    p_init.set_defaults(_parser=p_init, _run=cmd_db_init)
    p_init.add_argument("--db-path", default="./pki/micropki.db", help="Path to the SQLite database")
    p_init.add_argument("--log-file", default=None)

    # --- ca list-certs ---
    p = ca_sub.add_parser("list-certs", help="List all issued certificates")
    p.set_defaults(_parser=p, _run=cmd_ca_list_certs)
    p.add_argument("--status", choices=["valid", "revoked", "expired"], help="Filter by certificate status")
    p.add_argument("--format", choices=["table", "json", "csv"], default="table", help="Output format")
    p.add_argument("--db-path", default="./pki/micropki.db", help="Path to the SQLite database")
    p.add_argument("--log-file", default=None)

    # --- ca show-cert ---
    p = ca_sub.add_parser("show-cert", help="Show a specific certificate by serial number")
    p.set_defaults(_parser=p, _run=cmd_ca_show_cert)
    p.add_argument("serial", help="Serial number of the certificate (hex)")
    p.add_argument("--db-path", default="./pki/micropki.db", help="Path to the SQLite database")
    p.add_argument("--log-file", default=None)

    # --- repo serve ---
    p = subparsers.add_parser("repo", help="Repository server operations")
    repo_sub = p.add_subparsers(dest="repo_command")
    p_serve = repo_sub.add_parser("serve", help="Start the repository HTTP server")
    p_serve.set_defaults(_parser=p_serve, _run=cmd_repo_serve)
    p_serve.add_argument("--host", default="127.0.0.1", help="Bind address")
    p_serve.add_argument("--port", type=int, default=8080, help="TCP port")
    p_serve.add_argument("--db-path", default="./pki/micropki.db", help="Path to the SQLite database")
    p_serve.add_argument("--cert-dir", default="./pki/certs", help="Directory containing PEM certificates")
    p_serve.add_argument("--log-file", default=None)

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

    # --- ca verify ---
    p = ca_sub.add_parser("verify", help="Verify certificate (self-signed)")
    p.set_defaults(_run=cmd_ca_verify)
    p.add_argument("--cert", required=True)
    p.add_argument("--log-file", default=None)

    # --- ca verify-chain ---
    p = ca_sub.add_parser("verify-chain", help="Validate full certificate chain")
    p.set_defaults(_run=cmd_ca_verify_chain)
    p.add_argument("--leaf", required=True, help="Leaf certificate PEM")
    p.add_argument("--intermediate", action="append", help="Intermediate cert(s) PEM")
    p.add_argument("--root", required=True, help="Root CA cert PEM")
    p.add_argument("--log-file", default=None)

    # --- ca revoke ---
    p = ca_sub.add_parser("revoke", help="Revoke a certificate")
    p.set_defaults(_run=cmd_ca_revoke)
    p.add_argument("serial", help="Serial number of the certificate to revoke (hex)")
    p.add_argument("--reason", default="unspecified", help="Revocation reason code")
    p.add_argument("--db-path", default="./pki/micropki.db", help="Path to DB")
    p.add_argument("--force", action="store_true", help="Skip confirmation")
    p.add_argument("--log-file", default=None)

    # --- ca gen-crl ---
    p = ca_sub.add_parser("gen-crl", help="Generate CRL for a CA")
    p.set_defaults(_parser=p, _run=cmd_ca_gen_crl)
    p.add_argument("--ca-cert", required=True, help="CA cert PEM")
    p.add_argument("--ca-key", required=True, help="CA encrypted key PEM")
    p.add_argument("--ca-pass-file", required=True, help="CA passphrase file")
    p.add_argument("--out-dir", default="./pki")
    p.add_argument("--out-file", default=None, help="Custom output file for CRL")
    p.add_argument("--next-update", type=int, default=7, help="Days until next update")
    p.add_argument("--db-path", default="./pki/micropki.db")
    p.add_argument("--log-file", default=None)

    # --- ca check-revoked ---
    p = ca_sub.add_parser("check-revoked", help="Check revocation status of a certificate")
    p.set_defaults(_run=cmd_ca_check_revoked)
    p.add_argument("serial", help="Serial number of the certificate (hex)")
    p.add_argument("--db-path", default="./pki/micropki.db")
    p.add_argument("--log-file", default=None)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "ca":
        if not getattr(args, "ca_command", None):
            ca_parser.print_help()
            sys.exit(0)
        run = getattr(args, "_run", None)
        if run:
            sys.exit(run(args))
    elif args.command == "db":
        if not getattr(args, "db_command", None):
            parser.print_help()
            sys.exit(0)
        run = getattr(args, "_run", None)
        if run:
            sys.exit(run(args))
    elif args.command == "repo":
        if not getattr(args, "repo_command", None):
            parser.print_help()
            sys.exit(0)
        run = getattr(args, "_run", None)
        if run:
            # Need to call repo logic instead of empty function
            import uvicorn
            from .repo import init_server, app
            init_server(log_file=args.log_file, cert_dir=args.cert_dir)
            sys.exit(uvicorn.run(app, host=args.host, port=args.port, log_level="info"))

    sys.exit(0)


if __name__ == "__main__":
    main()
