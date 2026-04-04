"""CLI: ca/db/repo commands for MicroPKI."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import ca
from . import crl as crl_module
from . import database
from . import crypto_utils
from . import logger as log_module
from . import repository
from . import revocation as rev_module


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


def cmd_ca_revoke(args) -> int:
    parser = getattr(args, "_parser", argparse.ArgumentParser())
    log = log_module.setup_logging(getattr(args, "log_file", None))
    serial = (args.serial or "").strip()
    try:
        int(serial, 16)
    except ValueError:
        parser.error("serial must be a hexadecimal string")

    crl_opt = getattr(args, "crl", None)
    if crl_opt is not None and not getattr(args, "ca_pass_file", None):
        parser.error("--ca-pass-file is required when --crl is used")

    try:
        database.init_db(args.db_path)
    except Exception as e:
        log.error("Database init failed: %s", e)
        print(f"Error: {e}", file=sys.stderr)
        return 1

    try:
        if not rev_module.confirm_or_abort(
            f"Revoke certificate with serial {serial.upper()}?",
            force=args.force,
        ):
            print("Revocation cancelled.", file=sys.stderr)
            return 1
    except EOFError:
        print("Error: not a TTY; use --force to revoke without confirmation.", file=sys.stderr)
        return 1

    try:
        outcome = rev_module.revoke_by_serial(args.db_path, serial, args.reason, logger=log)
    except ValueError as e:
        log.error("%s", e)
        print(f"Error: {e}", file=sys.stderr)
        return 2

    if outcome == "not_found":
        print("Error: certificate not found", file=sys.stderr)
        return 1
    if outcome == "already_revoked":
        print("Warning: certificate already revoked", file=sys.stderr)
        return 0

    if crl_opt is not None:
        row = database.get_certificate_by_serial(args.db_path, serial)
        resolved = ca.resolve_local_ca_for_issuer(args.out_dir, row["issuer"])
        if resolved is None:
            log.error("Could not map issuer to local Root/Intermediate CA; CRL not regenerated.")
            print(
                "Note: revocation recorded; run `micropki ca gen-crl` with the correct CA.",
                file=sys.stderr,
            )
            return 0
        ca_cert, key_path, default_name = resolved
        try:
            passphrase = crypto_utils.load_passphrase(args.ca_pass_file)
            ca_key = crypto_utils.load_private_key_encrypted(str(key_path), passphrase)
        except Exception as e:
            log.error("Cannot load CA key for CRL regeneration: %s", e)
            print(f"Error: {e}", file=sys.stderr)
            return 1
        out_path = None if crl_opt == "__AUTO__" else crl_opt
        try:
            crl_module.generate_crl_for_ca(
                args.db_path,
                args.out_dir,
                ca_cert,
                ca_key,
                next_update_days=args.next_update,
                out_file=out_path,
                default_crl_filename=default_name if out_path is None else None,
                logger=log,
            )
        except Exception as e:
            log.error("CRL regeneration after revoke failed: %s", e)
            print(f"Error: {e}", file=sys.stderr)
            return 1

    print(f"Revoked serial {serial.upper()}")
    return 0


def cmd_ca_gen_crl(args) -> int:
    parser = getattr(args, "_parser", argparse.ArgumentParser())
    log = log_module.setup_logging(getattr(args, "log_file", None))
    if args.next_update <= 0:
        parser.error("--next-update must be a positive integer")

    out_p = Path(args.out_dir)
    certs_d = out_p / "certs"
    priv_d = out_p / "private"
    ca_arg = str(args.ca).strip()
    default_name: str | None = None

    if ca_arg.lower() == "root":
        ca_cert_path = certs_d / "ca.cert.pem"
        ca_key_path = priv_d / "ca.key.pem"
        default_name = "root.crl.pem"
    elif ca_arg.lower() == "intermediate":
        ca_cert_path = certs_d / "intermediate.cert.pem"
        ca_key_path = priv_d / "intermediate.key.pem"
        default_name = "intermediate.crl.pem"
    else:
        ca_cert_path = Path(ca_arg)
        if not ca_cert_path.is_file():
            parser.error(f"--ca path not found: {ca_cert_path}")
        if not args.ca_key:
            parser.error("--ca-key is required when --ca is a certificate file path")
        ca_key_path = Path(args.ca_key)
        default_name = f"{ca_cert_path.stem}.crl.pem"

    _validate_file_exists(parser, str(ca_cert_path), "--ca")
    _validate_file_exists(parser, str(ca_key_path), "--ca-key")
    _validate_passphrase_file(parser, args.ca_pass_file, "--ca-pass-file")

    try:
        database.init_db(args.db_path)
        ca_cert = crypto_utils.load_certificate_pem(str(ca_cert_path))
        passphrase = crypto_utils.load_passphrase(args.ca_pass_file)
        ca_key = crypto_utils.load_private_key_encrypted(str(ca_key_path), passphrase)
        path, nrev = crl_module.generate_crl_for_ca(
            args.db_path,
            args.out_dir,
            ca_cert,
            ca_key,
            next_update_days=args.next_update,
            out_file=args.out_file,
            default_crl_filename=default_name,
            logger=log,
        )
        print(f"CRL written: {path} (revoked entries: {nrev})")
        return 0
    except Exception as e:
        log.error("CRL generation failed: %s", e)
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_ca_check_revoked(args) -> int:
    log = log_module.setup_logging(getattr(args, "log_file", None))
    serial = (args.serial or "").strip()
    try:
        int(serial, 16)
    except ValueError:
        print("Error: serial must be hexadecimal", file=sys.stderr)
        return 1
    try:
        database.init_db(args.db_path)
        row = database.get_certificate_by_serial(args.db_path, serial)
    except Exception as e:
        log.error("Database error: %s", e)
        print(f"Error: {e}", file=sys.stderr)
        return 1

    if row is None:
        print("status=not_found")
        return 1

    print(f"status={row['status']}")
    if row["revocation_reason"]:
        print(f"revocation_reason={row['revocation_reason']}")
    if row["revocation_date"]:
        print(f"revocation_date={row['revocation_date']}")

    if getattr(args, "crl_file", None):
        from cryptography import x509

        p = Path(args.crl_file)
        if not p.is_file():
            print(f"Error: CRL file not found: {p}", file=sys.stderr)
            return 1
        try:
            pem_crl = x509.load_pem_x509_crl(p.read_bytes())
            want = int(serial, 16)
            on_crl = any(r.serial_number == want for r in pem_crl)
            print(f"crl_contains_serial={'yes' if on_crl else 'no'}")
        except Exception as e:
            log.error("Failed to parse CRL: %s", e)
            print(f"Error: {e}", file=sys.stderr)
            return 1

    return 0


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
        repository.serve(
            args.host,
            args.port,
            args.db_path,
            args.cert_dir,
            log,
            pki_dir=getattr(args, "pki_dir", None),
        )
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


def main() -> None:
    parser = argparse.ArgumentParser(prog="micropki", description="MicroPKI - minimal PKI")
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    ca_parser = subparsers.add_parser("ca", help="CA operations")
    ca_sub = ca_parser.add_subparsers(dest="ca_command")
    db_parser = subparsers.add_parser("db", help="Database operations")
    db_sub = db_parser.add_subparsers(dest="db_command")
    repo_parser = subparsers.add_parser("repo", help="Repository server operations")
    repo_sub = repo_parser.add_subparsers(dest="repo_command")

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

    p = ca_sub.add_parser("verify", help="Verify certificate (self-signed)")
    p.set_defaults(_run=cmd_ca_verify)
    p.add_argument("--cert", required=True)
    p.add_argument("--log-file", default=None)

    p = ca_sub.add_parser("list-certs", help="List certificates from database")
    p.set_defaults(_run=cmd_ca_list_certs)
    p.add_argument("--db-path", default="./pki/micropki.db")
    p.add_argument("--status", choices=["valid", "revoked", "expired"], default=None)
    p.add_argument("--format", choices=["table", "json", "csv"], default="table")
    p.add_argument("--log-file", default=None)

    p = ca_sub.add_parser("show-cert", help="Show certificate PEM by serial")
    p.set_defaults(_run=cmd_ca_show_cert)
    p.add_argument("serial")
    p.add_argument("--db-path", default="./pki/micropki.db")
    p.add_argument("--log-file", default=None)

    p = ca_sub.add_parser("verify-chain", help="Validate full certificate chain")
    p.set_defaults(_run=cmd_ca_verify_chain)
    p.add_argument("--leaf", required=True, help="Leaf certificate PEM")
    p.add_argument("--intermediate", action="append", help="Intermediate cert(s) PEM")
    p.add_argument("--root", required=True, help="Root CA cert PEM")
    p.add_argument("--log-file", default=None)

    p = ca_sub.add_parser("revoke", help="Revoke certificate by serial (hex)")
    p.set_defaults(_parser=p, _run=cmd_ca_revoke)
    p.add_argument("serial", help="Certificate serial number (hex, case-insensitive)")
    p.add_argument(
        "--reason",
        default="unspecified",
        help="Revocation reason (RFC 5280): unspecified, keyCompromise, cACompromise, "
        "affiliationChanged, superseded, cessationOfOperation, certificateHold, "
        "removeFromCRL, privilegeWithdrawn, aACompromise",
    )
    p.add_argument(
        "--crl",
        nargs="?",
        const="__AUTO__",
        default=None,
        metavar="PATH",
        help="Regenerate CRL after revoke; optional path (default: <out-dir>/crl/<issuer>.crl.pem). "
        "Requires --ca-pass-file.",
    )
    p.add_argument("--next-update", type=int, default=7, help="Days until CRL nextUpdate when using --crl")
    p.add_argument("--force", action="store_true", help="Skip interactive confirmation")
    p.add_argument("--db-path", default="./pki/micropki.db")
    p.add_argument("--out-dir", default="./pki", help="PKI root (private/, certs/, crl/)")
    p.add_argument("--ca-pass-file", default=None, help="Passphrase file for issuing CA key (required with --crl)")
    p.add_argument("--log-file", default=None)

    p = ca_sub.add_parser("gen-crl", help="Generate (re)signed full CRL for a CA")
    p.set_defaults(_parser=p, _run=cmd_ca_gen_crl)
    p.add_argument(
        "--ca",
        required=True,
        help="CA selector: root, intermediate, or path to CA certificate PEM",
    )
    p.add_argument("--ca-key", default=None, help="CA private key PEM (required if --ca is a file path)")
    p.add_argument("--ca-pass-file", required=True, help="Passphrase file for CA private key")
    p.add_argument("--next-update", type=int, default=7, help="Days until CRL nextUpdate")
    p.add_argument("--out-file", default=None, help="Output CRL path (default: <out-dir>/crl/<ca>.crl.pem)")
    p.add_argument("--out-dir", default="./pki")
    p.add_argument("--db-path", default="./pki/micropki.db")
    p.add_argument("--log-file", default=None)

    p = ca_sub.add_parser("check-revoked", help="Show revocation status from DB (optional CRL cross-check)")
    p.set_defaults(_run=cmd_ca_check_revoked)
    p.add_argument("serial", help="Certificate serial (hex)")
    p.add_argument("--db-path", default="./pki/micropki.db")
    p.add_argument("--crl", dest="crl_file", default=None, metavar="PATH", help="Optional PEM CRL to check serial")
    p.add_argument("--log-file", default=None)

    p = db_sub.add_parser("init", help="Initialize SQLite database schema")
    p.set_defaults(_run=cmd_db_init)
    p.add_argument("--db-path", default="./pki/micropki.db")
    p.add_argument("--log-file", default=None)

    p = repo_sub.add_parser("serve", help="Start HTTP repository server")
    p.set_defaults(_run=cmd_repo_serve)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--db-path", default="./pki/micropki.db")
    p.add_argument("--cert-dir", default="./pki/certs")
    p.add_argument(
        "--pki-dir",
        default=None,
        help="PKI root directory (default: parent of --cert-dir; used for crl/ files)",
    )
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
