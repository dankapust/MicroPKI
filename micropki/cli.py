"""CLI: micropki ca init, ca verify; input validation and secure passphrase handling."""

import argparse
import sys
from pathlib import Path

from . import ca
from . import crypto_utils
from . import logger as log_module


def _validate_ca_init_args(parser: argparse.ArgumentParser, args) -> None:
    """Validate ca init arguments; on failure log/print error and exit non-zero."""
    log = log_module.setup_logging(getattr(args, "log_file", None))

    if not (getattr(args, "subject", None) or "").strip():
        log.error("Validation failed: --subject is required and must be non-empty")
        parser.error("--subject is required and must be a non-empty string")

    key_type = getattr(args, "key_type", "rsa").lower()
    if key_type not in ("rsa", "ecc"):
        log.error("Validation failed: --key-type must be 'rsa' or 'ecc'")
        parser.error("--key-type must be 'rsa' or 'ecc'")

    key_size = getattr(args, "key_size", None)
    if key_type == "rsa":
        if key_size != 4096:
            log.error("Validation failed: --key-size must be 4096 for RSA")
            parser.error("--key-size must be 4096 for RSA")
    else:
        if key_size != 384:
            log.error("Validation failed: --key-size must be 384 for ECC")
            parser.error("--key-size must be 384 for ECC")

    pass_file = getattr(args, "passphrase_file", None)
    if not pass_file:
        log.error("Validation failed: --passphrase-file is required")
        parser.error("--passphrase-file is required")
    p = Path(pass_file)
    if not p.exists():
        log.error("Validation failed: passphrase file does not exist: %s", pass_file)
        parser.error(f"--passphrase-file must exist and be readable: {pass_file}")
    if not p.is_file():
        log.error("Validation failed: passphrase path is not a file: %s", pass_file)
        parser.error(f"--passphrase-file is not a file: {pass_file}")
    try:
        p.read_bytes()
    except OSError as e:
        log.error("Validation failed: cannot read passphrase file: %s", e)
        parser.error(f"Cannot read --passphrase-file: {pass_file}")

    out_dir = getattr(args, "out_dir", "./pki") or "./pki"
    out = Path(out_dir)
    if out.exists() and not out.is_dir():
        log.error("Validation failed: --out-dir exists and is not a directory: %s", out_dir)
        parser.error(f"--out-dir must be a directory: {out_dir}")
    try:
        out.mkdir(parents=True, exist_ok=True)
        # Check writable
        test = out / ".micropki_write_test"
        test.write_text("")
        test.unlink()
    except OSError as e:
        log.error("Validation failed: --out-dir is not writable: %s", e)
        parser.error(f"--out-dir must be writable: {out_dir}")

    validity = getattr(args, "validity_days", 3650)
    if not isinstance(validity, int) or validity <= 0:
        log.error("Validation failed: --validity-days must be a positive integer")
        parser.error("--validity-days must be a positive integer")

    # Optional: DN syntax
    try:
        from . import certificates
        certificates.parse_subject_dn(args.subject)
    except ValueError as e:
        log.error("Validation failed: invalid DN syntax: %s", e)
        parser.error(f"Invalid --subject DN: {e}")


def cmd_ca_init(args) -> int:
    """Run ca init: validate, load passphrase securely, run init_root_ca."""
    parser = getattr(args, "_parser", None)
    _validate_ca_init_args(parser or argparse.ArgumentParser(), args)

    try:
        passphrase = crypto_utils.load_passphrase(args.passphrase_file)
    except (FileNotFoundError, ValueError) as e:
        log = log_module.setup_logging(getattr(args, "log_file", None))
        log.error("Cannot read passphrase file: %s", e)
        # Do not echo passphrase or file content
        print("Error: could not read passphrase file.", file=sys.stderr)
        return 1

    try:
        ca.init_root_ca(
            subject=args.subject.strip(),
            key_type=args.key_type.lower(),
            key_size=args.key_size,
            passphrase=passphrase,
            out_dir=args.out_dir or "./pki",
            validity_days=args.validity_days,
            log_file=args.log_file,
            force=getattr(args, "force", False),
        )
    except FileExistsError as e:
        log = log_module.setup_logging(getattr(args, "log_file", None))
        log.error("%s", e)
        print(str(e), file=sys.stderr)
        return 1
    except Exception as e:
        log = log_module.setup_logging(getattr(args, "log_file", None))
        log.exception("CA init failed")
        print(f"Error: {e}", file=sys.stderr)
        return 1
    return 0


def cmd_ca_verify(args) -> int:
    """Verify certificate (self-signed) with micropki ca verify --cert <path>."""
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
        log = log_module.setup_logging(getattr(args, "log_file", None))
        log.error("Verification failed: %s", e)
        print(f"Verification failed: {e}", file=sys.stderr)
        return 1


def main() -> None:
    parser = argparse.ArgumentParser(prog="micropki", description="MicroPKI - minimal PKI")
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # ca
    ca_parser = subparsers.add_parser("ca", help="CA operations")
    ca_sub = ca_parser.add_subparsers(dest="ca_command")

    # ca init
    init_p = ca_sub.add_parser("init", help="Create self-signed Root CA")
    init_p.set_defaults(_parser=init_p, _run=cmd_ca_init)
    init_p.add_argument("--subject", required=True, help="Distinguished Name (e.g. /CN=My Root CA)")
    init_p.add_argument("--key-type", default="rsa", choices=["rsa", "ecc"], help="Key type (default: rsa)")
    init_p.add_argument("--key-size", type=int, default=4096, help="RSA 4096 or ECC 384")
    init_p.add_argument("--passphrase-file", required=True, help="Path to file with passphrase")
    init_p.add_argument("--out-dir", default="./pki", help="Output directory (default: ./pki)")
    init_p.add_argument("--validity-days", type=int, default=3650, help="Validity in days (default: 3650)")
    init_p.add_argument("--log-file", default=None, help="Log file (default: stderr)")
    init_p.add_argument("--force", action="store_true", help="Overwrite existing key/cert files")

    # ca verify
    verify_p = ca_sub.add_parser("verify", help="Verify certificate (self-signed)")
    verify_p.set_defaults(_run=cmd_ca_verify)
    verify_p.add_argument("--cert", required=True, help="Path to certificate PEM")
    verify_p.add_argument("--log-file", default=None, help="Log file (default: stderr)")

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

    sys.exit(0)


if __name__ == "__main__":
    main()
