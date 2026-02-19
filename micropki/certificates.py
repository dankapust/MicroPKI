"""X.509 certificate building: self-signed Root CA, extensions (BC, KU, SKI, AKI)."""

import os
from datetime import datetime, timedelta, timezone
from typing import Union

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID


def parse_subject_dn(dn_string: str) -> x509.Name:
    """
    Parse DN from slash or comma notation into x509.Name.
    E.g. /CN=My Root CA or CN=My Root CA,O=Demo,C=US.
    """
    s = (dn_string or "").strip()
    if not s:
        raise ValueError("Subject DN is empty")

    # Normalize: replace / with , and split by ,
    normalized = s.replace("/", ",").strip(",")
    parts = [p.strip() for p in normalized.split(",") if p.strip()]
    if not parts:
        raise ValueError("Subject DN has no components")

    attrs = []
    for part in parts:
        if "=" not in part:
            raise ValueError(f"Invalid DN component (missing =): {part}")
        key, _, value = part.partition("=")
        key = key.strip().upper()
        value = value.strip()
        if not key or not value:
            raise ValueError(f"Invalid DN component: {part}")

        oid_map = {
            "C": NameOID.COUNTRY_NAME,
            "O": NameOID.ORGANIZATION_NAME,
            "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
            "CN": NameOID.COMMON_NAME,
            "L": NameOID.LOCALITY_NAME,
            "ST": NameOID.STATE_OR_PROVINCE_NAME,
            "STREET": NameOID.STREET_ADDRESS,
            "DC": NameOID.DOMAIN_COMPONENT,
        }
        oid = oid_map.get(key)
        if oid is None:
            raise ValueError(f"Unsupported DN attribute: {key}")
        attrs.append(x509.NameAttribute(oid, value))

    return x509.Name(attrs)


def subject_key_identifier_from_public_key(public_key) -> x509.SubjectKeyIdentifier:
    """SKI per RFC 5280 s4.2.1.2: SHA-1 of subjectPublicKey BIT STRING value."""
    return x509.SubjectKeyIdentifier.from_public_key(public_key)


def build_self_signed_root_ca(
    subject_dn: str,
    private_key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey],
    validity_days: int,
    key_type: str,
    key_size: int,
) -> x509.Certificate:
    """
    Build X.509 v3 self-signed Root CA certificate.
    - Serial: positive integer from CSPRNG (20+ bits entropy).
    - Subject = Issuer.
    - BasicConstraints CA=TRUE (critical), no path length.
    - KeyUsage keyCertSign, cRLSign (critical).
    - SKI and AKI (AKI = SKI for self-signed).
    - RSA -> sha256WithRSAEncryption, ECC P-384 -> ecdsa-with-SHA384.
    """
    name = parse_subject_dn(subject_dn)
    public_key = private_key.public_key()

    # Serial: at least 20 bits randomness; X.509 allows max 159 bits (cryptography library limit)
    serial_bytes = os.urandom(19)
    serial = int.from_bytes(serial_bytes, "big")
    if serial <= 0:
        serial = 1

    not_before = datetime.now(timezone.utc)
    not_after = not_before + timedelta(days=validity_days)

    ski = subject_key_identifier_from_public_key(public_key)
    aki = x509.AuthorityKeyIdentifier(
        key_identifier=ski.digest,
        authority_cert_issuer=None,
        authority_cert_serial_number=None,
    )

    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(public_key)
        .serial_number(serial)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(ski, critical=False)
        .add_extension(aki, critical=False)
    )

    if isinstance(private_key, rsa.RSAPrivateKey):
        algo = hashes.SHA256()
    else:
        algo = hashes.SHA384()

    cert = builder.sign(private_key=private_key, algorithm=algo)
    return cert
