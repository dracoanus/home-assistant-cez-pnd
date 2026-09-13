"""Persistent Collector-owned TLS identity generated after privilege drop."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
import secrets

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from .api import METER_ID_PATTERN
from .security_files import atomic_write_private, read_private_file


IDENTITY_DIRECTORY = Path("/data/cez-pnd-identity")
IDENTITY_FILE = IDENTITY_DIRECTORY / "identity.json"
IDENTITY_SCHEMA_VERSION = 1
MAX_IDENTITY_BYTES = 64 * 1024
HOSTNAME_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$")


@dataclass(frozen=True)
class ManagedIdentity:
    meter_id: str
    hostname: str
    ca_certificate_pem: str
    ca_private_key_pem: str = field(repr=False)
    server_certificate_pem: str
    server_private_key_pem: str = field(repr=False)


class ManagedIdentityStore:
    """Generate once and strictly validate one atomic managed identity."""

    def __init__(self, path: Path = IDENTITY_FILE) -> None:
        self.path = path

    def load_or_create(self, hostname: str) -> tuple[ManagedIdentity, bool]:
        hostname = validate_internal_hostname(hostname)
        if self.path.is_symlink() or _interrupted_generation_exists(self.path):
            raise ValueError("managed_identity_invalid")
        if self.path.exists():
            return self.load(hostname), False
        identity = _generate_identity(hostname)
        atomic_write_private(
            self.path,
            _encode_identity(identity),
            maximum_bytes=MAX_IDENTITY_BYTES,
        )
        return self.load(hostname), True

    def load(self, hostname: str) -> ManagedIdentity:
        hostname = validate_internal_hostname(hostname)
        try:
            raw = json.loads(
                read_private_file(self.path, maximum_bytes=MAX_IDENTITY_BYTES).decode(
                    "utf-8"
                )
            )
            identity = _identity_from_mapping(raw)
            _validate_identity(identity, hostname)
            return identity
        except (
            OSError,
            UnicodeError,
            ValueError,
            TypeError,
            json.JSONDecodeError,
            InvalidSignature,
            UnsupportedAlgorithm,
            x509.ExtensionNotFound,
        ) as error:
            raise ValueError("managed_identity_invalid") from error


def validate_internal_hostname(hostname: str) -> str:
    if (
        not isinstance(hostname, str)
        or len(hostname) > 253
        or not HOSTNAME_PATTERN.fullmatch(hostname)
        or not hostname.endswith("-cez-pnd-collector")
    ):
        raise ValueError("managed_identity_hostname_invalid")
    return hostname


def hostname_from_supervisor_slug(slug: str) -> str:
    if not isinstance(slug, str) or not re.fullmatch(r"[a-z0-9_]{1,128}", slug):
        raise ValueError("managed_identity_hostname_invalid")
    return validate_internal_hostname(slug.replace("_", "-"))


def _generate_identity(hostname: str) -> ManagedIdentity:
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_subject_key_identifier = x509.SubjectKeyIdentifier.from_public_key(
        ca_key.public_key()
    )
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CEZ PND Collector local CA")])
    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(ca_subject_key_identifier, critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                ca_subject_key_identifier
            ),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    server_key = ec.generate_private_key(ec.SECP256R1())
    server_subject_key_identifier = x509.SubjectKeyIdentifier.from_public_key(
        server_key.public_key()
    )
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    server_certificate = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_certificate.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=397))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(server_subject_key_identifier, critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                ca_subject_key_identifier
            ),
            critical=False,
        )
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=True)
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, False, False, False, False),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return ManagedIdentity(
        meter_id="mtr_" + secrets.token_hex(16),
        hostname=hostname,
        ca_certificate_pem=ca_certificate.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        ca_private_key_pem=_private_pem(ca_key),
        server_certificate_pem=server_certificate.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        server_private_key_pem=_private_pem(server_key),
    )


def _private_pem(key: ec.EllipticCurvePrivateKey) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")


def _encode_identity(identity: ManagedIdentity) -> bytes:
    return json.dumps(
        {
            "schema_version": IDENTITY_SCHEMA_VERSION,
            "meter_id": identity.meter_id,
            "hostname": identity.hostname,
            "ca_certificate_pem": identity.ca_certificate_pem,
            "ca_private_key_pem": identity.ca_private_key_pem,
            "server_certificate_pem": identity.server_certificate_pem,
            "server_private_key_pem": identity.server_private_key_pem,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _identity_from_mapping(raw: object) -> ManagedIdentity:
    expected = {
        "schema_version", "meter_id", "hostname", "ca_certificate_pem",
        "ca_private_key_pem", "server_certificate_pem", "server_private_key_pem",
    }
    if not isinstance(raw, dict) or set(raw) != expected or raw["schema_version"] != 1:
        raise ValueError("invalid managed identity schema")
    values = [raw[key] for key in expected - {"schema_version"}]
    if not all(isinstance(value, str) and 0 < len(value) <= 16 * 1024 for value in values):
        raise ValueError("invalid managed identity fields")
    return ManagedIdentity(
        raw["meter_id"], raw["hostname"], raw["ca_certificate_pem"],
        raw["ca_private_key_pem"], raw["server_certificate_pem"], raw["server_private_key_pem"],
    )


def _validate_identity(identity: ManagedIdentity, hostname: str) -> None:
    if not METER_ID_PATTERN.fullmatch(identity.meter_id) or identity.hostname != hostname:
        raise ValueError("managed identity mismatch")
    ca_cert = x509.load_pem_x509_certificate(identity.ca_certificate_pem.encode("ascii"))
    ca_key = serialization.load_pem_private_key(identity.ca_private_key_pem.encode("ascii"), password=None)
    server_cert = x509.load_pem_x509_certificate(identity.server_certificate_pem.encode("ascii"))
    server_key = serialization.load_pem_private_key(identity.server_private_key_pem.encode("ascii"), password=None)
    ca_public_key = ca_cert.public_key()
    server_public_key = server_cert.public_key()
    if not all(
        isinstance(key, ec.EllipticCurvePrivateKey)
        for key in (ca_key, server_key)
    ) or not all(
        isinstance(key, ec.EllipticCurvePublicKey)
        for key in (ca_public_key, server_public_key)
    ):
        raise ValueError("invalid key type")
    if not all(
        isinstance(key.curve, ec.SECP256R1)
        for key in (ca_key, server_key, ca_public_key, server_public_key)
    ):
        raise ValueError("invalid key curve")
    if ca_key.public_key().public_numbers() != ca_public_key.public_numbers():
        raise ValueError("CA key mismatch")
    if server_key.public_key().public_numbers() != server_public_key.public_numbers():
        raise ValueError("server key mismatch")
    ca_constraints = ca_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    leaf_constraints = server_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    ca_usage = ca_cert.extensions.get_extension_for_class(x509.KeyUsage).value
    leaf_usage = server_cert.extensions.get_extension_for_class(x509.KeyUsage).value
    leaf_eku = server_cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    if (
        ca_cert.subject != ca_cert.issuer
        or ca_constraints.ca is not True
        or ca_constraints.path_length != 0
        or not ca_usage.key_cert_sign
        or not ca_usage.crl_sign
    ):
        raise ValueError("invalid CA certificate")
    if (
        leaf_constraints.ca is not False
        or not leaf_usage.digital_signature
        or leaf_usage.key_cert_sign
        or leaf_usage.crl_sign
        or list(leaf_eku) != [x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]
        or server_cert.issuer != ca_cert.subject
    ):
        raise ValueError("invalid server issuer")
    ca_public_key.verify(
        ca_cert.signature,
        ca_cert.tbs_certificate_bytes,
        ec.ECDSA(ca_cert.signature_hash_algorithm),
    )
    ca_public_key.verify(
        server_cert.signature,
        server_cert.tbs_certificate_bytes,
        ec.ECDSA(server_cert.signature_hash_algorithm),
    )
    ca_ski = ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    ca_aki = ca_cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
    leaf_aki = server_cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
    server_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    if ca_aki.key_identifier != ca_ski.digest or leaf_aki.key_identifier != ca_ski.digest:
        raise ValueError("invalid authority key identifier")
    san = server_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    if list(san) != [x509.DNSName(hostname)]:
        raise ValueError("invalid server SAN")
    now = datetime.now(timezone.utc)
    if (
        ca_cert.not_valid_before_utc > now
        or server_cert.not_valid_before_utc > now
        or ca_cert.not_valid_after_utc <= now
        or server_cert.not_valid_after_utc <= now
    ):
        raise ValueError("expired managed identity")


def _interrupted_generation_exists(path: Path) -> bool:
    """Retain and reject evidence of an interrupted atomic identity write."""

    prefix = f".{path.name}."
    try:
        return any(
            candidate.name.startswith(prefix) and candidate.name.endswith(".tmp")
            for candidate in path.parent.iterdir()
        )
    except FileNotFoundError:
        return False
