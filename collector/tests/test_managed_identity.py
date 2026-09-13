"""Managed Collector identity regression tests."""

from __future__ import annotations

import json
from pathlib import Path
import ssl
import tempfile
import unittest
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtendedKeyUsageOID

from collector_service import managed_identity


class ManagedIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "identity.json"
        self.store = managed_identity.ManagedIdentityStore(self.path)
        self.hostname = "606197c3-cez-pnd-collector"
        self.patches = (
            mock.patch.object(managed_identity, "atomic_write_private", side_effect=lambda path, content, **_: path.write_bytes(content)),
            mock.patch.object(managed_identity, "read_private_file", side_effect=lambda path, **_: path.read_bytes()),
        )
        for patcher in self.patches:
            patcher.start()

    def tearDown(self) -> None:
        for patcher in reversed(self.patches):
            patcher.stop()
        self.temporary.cleanup()

    def test_first_generation_and_second_start_load_same_identity(self) -> None:
        first, created = self.store.load_or_create(self.hostname)
        second, created_again = self.store.load_or_create(self.hostname)
        self.assertTrue(created)
        self.assertFalse(created_again)
        self.assertEqual(first, second)
        self.assertRegex(first.meter_id, r"^mtr_[a-f0-9]{32}$")

        ca = x509.load_pem_x509_certificate(first.ca_certificate_pem.encode())
        leaf = x509.load_pem_x509_certificate(first.server_certificate_pem.encode())
        self.assertEqual(leaf.issuer, ca.subject)
        san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        self.assertEqual(san.get_values_for_type(x509.DNSName), [self.hostname])
        self.assertNotIn("*", first.server_certificate_pem)
        ca_key = serialization.load_pem_private_key(first.ca_private_key_pem.encode(), None)
        self.assertEqual(ca_key.public_key().public_numbers(), ca.public_key().public_numbers())
        self.assertTrue(ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
        self.assertFalse(leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
        self.assertEqual(
            list(leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value),
            [ExtendedKeyUsageOID.SERVER_AUTH],
        )

    def test_generated_identity_passes_strict_tls_and_rejects_wrong_hostname(self) -> None:
        identity, _ = self.store.load_or_create(self.hostname)
        self._strict_tls_handshake(identity, self.hostname)
        with self.assertRaises(ssl.SSLCertVerificationError):
            self._strict_tls_handshake(identity, "wrong-cez-pnd-collector")

    def test_secret_private_keys_are_excluded_from_repr(self) -> None:
        identity, _ = self.store.load_or_create(self.hostname)
        rendered = repr(identity)
        self.assertNotIn(identity.ca_private_key_pem, rendered)
        self.assertNotIn(identity.server_private_key_pem, rendered)

    def test_corrupt_or_partial_identity_fails_without_replacement(self) -> None:
        self.path.write_text('{"schema_version":1}', encoding="utf-8")
        before = self.path.read_bytes()
        with self.assertRaisesRegex(ValueError, "managed_identity_invalid"):
            self.store.load_or_create(self.hostname)
        self.assertEqual(self.path.read_bytes(), before)

    def test_interrupted_generation_artifact_prevents_new_ca(self) -> None:
        stale = self.path.parent / f".{self.path.name}.{'a' * 32}.tmp"
        stale.write_bytes(b"partial-private-material")
        with mock.patch.object(managed_identity, "_generate_identity") as generate:
            with self.assertRaisesRegex(ValueError, "managed_identity_invalid"):
                self.store.load_or_create(self.hostname)
        generate.assert_not_called()

    def test_malformed_certificate_key_mismatch_and_extra_san_fail_closed(self) -> None:
        identity, _ = self.store.load_or_create(self.hostname)
        malformed = managed_identity.ManagedIdentity(
            identity.meter_id,
            identity.hostname,
            "not a certificate",
            identity.ca_private_key_pem,
            identity.server_certificate_pem,
            identity.server_private_key_pem,
        )
        with self.assertRaises(ValueError):
            managed_identity._validate_identity(malformed, self.hostname)
        other = managed_identity._generate_identity(self.hostname)
        mismatch = managed_identity.ManagedIdentity(
            identity.meter_id,
            identity.hostname,
            identity.ca_certificate_pem,
            identity.ca_private_key_pem,
            identity.server_certificate_pem,
            other.server_private_key_pem,
        )
        with self.assertRaises(ValueError):
            managed_identity._validate_identity(mismatch, self.hostname)
        ca_key = serialization.load_pem_private_key(
            identity.ca_private_key_pem.encode("ascii"), None
        )
        leaf = x509.load_pem_x509_certificate(
            identity.server_certificate_pem.encode("ascii")
        )
        builder = (
            x509.CertificateBuilder()
            .subject_name(leaf.subject)
            .issuer_name(leaf.issuer)
            .public_key(leaf.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(leaf.not_valid_before_utc)
            .not_valid_after(leaf.not_valid_after_utc)
        )
        for extension in leaf.extensions:
            if not isinstance(extension.value, x509.SubjectAlternativeName):
                builder = builder.add_extension(extension.value, extension.critical)
        extra_san_certificate = builder.add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(self.hostname), x509.DNSName("extra-cez-pnd-collector")]
            ),
            critical=True,
        ).sign(ca_key, hashes.SHA256())
        extra_san = managed_identity.ManagedIdentity(
            identity.meter_id,
            identity.hostname,
            identity.ca_certificate_pem,
            identity.ca_private_key_pem,
            extra_san_certificate.public_bytes(serialization.Encoding.PEM).decode("ascii"),
            identity.server_private_key_pem,
        )
        with self.assertRaises(ValueError):
            managed_identity._validate_identity(extra_san, self.hostname)

    def test_hostname_is_derived_from_supervisor_slug_and_strict(self) -> None:
        self.assertEqual(
            managed_identity.hostname_from_supervisor_slug("606197c3_cez_pnd_collector"),
            self.hostname,
        )
        for invalid in ("CEZ_PND", "../cez_pnd_collector", "unrelated_app"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                managed_identity.hostname_from_supervisor_slug(invalid)

    def test_wrong_hostname_and_symlink_fail_closed(self) -> None:
        self.store.load_or_create(self.hostname)
        with self.assertRaisesRegex(ValueError, "managed_identity_invalid"):
            self.store.load("local-cez-pnd-collector")
        link = self.path.with_name("link.json")
        try:
            link.symlink_to(self.path)
        except OSError:
            self.skipTest("symlinks unavailable")
        with self.assertRaises(ValueError):
            managed_identity.ManagedIdentityStore(link).load_or_create(self.hostname)

    def _strict_tls_handshake(
        self, identity: managed_identity.ManagedIdentity, hostname: str
    ) -> None:
        certificate = Path(self.temporary.name) / "server.crt"
        private_key = Path(self.temporary.name) / "server.key"
        certificate.write_text(identity.server_certificate_pem, encoding="ascii")
        private_key.write_text(identity.server_private_key_pem, encoding="ascii")
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(certificate, private_key)
        client_context = ssl.create_default_context(cadata=identity.ca_certificate_pem)
        client_context.verify_mode = ssl.CERT_REQUIRED
        client_context.check_hostname = True
        if hasattr(ssl, "VERIFY_X509_STRICT"):
            client_context.verify_flags |= ssl.VERIFY_X509_STRICT
        client_in, client_out = ssl.MemoryBIO(), ssl.MemoryBIO()
        server_in, server_out = ssl.MemoryBIO(), ssl.MemoryBIO()
        client = client_context.wrap_bio(
            client_in, client_out, server_hostname=hostname
        )
        server = server_context.wrap_bio(server_in, server_out, server_side=True)
        client_done = server_done = False
        for _ in range(20):
            if not client_done:
                try:
                    client.do_handshake()
                    client_done = True
                except ssl.SSLWantReadError:
                    pass
            outgoing = client_out.read()
            if outgoing:
                server_in.write(outgoing)
            if not server_done:
                try:
                    server.do_handshake()
                    server_done = True
                except ssl.SSLWantReadError:
                    pass
            outgoing = server_out.read()
            if outgoing:
                client_in.write(outgoing)
            if client_done and server_done:
                return
        self.fail("TLS handshake did not complete")


if __name__ == "__main__":
    unittest.main()
