"""Regression tests for the narrow offline Collector API."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import secrets
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from collector_service.api import CollectorApi, SYNTHETIC_METER_ID, TokenVerifier
from collector_service.security_files import _validate_file_metadata, read_private_file


class CollectorApiTest(unittest.TestCase):
    def setUp(self) -> None:
        self.token = secrets.token_urlsafe(32)
        self.verifier = TokenVerifier(
            hashlib.sha256(self.token.encode("ascii")).hexdigest(),
            SYNTHETIC_METER_ID,
            frozenset({"health:read", "status:read", "measurements:read"}),
        )
        self.api = CollectorApi(self.verifier)
        self.auth = {"Authorization": f"Bearer {self.token}"}

    def test_all_routes_require_authentication(self) -> None:
        targets = (
            "/api/v1/health",
            f"/api/v1/status?meter_id={SYNTHETIC_METER_ID}",
            f"/api/v1/measurements?meter_id={SYNTHETIC_METER_ID}&start=2026-08-01T00:00:00Z&end=2026-08-01T00:30:00Z",
        )
        for target in targets:
            with self.subTest(target=target):
                self.assertEqual(self.api.handle("GET", target, {}).status, 401)
                self.assertEqual(
                    self.api.handle("GET", target, {"Authorization": "Bearer wrong"}).status,
                    401,
                )
                self.assertEqual(
                    self.api.handle(
                        "GET",
                        target,
                        {"Authorization": f"Bearer {self.token[:-1]}!"},
                    ).status,
                    401,
                )

    def test_health_is_minimal(self) -> None:
        response = self.api.handle("GET", "/api/v1/health", self.auth)
        self.assertEqual(response.status, 200)
        self.assertEqual(response.body, {"schema_version": "1.0", "service_status": "ok"})

    def test_status_keeps_freshness_fields_separate(self) -> None:
        response = self.api.handle(
            "GET", f"/api/v1/status?meter_id={SYNTHETIC_METER_ID}", self.auth
        )
        self.assertEqual(response.status, 200)
        self.assertIsNotNone(response.body["data_timestamp"])
        self.assertIsNotNone(response.body["last_attempt"])
        self.assertIsNone(response.body["last_success"])
        self.assertEqual(response.body["completeness"]["state"], "partial")
        self.assertEqual(response.body["source_status"], "synthetic_offline_partial")

    def test_measurements_represent_missing_as_null_never_zero(self) -> None:
        response = self.api.handle(
            "GET",
            f"/api/v1/measurements?meter_id={SYNTHETIC_METER_ID}&start=2026-08-01T00:00:00Z&end=2026-08-01T00:30:00Z",
            self.auth,
        )
        self.assertEqual(response.status, 200)
        missing = [value for value in response.body["values"] if value["quality"] == "missing"]
        self.assertEqual(len(missing), 1)
        self.assertIsNone(missing[0]["value_kwh"])
        self.assertEqual(response.body["completeness"]["missing_count"], 1)
        self.assertEqual(len(response.body["missing"]), 1)

    def test_arbitrary_routes_methods_and_query_fields_are_rejected(self) -> None:
        self.assertEqual(self.api.handle("GET", "/api/v1/browser", self.auth).status, 404)
        self.assertEqual(self.api.handle("POST", "/api/v1/health", self.auth).status, 405)
        self.assertEqual(
            self.api.handle("GET", "/api/v1/health?url=https://example.invalid", self.auth).status,
            400,
        )
        self.assertEqual(
            self.api.handle("GET", "https://example.invalid/api/v1/health", self.auth).status,
            400,
        )

    def test_measurement_pagination_stays_on_the_synthetic_revision(self) -> None:
        target = (
            f"/api/v1/measurements?meter_id={SYNTHETIC_METER_ID}"
            "&start=2026-08-01T00:00:00Z&end=2026-08-01T00:30:00Z&limit=1"
        )
        first = self.api.handle("GET", target, self.auth)
        self.assertEqual(first.status, 200)
        self.assertEqual(len(first.body["values"]), 1)
        self.assertIsNotNone(first.body["next_cursor"])
        second = self.api.handle(
            "GET", f"{target}&cursor={first.body['next_cursor']}", self.auth
        )
        self.assertEqual(second.status, 200)
        self.assertEqual(len(second.body["values"]), 1)
        self.assertIsNone(second.body["next_cursor"])
        self.assertEqual(first.body["dataset_revision"], second.body["dataset_revision"])

    def test_token_never_appears_in_responses(self) -> None:
        for target in ("/api/v1/health", "/api/v1/missing"):
            encoded = json.dumps(self.api.handle("GET", target, self.auth).body)
            self.assertNotIn(self.token, encoded)

    def test_verifier_file_requires_private_uid_2000_regular_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "client.json")
            path.write_text(
                json.dumps(
                    {
                        "schema_version": "1",
                        "token_sha256": self.verifier.token_sha256,
                        "meter_id": SYNTHETIC_METER_ID,
                        "scopes": sorted(self.verifier.scopes),
                    }
                ),
                encoding="utf-8",
            )
            path.chmod(0o600)
            with mock.patch(
                "collector_service.api.read_private_file",
                return_value=path.read_bytes(),
            ):
                loaded = TokenVerifier.from_file(path)
                self.assertEqual(loaded, self.verifier)

    def test_private_file_metadata_fails_closed(self) -> None:
        _validate_file_metadata(
            SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=2000),
            private=True,
        )
        for metadata in (
            SimpleNamespace(st_mode=stat.S_IFREG | 0o640, st_uid=2000),
            SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0),
            SimpleNamespace(st_mode=stat.S_IFLNK | 0o600, st_uid=2000),
        ):
            with self.subTest(metadata=metadata):
                with self.assertRaises(ValueError):
                    _validate_file_metadata(metadata, private=True)

    def test_private_file_read_is_bounded_and_uses_no_follow(self) -> None:
        secure_metadata = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=2000)
        with mock.patch("collector_service.security_files.Path.is_dir", return_value=True), mock.patch(
            "collector_service.security_files.os.O_NOFOLLOW", 0x20000, create=True
        ), mock.patch(
            "collector_service.security_files.os.O_CLOEXEC", 0x80000, create=True
        ), mock.patch("collector_service.security_files.os.open", return_value=7) as opened, mock.patch(
            "collector_service.security_files.os.fstat", return_value=secure_metadata
        ), mock.patch(
            "collector_service.security_files.os.read", side_effect=[b"safe", b""]
        ), mock.patch("collector_service.security_files.os.close") as closed:
            self.assertEqual(read_private_file(Path("/data/auth/client.json"), maximum_bytes=8), b"safe")
            flags = opened.call_args.args[1]
            self.assertTrue(flags & 0x20000)
            closed.assert_called_once_with(7)

        with mock.patch("collector_service.security_files.Path.is_dir", return_value=True), mock.patch(
            "collector_service.security_files.os.O_NOFOLLOW", 0x20000, create=True
        ), mock.patch(
            "collector_service.security_files.os.O_CLOEXEC", 0x80000, create=True
        ), mock.patch("collector_service.security_files.os.open", return_value=8), mock.patch(
            "collector_service.security_files.os.fstat", return_value=secure_metadata
        ), mock.patch(
            "collector_service.security_files.os.read", return_value=b"123456789"
        ), mock.patch("collector_service.security_files.os.close"):
            with self.assertRaises(ValueError):
                read_private_file(Path("/data/auth/client.json"), maximum_bytes=8)


if __name__ == "__main__":
    unittest.main()
