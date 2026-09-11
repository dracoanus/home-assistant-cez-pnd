"""Regression tests for the real normalized Collector API."""
from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import secrets
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from collector_service.api import CollectorApi, SYNTHETIC_METER_ID, TokenVerifier, _encode_cursor
from collector_service.cez_csv_models import IntervalQuality, IntervalRecord, ParsedPndData, PndChannel
from collector_service.dataset_store import NormalizedDatasetStore
from collector_service.security_files import _validate_file_metadata, read_private_file

START = datetime(2026, 8, 1, tzinfo=UTC)


def _profile(channel: PndChannel, count: int = 2) -> ParsedPndData:
    qualities = (IntervalQuality.VALID, IntervalQuality.MISSING, IntervalQuality.INVALID)
    intervals = []
    for index in range(count):
        quality = qualities[index % 3]
        value = Decimal("0.125") if quality is IntervalQuality.VALID else None
        intervals.append(IntervalRecord(channel, START + timedelta(minutes=15 * index),
            START + timedelta(minutes=15 * (index + 1)), value, quality, date(2026, 8, 1)))
    return ParsedPndData(channel, channel.profile_marker, "utf-8", ";", tuple(intervals))


class CollectorApiTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.token = secrets.token_urlsafe(32)
        self.verifier = TokenVerifier(hashlib.sha256(self.token.encode("ascii")).hexdigest(), SYNTHETIC_METER_ID,
            frozenset({"health:read", "status:read", "measurements:read"}))
        self.store = NormalizedDatasetStore(Path(self.temporary.name) / "data.sqlite3", required_uid=None,
            revision_factory=lambda: "ds_" + "a" * 32)
        self.store.record_attempt(START - timedelta(hours=1))
        self.store.commit_dataset(_profile(PndChannel.CONSUMPTION, 3), _profile(PndChannel.PRODUCTION, 3), collected_at=START)
        self.api = CollectorApi(self.verifier, self.store)
        self.auth = {"Authorization": f"Bearer {self.token}"}

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_auth_health_and_meter_isolation(self) -> None:
        targets = ("/api/v1/health", f"/api/v1/status?meter_id={SYNTHETIC_METER_ID}",
            f"/api/v1/measurements?meter_id={SYNTHETIC_METER_ID}&start=2026-08-01T00:00:00Z&end=2026-08-01T01:00:00Z")
        for target in targets:
            self.assertEqual(self.api.handle("GET", target, {}).status, 401)
        self.assertEqual(self.api.handle("GET", "/api/v1/health", self.auth).body,
            {"schema_version": "1.0", "service_status": "ok"})
        other = "mtr_" + "0" * 32
        self.assertEqual(self.api.handle("GET", f"/api/v1/status?meter_id={other}", self.auth).status, 404)

    def test_status_reads_real_persisted_metadata(self) -> None:
        response = self.api.handle("GET", f"/api/v1/status?meter_id={SYNTHETIC_METER_ID}", self.auth)
        self.assertEqual(response.status, 200)
        self.assertEqual(response.body["dataset_revision"], "ds_" + "a" * 32)
        self.assertEqual(response.body["data_timestamp"], "2026-08-01T00:15:00Z")
        self.assertEqual(response.body["last_attempt"], "2026-07-31T23:00:00Z")
        self.assertEqual(response.body["last_success"], "2026-08-01T00:00:00Z")
        self.assertEqual(response.body["source_status"], "partial")
        self.assertEqual(response.body["completeness"], {"state": "partial", "expected_count": 6,
            "valid_count": 2, "missing_count": 2, "invalid_count": 2})

    def test_measurements_map_channels_decimal_missing_and_invalid(self) -> None:
        response = self.api.handle("GET", f"/api/v1/measurements?meter_id={SYNTHETIC_METER_ID}&start=2026-08-01T00:00:00Z&end=2026-08-01T01:00:00Z", self.auth)
        self.assertEqual(response.status, 200)
        values = response.body["values"]
        self.assertEqual({item["channel"] for item in values}, {"grid_import", "grid_export"})
        self.assertTrue(all(isinstance(item["value_kwh"], str) for item in values if item["quality"] == "valid"))
        self.assertTrue(all(item["value_kwh"] is None for item in values if item["quality"] == "missing"))
        self.assertFalse(any(item["quality"] == "invalid" for item in values))
        self.assertEqual(len(response.body["missing"]), 2)
        self.assertEqual(response.body["completeness"]["invalid_count"], 2)
        self.assertEqual(sum(response.body["completeness"][key] for key in ("valid_count", "missing_count", "invalid_count")), response.body["completeness"]["expected_count"])

    def test_keyset_pagination_is_deterministic_and_cursor_is_bound(self) -> None:
        target = f"/api/v1/measurements?meter_id={SYNTHETIC_METER_ID}&start=2026-08-01T00:00:00Z&end=2026-08-01T01:00:00Z&limit=1"
        rows = []
        cursor = None
        revisions = set()
        while True:
            response = self.api.handle("GET", target + (f"&cursor={cursor}" if cursor else ""), self.auth)
            self.assertEqual(response.status, 200)
            revisions.add(response.body["dataset_revision"])
            rows.extend(response.body["values"])
            cursor = response.body["next_cursor"]
            if cursor is None: break
        self.assertEqual(revisions, {"ds_" + "a" * 32})
        self.assertEqual(len(rows), 4)  # two invalid rows are counted but omitted
        first = self.api.handle("GET", target, self.auth).body["next_cursor"]
        wrong_range = target.replace("01:00:00Z", "00:45:00Z") + f"&cursor={first}"
        self.assertEqual(self.api.handle("GET", wrong_range, self.auth).body["error"]["code"], "invalid_cursor")
        tampered = first[:-1] + ("A" if first[-1] != "A" else "B")
        self.assertEqual(self.api.handle("GET", target + f"&cursor={tampered}", self.auth).status, 400)
        wrong_revision = _encode_cursor("ds_" + "b" * 32,
            "2026-08-01T00:00:00Z", "2026-08-01T01:00:00Z",
            "2026-08-01T00:00:00Z", "grid_export")
        self.assertEqual(self.api.handle("GET", target + f"&cursor={wrong_revision}", self.auth).body["error"]["code"], "invalid_cursor")
        nonexistent = _encode_cursor("ds_" + "a" * 32,
            "2026-08-01T00:00:00Z", "2026-08-01T01:00:00Z",
            "2026-08-01T00:07:00Z", "grid_export")
        self.assertEqual(self.api.handle("GET", target + f"&cursor={nonexistent}", self.auth).status, 400)

    def test_more_than_one_thousand_rows_spans_pages_without_duplicates(self) -> None:
        self.store.commit_dataset(_profile(PndChannel.CONSUMPTION, 501),
            _profile(PndChannel.PRODUCTION, 501), collected_at=START)
        target = f"/api/v1/measurements?meter_id={SYNTHETIC_METER_ID}&start=2026-08-01T00:00:00Z&end=2026-08-07T00:00:00Z"
        first = self.api.handle("GET", target, self.auth)
        self.assertEqual(first.status, 200)
        self.assertIsNotNone(first.body["next_cursor"])
        second = self.api.handle("GET", target + f"&cursor={first.body['next_cursor']}", self.auth)
        self.assertEqual(second.status, 200)
        self.assertIsNone(second.body["next_cursor"])
        identities = [(item["interval_start"], item["channel"]) for response in (first, second) for item in response.body["values"]]
        self.assertEqual(len(identities), len(set(identities)))
        self.assertEqual(first.body["dataset_revision"], second.body["dataset_revision"])

    def test_range_and_arbitrary_routes_are_rejected(self) -> None:
        self.assertEqual(self.api.handle("GET", "/api/v1/browser", self.auth).status, 404)
        self.assertEqual(self.api.handle("POST", "/api/v1/health", self.auth).status, 405)
        target = f"/api/v1/measurements?meter_id={SYNTHETIC_METER_ID}&start=2026-01-01T00:00:00Z&end=2026-04-01T00:00:00Z"
        self.assertEqual(self.api.handle("GET", target, self.auth).status, 400)

    def test_token_never_appears_in_responses(self) -> None:
        self.assertNotIn(self.token, json.dumps(self.api.handle("GET", "/api/v1/health", self.auth).body))

    def test_verifier_and_private_file_guards(self) -> None:
        with mock.patch("collector_service.api.read_private_file", return_value=json.dumps({"schema_version": "1", "token_sha256": self.verifier.token_sha256, "meter_id": SYNTHETIC_METER_ID, "scopes": sorted(self.verifier.scopes)}).encode()):
            self.assertEqual(TokenVerifier.from_file(Path("unused")), self.verifier)
        _validate_file_metadata(SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=2000), private=True)
        with self.assertRaises(ValueError):
            _validate_file_metadata(SimpleNamespace(st_mode=stat.S_IFREG | 0o640, st_uid=2000), private=True)
        secure = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=2000)
        with mock.patch("collector_service.security_files.Path.is_dir", return_value=True), mock.patch("collector_service.security_files.os.O_NOFOLLOW", 0x20000, create=True), mock.patch("collector_service.security_files.os.O_CLOEXEC", 0x80000, create=True), mock.patch("collector_service.security_files.os.open", return_value=7), mock.patch("collector_service.security_files.os.fstat", return_value=secure), mock.patch("collector_service.security_files.os.read", side_effect=[b"safe", b""]), mock.patch("collector_service.security_files.os.close"):
            self.assertEqual(read_private_file(Path("/data/auth/client.json"), maximum_bytes=8), b"safe")


if __name__ == "__main__": unittest.main()
