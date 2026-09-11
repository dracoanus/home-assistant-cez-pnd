"""Offline tests for the transactional normalized dataset store."""
from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from pathlib import Path
import sqlite3
import stat
import os
import tempfile
import unittest
from unittest import mock

from collector_service.cez_csv_models import IntervalQuality, IntervalRecord, ParsedPndData, PndChannel
from collector_service.dataset_store import NormalizedDatasetStore


START = datetime(2026, 9, 1, tzinfo=UTC)


def _parsed(channel: PndChannel, values: tuple[tuple[Decimal | None, IntervalQuality], ...]) -> ParsedPndData:
    intervals = tuple(IntervalRecord(channel, START + timedelta(minutes=15 * index),
        START + timedelta(minutes=15 * (index + 1)), value, quality, date(2026, 9, 1))
        for index, (value, quality) in enumerate(values))
    return ParsedPndData(channel, channel.profile_marker, "utf-8", ";", intervals)


class DatasetStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "dataset.sqlite3"
        self.revision_number = 0
        def revision() -> str:
            self.revision_number += 1
            return f"ds_{self.revision_number:032x}"
        self.store = NormalizedDatasetStore(self.path, required_uid=None, revision_factory=revision)
        self.consumption = _parsed(PndChannel.CONSUMPTION, ((Decimal("1.25"), IntervalQuality.VALID), (None, IntervalQuality.MISSING)))
        self.production = _parsed(PndChannel.PRODUCTION, ((None, IntervalQuality.INVALID), (Decimal("0.50"), IntervalQuality.VALID)))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_secure_create_persistence_and_no_sensitive_identifiers(self) -> None:
        self.store.record_attempt(START)
        status = self.store.commit_dataset(self.consumption, self.production, collected_at=START)
        self.assertEqual((status.expected_count, status.valid_count, status.missing_count, status.invalid_count), (4, 2, 1, 1))
        self.assertEqual(status.state, "partial")
        reopened = NormalizedDatasetStore(self.path, required_uid=None)
        self.assertEqual(reopened.read_status(), status)
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        raw = self.path.read_bytes()
        for forbidden in (b"username", b"password", b"cookie", b"ean", b"elm"):
            self.assertNotIn(forbidden, raw.lower())

    def test_idempotent_upsert_and_corrected_value_replaces_row(self) -> None:
        first = self.store.commit_dataset(self.consumption, self.production, collected_at=START)
        second = self.store.commit_dataset(self.consumption, self.production, collected_at=START + timedelta(hours=1))
        self.assertNotEqual(first.revision, second.revision)
        page = self.store.read_measurements("2026-09-01T00:00:00Z", "2026-09-01T01:00:00Z", limit=100)
        self.assertIsNotNone(page)
        self.assertEqual(len(page.rows), 4)
        corrected = _parsed(PndChannel.CONSUMPTION, ((Decimal("1.75"), IntervalQuality.VALID), (None, IntervalQuality.MISSING)))
        third = self.store.commit_dataset(corrected, self.production, collected_at=START + timedelta(hours=2))
        page = self.store.read_measurements("2026-09-01T00:00:00Z", "2026-09-01T01:00:00Z", limit=100)
        row = next(item for item in page.rows if item.channel == "grid_import" and item.interval_start == "2026-09-01T00:00:00Z")
        self.assertEqual(row.value_kwh, "1.75")
        self.assertTrue(all(item.revision == third.revision for item in page.rows))

    def test_transaction_failure_preserves_previous_revision(self) -> None:
        previous = self.store.commit_dataset(self.consumption, self.production, collected_at=START)
        original_connect = self.store._connect
        class FailingConnection:
            def __init__(self, wrapped): self.wrapped = wrapped; self.count = 0
            def __enter__(self): return self
            def __exit__(self, *args): self.wrapped.close()
            def execute(self, sql, parameters=()):
                if "INSERT INTO measurements" in sql:
                    self.count += 1
                    if self.count == 2: raise sqlite3.OperationalError("injected")
                return self.wrapped.execute(sql, parameters)
            def __getattr__(self, name): return getattr(self.wrapped, name)
        with mock.patch.object(self.store, "_connect", side_effect=lambda: FailingConnection(original_connect())):
            with self.assertRaises(sqlite3.OperationalError):
                self.store.commit_dataset(self.consumption, self.production, collected_at=START + timedelta(hours=1))
        self.assertEqual(self.store.read_status().revision, previous.revision)
        self.assertEqual(len(self.store.read_measurements("2026-09-01T00:00:00Z", "2026-09-01T01:00:00Z", limit=100).rows), 4)

    def test_wrong_second_channel_is_rejected_before_publication(self) -> None:
        previous = self.store.commit_dataset(self.consumption, self.production, collected_at=START)
        with self.assertRaises(ValueError):
            self.store.commit_dataset(self.consumption, self.consumption, collected_at=START)
        self.assertEqual(self.store.read_status().revision, previous.revision)


if __name__ == "__main__":
    unittest.main()
