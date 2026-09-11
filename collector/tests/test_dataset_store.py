"""Offline tests for the transactional normalized dataset store."""
from __future__ import annotations

from contextlib import closing
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


def _parsed(channel: PndChannel, values: tuple[tuple[Decimal | None, IntervalQuality], ...], *, start: datetime = START) -> ParsedPndData:
    intervals = tuple(IntervalRecord(channel, start + timedelta(minutes=15 * index),
        start + timedelta(minutes=15 * (index + 1)), value, quality, start.date())
        for index, (value, quality) in enumerate(values))
    return ParsedPndData(channel, channel.profile_marker, "utf-8", ";", intervals)


class DatasetStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name) / "cez-pnd-dataset"
        self.directory.mkdir(mode=0o700)
        self.path = self.directory / "cez-pnd.sqlite3"
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
            self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)
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

    def test_backfill_checkpoint_initializes_advances_and_resumes(self) -> None:
        state = self.store.prepare_sync_state(
            date(2025, 1, 1), date(2026, 9, 10)
        )
        self.assertEqual(state.requested_history_start, date(2025, 1, 1))
        self.assertEqual(state.backfill_next_day, date(2025, 1, 1))
        self.assertFalse(state.backfill_complete)
        advanced = self.store.advance_sync_state(
            date(2025, 1, 1), date(2025, 2, 1), date(2026, 9, 10)
        )
        self.assertEqual(advanced.backfill_next_day, date(2025, 2, 1))
        reopened = NormalizedDatasetStore(self.path, required_uid=None)
        self.assertEqual(reopened.read_sync_state(), advanced)

    def test_checkpoint_never_advances_on_stale_or_failed_chunk(self) -> None:
        initial = self.store.prepare_sync_state(
            date(2025, 1, 1), date(2026, 9, 10)
        )
        with self.assertRaises(ValueError):
            self.store.advance_sync_state(
                date(2025, 2, 1), date(2025, 3, 1), date(2026, 9, 10)
            )
        self.assertEqual(self.store.read_sync_state(), initial)

    def test_earlier_history_start_extends_backwards(self) -> None:
        self.store.prepare_sync_state(date(2025, 3, 1), date(2026, 9, 10))
        self.store.advance_sync_state(
            date(2025, 3, 1), date(2025, 4, 1), date(2026, 9, 10)
        )
        earlier = self.store.prepare_sync_state(
            date(2025, 1, 1), date(2026, 9, 10)
        )
        self.assertEqual(earlier.requested_history_start, date(2025, 1, 1))
        self.assertEqual(earlier.backfill_next_day, date(2025, 1, 1))

    def test_later_history_start_rebases_failed_checkpoint(self) -> None:
        self.store.prepare_sync_state(date(2025, 1, 1), date(2026, 9, 10))
        rebased = self.store.prepare_sync_state(
            date(2025, 9, 1), date(2026, 9, 10)
        )
        self.assertEqual(rebased.requested_history_start, date(2025, 9, 1))
        self.assertEqual(rebased.backfill_next_day, date(2025, 9, 1))
        self.assertFalse(rebased.backfill_complete)

    def test_later_history_start_does_not_move_progress_backwards(self) -> None:
        self.store.prepare_sync_state(date(2025, 1, 1), date(2026, 9, 10))
        self.store.advance_sync_state(
            date(2025, 1, 1), date(2025, 10, 1), date(2026, 9, 10)
        )
        rebased = self.store.prepare_sync_state(
            date(2025, 9, 1), date(2026, 9, 10)
        )
        self.assertEqual(rebased.requested_history_start, date(2025, 9, 1))
        self.assertEqual(rebased.backfill_next_day, date(2025, 10, 1))
        self.assertFalse(rebased.backfill_complete)

    def test_later_history_start_does_not_delete_measurements(self) -> None:
        previous = self.store.commit_dataset(
            self.consumption, self.production, collected_at=START
        )
        self.store.prepare_sync_state(date(2025, 1, 1), date(2026, 9, 10))
        self.store.prepare_sync_state(date(2025, 9, 1), date(2026, 9, 10))
        current = self.store.read_status()
        page = self.store.read_measurements(
            "2026-09-01T00:00:00Z", "2026-09-01T01:00:00Z", limit=100
        )
        self.assertEqual(current, previous)
        self.assertEqual(len(page.rows), 4)

    def test_completed_backfill_remains_complete_after_later_start(self) -> None:
        self.store.prepare_sync_state(date(2025, 1, 1), date(2025, 1, 31))
        self.store.advance_sync_state(
            date(2025, 1, 1), date(2025, 2, 1), date(2025, 1, 31)
        )
        rebased = self.store.prepare_sync_state(
            date(2025, 1, 15), date(2026, 9, 10)
        )
        self.assertEqual(rebased.requested_history_start, date(2025, 1, 15))
        self.assertEqual(rebased.backfill_next_day, date(2025, 2, 1))
        self.assertTrue(rebased.backfill_complete)

    def test_later_then_earlier_history_start_extends_again(self) -> None:
        self.store.prepare_sync_state(date(2025, 1, 1), date(2026, 9, 10))
        later = self.store.prepare_sync_state(
            date(2025, 9, 1), date(2026, 9, 10)
        )
        self.assertEqual(later.backfill_next_day, date(2025, 9, 1))
        earlier = self.store.prepare_sync_state(
            date(2024, 12, 1), date(2026, 9, 10)
        )
        self.assertEqual(earlier.requested_history_start, date(2024, 12, 1))
        self.assertEqual(earlier.backfill_next_day, date(2024, 12, 1))
        self.assertFalse(earlier.backfill_complete)

    def test_revision_is_dataset_level_without_mass_rewrite(self) -> None:
        statements: list[str] = []
        original_connect = self.store._connect

        def traced_connect():
            connection = original_connect()
            connection.set_trace_callback(statements.append)
            return connection

        first = self.store.commit_dataset(
            self.consumption, self.production, collected_at=START
        )
        next_day = START + timedelta(days=1)
        day_two_consumption = _parsed(
            PndChannel.CONSUMPTION,
            ((Decimal("2"), IntervalQuality.VALID),),
            start=next_day,
        )
        day_two_production = _parsed(
            PndChannel.PRODUCTION,
            ((Decimal("1"), IntervalQuality.VALID),),
            start=next_day,
        )
        with mock.patch.object(self.store, "_connect", side_effect=traced_connect):
            status = self.store.commit_dataset(
                day_two_consumption, day_two_production,
                collected_at=next_day,
            )
        self.assertFalse(
            any(
                statement.upper().startswith("UPDATE MEASUREMENTS SET REVISION")
                for statement in statements
            )
        )
        with closing(sqlite3.connect(self.path)) as connection:
            physical = connection.execute(
                "SELECT DISTINCT revision FROM measurements WHERE interval_start<?",
                ("2026-09-02T00:00:00Z",),
            ).fetchall()
        self.assertEqual(physical, [(first.revision,)])
        page = self.store.read_measurements(
            "2026-09-01T00:00:00Z", "2026-09-03T00:00:00Z", limit=100
        )
        self.assertTrue(all(row.revision == status.revision for row in page.rows))

    def test_existing_database_gains_sync_state_without_rebuild(self) -> None:
        previous = self.store.commit_dataset(
            self.consumption, self.production, collected_at=START
        )
        state = self.store.prepare_sync_state(
            date(2025, 1, 1), date(2026, 9, 10)
        )
        self.assertEqual(state.backfill_next_day, date(2025, 1, 1))
        self.assertEqual(self.store.read_status(), previous)

    def test_wrong_second_channel_is_rejected_before_publication(self) -> None:
        previous = self.store.commit_dataset(self.consumption, self.production, collected_at=START)
        with self.assertRaises(ValueError):
            self.store.commit_dataset(self.consumption, self.consumption, collected_at=START)
        self.assertEqual(self.store.read_status().revision, previous.revision)

    def test_owner_equivalent_process_can_create_sqlite_transaction_sidecar(self) -> None:
        self.store.record_attempt(START)
        connection = sqlite3.connect(self.path)
        try:
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("UPDATE collector_state SET last_attempt=? WHERE id=1", ("2026-09-01T01:00:00Z",))
            journal = self.directory / "cez-pnd.sqlite3-journal"
            self.assertTrue(journal.is_file())
            connection.rollback()
        finally:
            connection.close()
        self.assertFalse(journal.exists())

    @unittest.skipUnless(os.name == "posix", "POSIX ownership/mode semantics required")
    def test_store_rejects_wrong_owner_and_world_writable_directory(self) -> None:
        owner = os.getuid()
        accepted = NormalizedDatasetStore(self.path, required_uid=owner)
        accepted.record_attempt(START)
        with self.assertRaisesRegex(OSError, "directory owner"):
            NormalizedDatasetStore(self.path, required_uid=owner + 1).read_status()
        os.chmod(self.directory, 0o707)
        try:
            with self.assertRaisesRegex(OSError, "unsafe dataset directory"):
                accepted.read_status()
        finally:
            os.chmod(self.directory, 0o700)


if __name__ == "__main__":
    unittest.main()
