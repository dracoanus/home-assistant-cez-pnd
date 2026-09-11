"""Offline tests for the fixed-interval Collector synchronization worker."""

from __future__ import annotations

from datetime import UTC, date, datetime
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest import mock

from collector_service import sync_worker
from collector_service.cez_http_auth import (
    AuthResult,
    AuthStatus,
    DataProbeDatasetCommittedObservation,
    SafeHttpAuthEvent,
)
from collector_service.dataset_store import NormalizedDatasetStore
from collector_service.api import CollectorApi, SYNTHETIC_METER_ID, TokenVerifier
from collector_service.cez_csv_models import (
    IntervalQuality,
    IntervalRecord,
    ParsedPndData,
    PndChannel,
)
from collector_service.runtime_config import SyncConfiguration
from collector_service.structured_logging import structured_event_json


def _configuration(history_start: date | None = None) -> SyncConfiguration:
    return SyncConfiguration(
        "private-user", "private-password", "private-elm", None, history_start
    )


def _committed() -> DataProbeDatasetCommittedObservation:
    return DataProbeDatasetCommittedObservation(
        96, 96, 0, 0, 96, 96, 0, 0, "complete"
    )


def _partial_committed() -> DataProbeDatasetCommittedObservation:
    return DataProbeDatasetCommittedObservation(
        96, 64, 32, 0, 96, 64, 32, 0, "partial"
    )


def _parsed(channel: PndChannel, value: str = "1") -> ParsedPndData:
    start = datetime(2026, 9, 10, tzinfo=UTC)
    return ParsedPndData(
        channel,
        channel.profile_marker,
        "utf-8",
        ";",
        (
            IntervalRecord(
                channel,
                start,
                datetime(2026, 9, 10, 0, 15, tzinfo=UTC),
                Decimal(value),
                IntervalQuality.VALID,
                date(2026, 9, 10),
            ),
        ),
    )


class SyncWorkerTests(unittest.TestCase):
    def test_cycle_reuses_data_probe_without_raw_persistence(self) -> None:
        transport = mock.Mock()
        transport.resolve = mock.Mock()
        events: list[SafeHttpAuthEvent] = []

        def probe(configuration, supplied_transport, **kwargs):
            self.assertEqual(configuration.probe_date, date(2026, 9, 10))
            self.assertEqual(kwargs["start_day"], date(2026, 9, 10))
            self.assertEqual(kwargs["end_day"], date(2026, 9, 11))
            self.assertIs(supplied_transport, transport)
            self.assertFalse(kwargs["persist_raw_outputs"])
            kwargs["emit"](
                SafeHttpAuthEvent(
                    "data_probe_dataset_committed",
                    dataset_committed_observation=_committed(),
                )
            )
            return AuthResult(
                AuthStatus.AUTHENTICATED,
                "auth_authenticated_endpoint_verified",
            )

        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            sync_worker, "run_data_probe", side_effect=probe
        ):
            outcome = sync_worker.run_sync_cycle(
                _configuration(),
                date(2026, 9, 10),
                date(2026, 9, 11),
                store=NormalizedDatasetStore(
                    Path(temporary) / "dataset.sqlite3", required_uid=None
                ),
                transport_factory=lambda: transport,
                emit_auth=events.append,
            )
        self.assertTrue(outcome.succeeded)
        self.assertEqual(outcome.committed, _committed())
        self.assertEqual(len(events), 1)

    def test_worker_is_nonblocking_uses_previous_prague_day_and_does_not_overlap(self) -> None:
        entered = threading.Event()
        release = threading.Event()
        active = 0
        maximum_active = 0
        days: list[date] = []
        events: list[sync_worker.SafeSyncEvent] = []

        def cycle(_configuration, target_day, end_day):
            nonlocal active, maximum_active
            active += 1
            maximum_active = max(maximum_active, active)
            days.append(target_day)
            self.assertEqual(end_day, target_day + sync_worker.timedelta(days=1))
            entered.set()
            release.wait(1.0)
            active -= 1
            return sync_worker.SyncCycleOutcome(True, committed=_committed())

        fixed = datetime(2026, 3, 29, 0, 30, tzinfo=sync_worker.PRAGUE_TIMEZONE)
        worker = sync_worker.SyncWorker(
            _configuration(),
            store=mock.Mock(),
            cycle=cycle,
            emit=events.append,
            now_local=lambda: fixed,
            interval_seconds=0.01,
        )
        started = time.monotonic()
        worker.start()
        self.assertLess(time.monotonic() - started, 0.2)
        self.assertTrue(entered.wait(1.0))
        release.set()
        time.sleep(0.04)
        self.assertTrue(worker.stop(1.0))
        self.assertGreaterEqual(len(days), 2)
        self.assertEqual(set(days), {date(2026, 3, 28), date(2026, 3, 29)})
        self.assertEqual(maximum_active, 1)
        self.assertEqual(
            sync_worker.CURRENT_DAY_SYNC_INTERVAL_SECONDS, 60 * 60
        )
        self.assertEqual(
            sync_worker.HISTORICAL_SYNC_INTERVAL_SECONDS, 6 * 60 * 60
        )
        self.assertEqual(events[0].event, "sync_worker_started")
        self.assertEqual(events[-1].event, "sync_worker_stopped")

    def test_hourly_wakes_run_current_day_and_historical_only_every_six_hours(
        self,
    ) -> None:
        historical_days: list[date] = []
        current_days: list[date] = []
        clock = iter(float(hour * 60 * 60) for hour in range(7))

        def historical(_configuration, start_day, _end_day):
            historical_days.append(start_day)
            return sync_worker.SyncCycleOutcome(True, committed=_committed())

        def current(_configuration, start_day, _end_day):
            current_days.append(start_day)
            if len(current_days) == 7:
                worker._stop_event.set()
            return sync_worker.SyncCycleOutcome(True, committed=_committed())

        fixed = datetime(2026, 9, 11, 12, tzinfo=sync_worker.PRAGUE_TIMEZONE)
        worker = sync_worker.SyncWorker(
            _configuration(),
            store=mock.Mock(),
            cycle=historical,
            current_day_cycle=current,
            emit=lambda _event: None,
            now_local=lambda: fixed,
            interval_seconds=0.001,
            historical_interval_seconds=6 * 60 * 60,
            monotonic_clock=clock.__next__,
        )
        worker._run()
        self.assertEqual(current_days, [date(2026, 9, 11)] * 7)
        self.assertEqual(historical_days, [date(2026, 9, 10)] * 2)

    def test_current_day_cycle_retains_complete_grid_validation(self) -> None:
        store = mock.Mock()
        with mock.patch.object(
            sync_worker,
            "run_sync_cycle",
            return_value=sync_worker.SyncCycleOutcome(
                True, committed=_committed()
            ),
        ) as cycle:
            worker = sync_worker.SyncWorker(
                _configuration(),
                store=store,
            )
            outcome = worker._default_current_day_cycle(
                _configuration(), date(2026, 9, 11), date(2026, 9, 12)
            )
        self.assertTrue(outcome.succeeded)
        self.assertNotIn("require_complete_days", cycle.call_args.kwargs)

    def test_current_day_events_are_bounded_and_secret_free(self) -> None:
        event = sync_worker.SafeSyncEvent(
            "current_day_sync_succeeded",
            committed=_committed(),
            local_day=date(2026, 9, 11),
        )
        payload = event.as_dict()
        self.assertEqual(payload["local_day"], "2026-09-11")
        self.assertEqual(payload["consumption_valid"], 96)
        self.assertEqual(payload["production_missing"], 0)
        self.assertNotIn("code", payload)
        with self.assertRaises(ValueError):
            sync_worker.SafeSyncEvent(
                "current_day_sync_failed",
                code="arbitrary",
                local_day=date(2026, 9, 11),
            )

    def test_partial_current_day_is_a_successful_sync(self) -> None:
        events: list[sync_worker.SafeSyncEvent] = []
        worker = sync_worker.SyncWorker(
            _configuration(),
            store=mock.Mock(),
            current_day_cycle=lambda *_args: sync_worker.SyncCycleOutcome(
                True, committed=_partial_committed()
            ),
            emit=events.append,
        )
        outcome = worker._scheduled_current_day(date(2026, 9, 11))
        self.assertTrue(outcome.succeeded)
        succeeded = events[-1].as_dict()
        self.assertEqual(succeeded["event"], "current_day_sync_succeeded")
        self.assertEqual(succeeded["dataset_state"], "partial")
        self.assertEqual(succeeded["consumption_missing"], 32)
        self.assertEqual(succeeded["production_missing"], 32)

    def test_cycle_failure_is_contained_and_event_is_secret_free(self) -> None:
        private_values = (
            "private-user",
            "private-password",
            "private-elm",
            "private-csv-value",
        )
        events: list[sync_worker.SafeSyncEvent] = []
        attempted = threading.Event()

        def failed_cycle(_configuration, _target_day, _end_day):
            attempted.set()
            raise RuntimeError(" ".join(private_values))

        worker = sync_worker.SyncWorker(
            _configuration(),
            store=mock.Mock(),
            cycle=failed_cycle,
            emit=events.append,
            interval_seconds=60,
        )
        worker.start()
        self.assertTrue(attempted.wait(1.0))
        self.assertTrue(worker.stop(1.0))
        failed = next(event for event in events if event.event == "sync_cycle_failed")
        rendered = structured_event_json(failed.as_dict())
        self.assertEqual(failed.code, "sync_cycle_internal_failed")
        for private in private_values:
            self.assertNotIn(private, rendered)
        with self.assertRaises(ValueError):
            sync_worker.SafeSyncEvent("sync_cycle_failed", code="arbitrary")

    def test_failed_cycle_advances_attempt_only_and_preserves_dataset(self) -> None:
        transport = mock.Mock()
        transport.resolve = mock.Mock()
        with tempfile.TemporaryDirectory() as temporary:
            store = NormalizedDatasetStore(
                Path(temporary) / "dataset.sqlite3",
                required_uid=None,
                revision_factory=lambda: "ds_" + "a" * 32,
            )
            previous = store.commit_dataset(
                _parsed(PndChannel.CONSUMPTION),
                _parsed(PndChannel.PRODUCTION),
                collected_at=datetime(2026, 9, 10, 1, tzinfo=UTC),
            )

            def failed_probe(*_args, **_kwargs):
                store.record_attempt(datetime(2026, 9, 11, 1, tzinfo=UTC))
                return AuthResult(AuthStatus.FAILED, "data_probe_auth_failed")

            with mock.patch.object(
                sync_worker, "run_data_probe", side_effect=failed_probe
            ):
                outcome = sync_worker.run_sync_cycle(
                    _configuration(),
                    date(2026, 9, 10),
                    date(2026, 9, 11),
                    store=store,
                    transport_factory=lambda: transport,
                    emit_auth=lambda _event: None,
                )
            current = store.read_status()
            self.assertFalse(outcome.succeeded)
            self.assertEqual(outcome.code, "data_probe_auth_failed")
            self.assertEqual(current.revision, previous.revision)
            self.assertEqual(current.last_success, previous.last_success)
            self.assertEqual(current.last_attempt, "2026-09-11T01:00:00Z")
            self.assertEqual(
                len(
                    store.read_measurements(
                        "2026-09-10T00:00:00Z",
                        "2026-09-10T01:00:00Z",
                        limit=10,
                    ).rows
                ),
                2,
            )

    def test_api_read_remains_available_while_worker_cycle_is_active(self) -> None:
        entered = threading.Event()
        release = threading.Event()
        token = "A" * 43
        with tempfile.TemporaryDirectory() as temporary:
            store = NormalizedDatasetStore(
                Path(temporary) / "dataset.sqlite3", required_uid=None
            )
            store.commit_dataset(
                _parsed(PndChannel.CONSUMPTION),
                _parsed(PndChannel.PRODUCTION),
                collected_at=datetime(2026, 9, 10, 1, tzinfo=UTC),
            )
            verifier = TokenVerifier.from_mapping(
                {
                    "schema_version": "1",
                    "token_sha256": hashlib.sha256(token.encode("ascii")).hexdigest(),
                    "meter_id": SYNTHETIC_METER_ID,
                    "scopes": ["health:read", "measurements:read", "status:read"],
                }
            )

            def cycle(_configuration, _target_day, _end_day):
                entered.set()
                release.wait(1.0)
                return sync_worker.SyncCycleOutcome(True, committed=_committed())

            worker = sync_worker.SyncWorker(
                _configuration(),
                store=store,
                cycle=cycle,
                emit=lambda _event: None,
                interval_seconds=60,
            )
            worker.start()
            self.assertTrue(entered.wait(1.0))
            response = CollectorApi(verifier, store).handle(
                "GET",
                f"/api/v1/status?meter_id={SYNTHETIC_METER_ID}",
                {"Authorization": f"Bearer {token}"},
            )
            self.assertEqual(response.status, 200)
            release.set()
            self.assertTrue(worker.stop(1.0))

    def test_success_event_exposes_only_bounded_counts_and_state(self) -> None:
        payload = sync_worker.SafeSyncEvent(
            "sync_cycle_succeeded", committed=_committed()
        ).as_dict()
        self.assertEqual(
            payload,
            {
                "event": "sync_cycle_succeeded",
                "consumption_intervals": 96,
                "production_intervals": 96,
                "dataset_state": "complete",
            },
        )

    def test_backfill_processes_at_most_two_sequential_31_day_chunks(self) -> None:
        ranges: list[tuple[date, date]] = []
        events: list[sync_worker.SafeSyncEvent] = []
        with tempfile.TemporaryDirectory() as temporary:
            store = NormalizedDatasetStore(
                Path(temporary) / "dataset.sqlite3", required_uid=None
            )

            def cycle(_configuration, start_day, end_day):
                ranges.append((start_day, end_day))
                return sync_worker.SyncCycleOutcome(True, committed=_committed())

            worker = sync_worker.SyncWorker(
                _configuration(date(2025, 1, 1)),
                store=store,
                cycle=cycle,
                emit=events.append,
            )
            outcome = worker._scheduled_cycle(date(2025, 3, 10))
            state = store.read_sync_state()
        self.assertTrue(outcome.succeeded)
        self.assertEqual(
            ranges,
            [
                (date(2025, 1, 1), date(2025, 2, 1)),
                (date(2025, 2, 1), date(2025, 3, 4)),
            ],
        )
        self.assertEqual(state.backfill_next_day, date(2025, 3, 4))
        self.assertFalse(state.backfill_complete)
        self.assertEqual(
            sum(event.event == "backfill_chunk_succeeded" for event in events),
            2,
        )

    def test_backfill_failure_stops_chunks_without_advancing_failed_range(self) -> None:
        ranges: list[tuple[date, date]] = []
        events: list[sync_worker.SafeSyncEvent] = []
        with tempfile.TemporaryDirectory() as temporary:
            store = NormalizedDatasetStore(
                Path(temporary) / "dataset.sqlite3", required_uid=None
            )

            def cycle(_configuration, start_day, end_day):
                ranges.append((start_day, end_day))
                if len(ranges) == 2:
                    return sync_worker.SyncCycleOutcome(
                        False, code="data_probe_auth_failed"
                    )
                return sync_worker.SyncCycleOutcome(True, committed=_committed())

            worker = sync_worker.SyncWorker(
                _configuration(date(2025, 1, 1)),
                store=store,
                cycle=cycle,
                emit=events.append,
            )
            outcome = worker._scheduled_cycle(date(2025, 3, 10))
            state = store.read_sync_state()
        self.assertFalse(outcome.succeeded)
        self.assertEqual(len(ranges), 2)
        self.assertEqual(state.backfill_next_day, date(2025, 2, 1))
        failure = next(
            event for event in events if event.event == "backfill_chunk_failed"
        )
        self.assertEqual(failure.code, "data_probe_auth_failed")

    def test_current_day_failure_preserves_successful_backfill_checkpoint(self) -> None:
        events: list[sync_worker.SafeSyncEvent] = []
        with tempfile.TemporaryDirectory() as temporary:
            store = NormalizedDatasetStore(
                Path(temporary) / "dataset.sqlite3", required_uid=None
            )

            def historical(_configuration, _start_day, _end_day):
                return sync_worker.SyncCycleOutcome(True, committed=_committed())

            def current(_configuration, _start_day, _end_day):
                return sync_worker.SyncCycleOutcome(
                    False, code="data_probe_auth_failed"
                )

            worker = sync_worker.SyncWorker(
                _configuration(date(2025, 1, 1)),
                store=store,
                cycle=historical,
                current_day_cycle=current,
                emit=events.append,
            )
            historical_outcome = worker._scheduled_cycle(date(2025, 3, 10))
            checkpoint = store.read_sync_state()
            current_outcome = worker._scheduled_current_day(date(2025, 3, 11))
        self.assertTrue(historical_outcome.succeeded)
        self.assertFalse(current_outcome.succeeded)
        self.assertEqual(checkpoint.backfill_next_day, date(2025, 3, 4))
        self.assertEqual(
            [event.event for event in events][-2:],
            ["current_day_sync_started", "current_day_sync_failed"],
        )

    def test_historical_failure_does_not_corrupt_current_day_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = NormalizedDatasetStore(
                Path(temporary) / "dataset.sqlite3", required_uid=None
            )

            def historical(_configuration, _start_day, _end_day):
                return sync_worker.SyncCycleOutcome(
                    False, code="data_probe_auth_failed"
                )

            def current(_configuration, _start_day, _end_day):
                committed_at = datetime(2026, 9, 11, 12, tzinfo=UTC)
                store.commit_dataset(
                    _parsed(PndChannel.CONSUMPTION, "2"),
                    _parsed(PndChannel.PRODUCTION, "0"),
                    collected_at=committed_at,
                )
                return sync_worker.SyncCycleOutcome(True, committed=_committed())

            worker = sync_worker.SyncWorker(
                _configuration(date(2025, 1, 1)),
                store=store,
                cycle=historical,
                current_day_cycle=current,
                emit=lambda _event: None,
            )
            historical_outcome = worker._scheduled_cycle(date(2026, 9, 10))
            current_outcome = worker._scheduled_current_day(date(2026, 9, 11))
            rows = store.read_measurements(
                "2026-09-10T00:00:00Z", "2026-09-10T01:00:00Z", limit=10
            ).rows
        self.assertFalse(historical_outcome.succeeded)
        self.assertTrue(current_outcome.succeeded)
        self.assertEqual(len(rows), 2)

    def test_backfill_exception_fails_safely_without_advancing_checkpoint(self) -> None:
        events: list[sync_worker.SafeSyncEvent] = []
        with tempfile.TemporaryDirectory() as temporary:
            store = NormalizedDatasetStore(
                Path(temporary) / "dataset.sqlite3", required_uid=None
            )

            def cycle(_configuration, _start_day, _end_day):
                raise RuntimeError("private runtime detail")

            worker = sync_worker.SyncWorker(
                _configuration(date(2025, 1, 1)),
                store=store,
                cycle=cycle,
                emit=events.append,
            )
            outcome = worker._scheduled_cycle(date(2025, 3, 10))
            state = store.read_sync_state()
        self.assertFalse(outcome.succeeded)
        self.assertEqual(outcome.code, "sync_cycle_internal_failed")
        self.assertEqual(state.backfill_next_day, date(2025, 1, 1))
        failure = next(
            event for event in events if event.event == "backfill_chunk_failed"
        )
        self.assertEqual(failure.code, "sync_cycle_internal_failed")
        self.assertNotIn("private runtime detail", structured_event_json(failure.as_dict()))

    def test_backfill_completion_transitions_to_three_day_overlap(self) -> None:
        ranges: list[tuple[date, date]] = []
        events: list[sync_worker.SafeSyncEvent] = []
        with tempfile.TemporaryDirectory() as temporary:
            store = NormalizedDatasetStore(
                Path(temporary) / "dataset.sqlite3", required_uid=None
            )

            def cycle(_configuration, start_day, end_day):
                ranges.append((start_day, end_day))
                return sync_worker.SyncCycleOutcome(True, committed=_committed())

            worker = sync_worker.SyncWorker(
                _configuration(date(2026, 9, 1)),
                store=store,
                cycle=cycle,
                emit=events.append,
            )
            worker._scheduled_cycle(date(2026, 9, 10))
            completed = store.read_sync_state()
            worker._scheduled_cycle(date(2026, 9, 10))
        self.assertTrue(completed.backfill_complete)
        self.assertEqual(
            ranges,
            [
                (date(2026, 9, 1), date(2026, 9, 11)),
                (date(2026, 9, 8), date(2026, 9, 11)),
            ],
        )
        self.assertIn("backfill_complete", [event.event for event in events])
        self.assertEqual(sync_worker.CORRECTION_OVERLAP_DAYS, 3)

    def test_backfill_events_expose_only_dates_counts_and_fixed_codes(self) -> None:
        event = sync_worker.SafeSyncEvent(
            "backfill_chunk_succeeded",
            committed=_committed(),
            start_day=date(2025, 1, 1),
            end_day=date(2025, 2, 1),
        )
        rendered = structured_event_json(event.as_dict())
        self.assertEqual(
            set(event.as_dict()),
            {
                "event",
                "start_day",
                "end_day",
                "consumption_intervals",
                "production_intervals",
                "dataset_state",
            },
        )
        for private in (
            "private-user",
            "private-password",
            "private-elm",
            "measurement-value",
        ):
            self.assertNotIn(private, rendered)


if __name__ == "__main__":
    unittest.main()
