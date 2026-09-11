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


def _configuration() -> SyncConfiguration:
    return SyncConfiguration("private-user", "private-password", "private-elm", None)


def _committed() -> DataProbeDatasetCommittedObservation:
    return DataProbeDatasetCommittedObservation(
        96, 96, 0, 0, 96, 96, 0, 0, "complete"
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

        def cycle(_configuration, target_day):
            nonlocal active, maximum_active
            active += 1
            maximum_active = max(maximum_active, active)
            days.append(target_day)
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
        self.assertGreaterEqual(len(days), 1)
        self.assertTrue(all(day == date(2026, 3, 28) for day in days))
        self.assertEqual(maximum_active, 1)
        self.assertEqual(sync_worker.SYNC_INTERVAL_SECONDS, 6 * 60 * 60)
        self.assertEqual(events[0].event, "sync_worker_started")
        self.assertEqual(events[-1].event, "sync_worker_stopped")

    def test_cycle_failure_is_contained_and_event_is_secret_free(self) -> None:
        private_values = (
            "private-user",
            "private-password",
            "private-elm",
            "private-csv-value",
        )
        events: list[sync_worker.SafeSyncEvent] = []
        attempted = threading.Event()

        def failed_cycle(_configuration, _target_day):
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

            def cycle(_configuration, _target_day):
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


if __name__ == "__main__":
    unittest.main()
