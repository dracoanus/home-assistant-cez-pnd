"""Offline per-attempt publication tests using authoritative SQLite state."""
from datetime import UTC, date, datetime
import io
import json
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest import mock

from collector_service.event_broker import EventBroker, EventBrokerError, SyncEvent
from collector_service.sync_worker import SyncCycleOutcome, SyncWorker
from collector_service.dataset_store import NormalizedDatasetStore
from collector_service.cez_csv_models import PndChannel
from collector.tests.test_sync_worker import _configuration, _committed, _partial_committed, _parsed


class SyncPublicationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.store = NormalizedDatasetStore(
            Path(self.temporary.name) / "dataset.sqlite3", required_uid=None
        )
        self.events = []
        self.logs = []

    def commit(self):
        self.store.commit_dataset(
            _parsed(PndChannel.CONSUMPTION), _parsed(PndChannel.PRODUCTION),
            collected_at=datetime(2026, 9, 10, 1, tzinfo=UTC),
        )

    def success(self, *_args):
        self.commit()
        return SyncCycleOutcome(True, committed=_committed())

    def failure(self, *_args):
        return SyncCycleOutcome(False, code="data_probe_auth_failed")

    def worker(self, cycle=None, history=None, publish=None):
        return SyncWorker(
            _configuration(history), store=self.store, cycle=cycle or self.success,
            emit=self.logs.append,
            publish=self.events.append if publish is None else publish,
        )

    def test_current_success_and_partial_success_use_new_exact_revision(self):
        for partial in (False, True):
            with self.subTest(partial=partial):
                self.events.clear()
                def cycle(*_args):
                    self.commit()
                    return SyncCycleOutcome(True, committed=(
                        _partial_committed() if partial else _committed()))
                outcome = self.worker(cycle)._scheduled_current_day(date(2026, 9, 10))
                self.assertTrue(outcome.succeeded)
                self.assertEqual(self.events, [SyncEvent(
                    "current_day", "succeeded", self.store.read_status().revision)])

    def test_failure_without_dataset_is_null_and_previous_dataset_is_unchanged(self):
        worker = self.worker(self.failure)
        worker._scheduled_current_day(date(2026, 9, 10))
        self.assertEqual(self.events, [SyncEvent("current_day", "failed", None)])
        self.commit()
        before = self.store.read_status()
        rows = self.store.read_measurements(
            "2026-09-10T00:00:00Z", "2026-09-11T00:00:00Z", limit=10).rows
        worker._scheduled_current_day(date(2026, 9, 10))
        self.assertEqual(self.events[-1], SyncEvent("current_day", "failed", before.revision))
        self.assertEqual(self.store.read_status(), before)
        self.assertEqual(self.store.read_measurements(
            "2026-09-10T00:00:00Z", "2026-09-11T00:00:00Z", limit=10).rows, rows)

    def test_two_backfill_chunks_publish_sequentially_before_checkpoints(self):
        advances = []
        original = self.store.advance_sync_state
        def advance(*args):
            advances.append(len(self.events))
            return original(*args)
        with mock.patch.object(self.store, "advance_sync_state", side_effect=advance):
            outcome = self.worker(history=date(2025, 1, 1))._scheduled_cycle(date(2025, 3, 10))
        self.assertTrue(outcome.succeeded)
        self.assertEqual(advances, [1, 2])
        self.assertEqual([e.sync_kind for e in self.events], ["historical_backfill"] * 2)
        self.assertNotEqual(self.events[0].dataset_revision, self.events[1].dataset_revision)

    def test_failed_second_chunk_and_complete_have_no_extra_event(self):
        calls = 0
        def cycle(*args):
            nonlocal calls
            calls += 1
            return self.success(*args) if calls == 1 else self.failure(*args)
        self.assertFalse(self.worker(cycle, date(2025, 1, 1))._scheduled_cycle(date(2025, 3, 10)).succeeded)
        self.assertEqual([e.sync_result for e in self.events], ["succeeded", "failed"])
        self.assertEqual(self.events[0].dataset_revision, self.events[1].dataset_revision)
        self.events.clear()
        self.assertTrue(self.worker(history=date(2025, 2, 1))._scheduled_cycle(date(2025, 2, 2)).succeeded)
        self.assertEqual(len(self.events), 1)
        self.assertTrue(any(e.event == "backfill_complete" for e in self.logs))

    def test_checkpoint_failure_does_not_publish_false_failure(self):
        with mock.patch.object(self.store, "advance_sync_state", side_effect=OSError("private")):
            outcome = self.worker(history=date(2025, 1, 1))._scheduled_cycle(date(2025, 3, 10))
        self.assertFalse(outcome.succeeded)
        self.assertEqual(outcome.code, "data_probe_storage_failed")
        self.assertEqual(self.events, [SyncEvent(
            "historical_backfill", "succeeded", self.store.read_status().revision)])

    def test_first_backfill_chunk_failure_publishes_once_without_dataset(self):
        cycle = mock.Mock(side_effect=self.failure)
        self.assertFalse(self.worker(cycle, date(2025, 1, 1))._scheduled_cycle(date(2025, 3, 10)).succeeded)
        cycle.assert_called_once()
        self.assertEqual(self.events, [SyncEvent("historical_backfill", "failed", None)])

    def test_invalid_authoritative_revision_is_not_published_or_logged(self):
        from collector_service.sync_worker import emit_sync_event
        worker = self.worker()
        worker._emit = emit_sync_event
        with mock.patch.object(self.store, "read_status", return_value=SimpleNamespace(revision="private-secret")), mock.patch("sys.stdout", new_callable=io.StringIO) as output:
            worker._notify_completion("current_day", SyncCycleOutcome(False, code="data_probe_auth_failed"))
        self.assertEqual(self.events, [])
        payload = json.loads(output.getvalue())
        self.assertEqual(set(payload), {"timestamp", "event"})
        self.assertEqual(payload["event"], "sync_notification_failed")
        self.assertNotIn("private-secret", output.getvalue())

    def test_correction_with_and_without_backfill_configuration(self):
        for history in (None, date(2025, 1, 1)):
            if history is not None:
                self.store.prepare_sync_state(history, date(2025, 1, 2))
                self.store.advance_sync_state(history, date(2025, 1, 3), date(2025, 1, 2))
            for succeeded in (True, False):
                with self.subTest(history=history, succeeded=succeeded):
                    self.events.clear()
                    self.worker(self.success if succeeded else self.failure, history)._scheduled_cycle(date(2025, 1, 2))
                    self.assertEqual(self.events, [SyncEvent(
                        "historical_correction", "succeeded" if succeeded else "failed",
                        self.store.read_status().revision)])

    def test_notification_errors_preserve_outcome_and_never_fabricate_null(self):
        for phase in ("read", "publish"):
            with self.subTest(phase=phase):
                self.events.clear()
                publisher = mock.Mock(side_effect=RuntimeError("private-secret")) if phase == "publish" else self.events.append
                worker = self.worker(publish=publisher)
                self.commit()
                outcome = SyncCycleOutcome(True, committed=_committed())
                with mock.patch.object(self.store, "read_status", side_effect=OSError("private-secret")) if phase == "read" else mock.patch.object(self.store, "read_status", wraps=self.store.read_status):
                    with mock.patch.object(worker, "_current_day_cycle", return_value=outcome), mock.patch("sys.stdout", new_callable=io.StringIO) as output:
                        self.assertIs(worker._scheduled_current_day(date(2026, 9, 10)), outcome)
                        self.assertEqual(output.getvalue(), "")
                self.assertEqual(self.events, [])
                self.assertEqual(self.logs[-2].event, "sync_notification_failed")
                self.assertNotIn("private-secret", json.dumps([e.as_dict() for e in self.logs]))

    def test_broker_close_during_cycle_does_not_trigger_retry(self):
        broker = EventBroker()
        calls = []
        def cycle(*args):
            calls.append(1)
            result = self.success(*args)
            broker.close()
            return result
        worker = self.worker(cycle, publish=broker.publish)
        def wait(_timeout):
            worker.request_stop()
            return True
        worker._wait = wait
        worker._run()
        self.assertEqual(len(calls), 2)  # Current-day, then independently due correction.
        self.assertFalse(any(e.event in {"sync_cycle_failed", "sync_notification_failed"} for e in self.logs))

    def test_stop_starts_no_new_attempt_or_notification(self):
        cycle = mock.Mock(side_effect=self.success)
        worker = self.worker(cycle)
        worker.request_stop()
        worker._scheduled_current_day(date(2026, 9, 10))
        worker._scheduled_cycle(date(2026, 9, 9))
        cycle.assert_not_called()
        self.assertEqual(self.events, [])

    def test_stop_during_inflight_attempt_skips_notification_and_next_attempt(self):
        entered, release = threading.Event(), threading.Event()
        calls = []
        def cycle(*args):
            calls.append(1)
            entered.set()
            if not release.wait(2):
                raise RuntimeError("synthetic release timeout")
            return self.success(*args)
        worker = self.worker(cycle)
        worker.start()
        try:
            self.assertTrue(entered.wait(2))
            worker.request_stop()
        finally:
            release.set()
            self.assertTrue(worker.stop(2))
        self.assertEqual(calls, [1])
        self.assertEqual(self.events, [])
        self.assertIsNotNone(self.store.read_status())
        self.assertFalse(any(e.event == "sync_cycle_failed" for e in self.logs))

    def test_server_injects_its_existing_broker_publisher(self):
        from collector_service import server
        instance = mock.Mock()
        instance.serve_forever.side_effect = KeyboardInterrupt
        instance.server_close.return_value = True
        watchdog = mock.Mock()
        watchdog.remaining.return_value = 8
        configuration = SimpleNamespace(sync=_configuration())
        with mock.patch("collector_service.sync_worker.SyncWorker") as worker_type, mock.patch.object(server, "_start_message"), mock.patch.object(server, "write_json_line"):
            worker_type.return_value.stop.return_value = True
            self.assertEqual(server._serve(configuration, instance, None, self.store, watchdog), 0)
        worker_type.assert_called_once_with(
            configuration.sync, store=self.store, publish=instance.event_broker.publish)
        worker_type.return_value.request_stop.assert_called_once()

    def test_scheduler_publishes_current_then_correction_without_log_duplicates(self):
        worker = self.worker()
        worker._wait = lambda _timeout: True
        worker._run()
        self.assertEqual([e.sync_kind for e in self.events], ["current_day", "historical_correction"])
        self.assertTrue(any(e.event == "sync_cycle_succeeded" for e in self.logs))

    def test_unexpected_broker_error_and_exception_are_contained(self):
        for error in (EventBrokerError("event_waiter_limit"), RuntimeError("private-secret")):
            publisher = mock.Mock(side_effect=error)
            self.assertTrue(self.worker(publish=publisher)._scheduled_current_day(date(2026, 9, 10)).succeeded)
            publisher.assert_called_once()
            self.assertTrue(any(e.event == "sync_notification_failed" for e in self.logs))


if __name__ == "__main__":
    unittest.main()
