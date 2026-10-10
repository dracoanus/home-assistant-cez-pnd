"""Deterministic offline deadline and conservative recovery tests."""
from dataclasses import replace
from datetime import date, datetime
import json
from pathlib import Path
import threading
import time
import unittest
from unittest import mock

from collector_service import runtime_config, sync_worker
from collector.tests.test_sync_worker import _configuration, _committed


class Clock:
    def __init__(self, until):
        self.value = 0.0
        self.until = until
        self.worker = None
        self.waits = []
    def now(self):
        return self.value
    def wait(self, delay):
        assert delay > 0
        self.waits.append(delay)
        self.value += delay
        if self.value > self.until:
            self.worker._stop_event.set()
            return True
        return False


class SchedulerTests(unittest.TestCase):
    def worker(self, minutes=60, until=12*3600, current=None, historical=None):
        clock = Clock(until)
        runs = []
        def cycle(kind, supplied=None):
            def run(*args):
                runs.append((kind, clock.value))
                return supplied(*args) if supplied else sync_worker.SyncCycleOutcome(True, committed=_committed())
            return run
        worker = sync_worker.SyncWorker(replace(_configuration(), sync_interval_minutes=minutes),
            store=mock.Mock(), current_day_cycle=cycle("current", current),
            cycle=cycle("history", historical), emit=lambda _: None,
            now_local=lambda: datetime(2026, 9, 11, tzinfo=sync_worker.PRAGUE_TIMEZONE),
            monotonic_clock=clock.now, wait=clock.wait)
        clock.worker = worker
        return worker, clock, runs

    def test_current_first_and_independent_history_for_all_intervals(self):
        for minutes in (15, 60, 720):
            with self.subTest(minutes=minutes):
                worker, clock, runs = self.worker(minutes)
                worker._run()
                self.assertEqual(runs[:2], [("current", 0), ("history", 0)])
                self.assertEqual([at for kind, at in runs if kind == "history"], [0, 21600, 43200])
                self.assertEqual([at for kind, at in runs if kind == "current"],
                                 list(range(0, 43201, minutes*60)))
                self.assertTrue(all(delay > 0 for delay in clock.waits))

    def test_completion_anchors_cadence_and_restart_is_immediate(self):
        for _ in range(2):
            worker, clock, runs = self.worker(until=8000)
            def current(*_):
                clock.value += 100
                return sync_worker.SyncCycleOutcome(True, committed=_committed())
            worker._current_day_cycle = lambda *args: (runs.append(("current", clock.value)), current())[1]
            worker._run()
            self.assertEqual([at for kind, at in runs if kind == "current"], [0, 3700, 7400])

    def test_long_history_coalesces_and_does_not_interrupt_operation(self):
        worker, clock, runs = self.worker(15, until=20000)
        active = False
        def history(*_):
            nonlocal active
            self.assertFalse(active)
            active = True
            clock.value += 10000
            active = False
            return sync_worker.SyncCycleOutcome(True, committed=_committed())
        worker._cycle = history
        worker._run()
        current = [at for kind, at in runs if kind == "current"]
        self.assertEqual(current[:3], [0, 10000, 10900])
        self.assertEqual(current.count(10000), 1)

    def test_transient_backoff_single_pending_retry_and_reset(self):
        worker, clock, runs = self.worker(until=16000)
        attempts = iter([False]*5 + [True, False] + [True]*10)
        def current(*_):
            if next(attempts):
                return sync_worker.SyncCycleOutcome(True, committed=_committed())
            return sync_worker.SyncCycleOutcome(False, code="auth_operation_timeout")
        worker._current_day_cycle = lambda *args: (runs.append(("current", clock.value)), current())[1]
        worker._run()
        self.assertEqual([at for kind, at in runs if kind == "current"], [0, 300, 1200, 3000, 6600, 10200, 13800, 14100])
        self.assertEqual([at for kind, at in runs if kind == "history"], [10200])
        self.assertEqual(sync_worker.retry_delay("auth_operation_timeout", 99), 3600)

    def test_long_failed_operation_has_no_overdue_retry_burst(self):
        worker, clock, runs = self.worker(15, until=6000)
        def current(*_):
            clock.value += 5000
            return sync_worker.SyncCycleOutcome(False, code="auth_connect_failed")
        worker._current_day_cycle = lambda *args: (runs.append(("current", clock.value)), current())[1]
        worker._run()
        self.assertEqual([at for kind, at in runs if kind == "current"], [0, 5300])

    def test_history_failure_holds_current_day_cooldown(self):
        worker, clock, runs = self.worker(15, until=7200,
            historical=lambda *_: sync_worker.SyncCycleOutcome(False, code="data_probe_auth_failed"))
        worker._run()
        self.assertEqual([at for kind, at in runs if kind == "current"], [0])
        self.assertEqual([at for kind, at in runs if kind == "history"], [0, 3600, 7200])

    def test_stop_between_history_chunks_preserves_checkpoint(self):
        from collector_service.dataset_store import NormalizedDatasetStore
        import tempfile
        with tempfile.TemporaryDirectory() as temporary:
            store = NormalizedDatasetStore(Path(temporary)/"test.sqlite3", required_uid=None)
            calls = []
            worker = sync_worker.SyncWorker(_configuration(date(2025, 1, 1)),
                store=store, emit=lambda _: None)
            def cycle(_config, start, end):
                calls.append((start, end))
                worker.request_stop()
                return sync_worker.SyncCycleOutcome(True, committed=_committed())
            worker._cycle = cycle
            self.assertTrue(worker._scheduled_cycle(date(2025, 4, 1)).succeeded)
            self.assertEqual(calls, [(date(2025, 1, 1), date(2025, 2, 1))])
            state = store.prepare_sync_state(date(2025, 1, 1), date(2025, 4, 1))
            self.assertEqual(state.backfill_next_day, date(2025, 2, 1))

    def test_conservative_failures_block_equivalent_history_login(self):
        for code in ("data_probe_auth_failed", "auth_tls_verification_failed", "data_probe_consumption_parse_failed",
                     "auth_transport_failed", "data_probe_consumption_export_status_failed"):
            with self.subTest(code=code):
                worker, clock, runs = self.worker(15, until=7200)
                worker._current_day_cycle = lambda *_: sync_worker.SyncCycleOutcome(False, code=code)
                worker._run()
                self.assertEqual(clock.waits, [3600, 3600, 3600])
                self.assertFalse(any(kind == "history" for kind, _ in runs))

    def test_waits_are_interruptible_and_stop_does_not_start_history(self):
        for minutes, failure in ((15, None), (720, None), (60, "auth_operation_timeout")):
            entered = threading.Event()
            def current(*_):
                entered.set()
                return (sync_worker.SyncCycleOutcome(False, code=failure) if failure
                        else sync_worker.SyncCycleOutcome(True, committed=_committed()))
            history = mock.Mock(return_value=sync_worker.SyncCycleOutcome(True, committed=_committed()))
            worker = sync_worker.SyncWorker(replace(_configuration(), sync_interval_minutes=minutes),
                store=mock.Mock(), current_day_cycle=current, cycle=history, emit=lambda _: None)
            worker.start()
            self.assertTrue(entered.wait(1))
            started = time.monotonic()
            self.assertTrue(worker.stop(1))
            self.assertLess(time.monotonic()-started, 1)
        worker, clock, runs = self.worker()
        def stop_current(*_):
            worker._stop_event.set()
            return sync_worker.SyncCycleOutcome(True, committed=_committed())
        worker._current_day_cycle = stop_current
        worker._run()
        self.assertFalse(runs)

    def test_interval_runtime_and_manifest_translation_contract(self):
        base = {"cez_sync_enabled": True, "cez_username": "test-user", "cez_password": "test-password", "cez_elm": "test-meter"}
        self.assertEqual(runtime_config._load_sync_configuration(base).sync_interval_minutes, 60)
        for value in (15, 60, 720):
            self.assertEqual(runtime_config._load_sync_configuration({**base, "sync_interval_minutes": value}).sync_interval_minutes, value)
        for value in (14, 721, True, False, 60.0, "60", None):
            with self.subTest(value_type=type(value).__name__), self.assertRaises(runtime_config.DiscoveryConfigurationError) as error:
                runtime_config._load_sync_configuration({**base, "sync_interval_minutes": value})
            self.assertEqual(error.exception.code, "sync_config_invalid_interval")
            with self.assertRaises(runtime_config.DiscoveryConfigurationError):
                replace(_configuration(), sync_interval_minutes=value)
        import re
        root = Path(__file__).resolve().parents[2]
        manifest = (root/"cez_pnd_collector/config.yaml").read_text(encoding="utf-8")
        options, schema = manifest.split("options:\n", 1)[1].split("schema:\n", 1)
        self.assertIn("  sync_interval_minutes: 60\n", options)
        self.assertIn("  sync_interval_minutes: int(15,720)\n", schema)
        translations = [(root/f"cez_pnd_collector/translations/{language}.yaml").read_text(encoding="utf-8") for language in ("cs", "en")]
        keys = lambda value: set(re.findall(r"^  ([a-z_]+):", value, re.M))
        self.assertEqual(keys(translations[0]), keys(translations[1]))
        self.assertEqual(keys(translations[0]), keys(schema))
        for translation in translations:
            block = translation.split("  sync_interval_minutes:\n", 1)[1].split("  cez_sync_enabled:", 1)[0]
            self.assertIn("    name:", block)
            self.assertIn("    description:", block)

    def test_join_budget_and_app_timeout_contract(self):
        import re
        from collector_service import shutdown
        root = Path(__file__).resolve().parents[2]
        manifest = (root/"cez_pnd_collector/config.yaml").read_text(encoding="utf-8")
        self.assertEqual(sync_worker.WORKER_STOP_TIMEOUT_SECONDS, 8)
        app_timeout = int(re.search(r"^timeout: ([0-9]+)$", manifest, re.M)[1])
        self.assertEqual(app_timeout, 15)
        self.assertEqual(shutdown.HARD_STOP_SECONDS, 10)
        self.assertEqual(shutdown.COOPERATIVE_STOP_SECONDS, 8)
        self.assertEqual(shutdown.FORCED_EXIT_STATUS, 70)
        self.assertGreater(app_timeout, shutdown.HARD_STOP_SECONDS)
        self.assertEqual(app_timeout - shutdown.HARD_STOP_SECONDS, 5)
        worker, _, _ = self.worker()
        worker._thread = mock.Mock()
        worker._thread.is_alive.return_value = True
        self.assertFalse(worker.stop())
        worker._thread.join.assert_called_once_with(8.0)
