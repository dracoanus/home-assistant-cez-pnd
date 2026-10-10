"""Offline process shutdown and SQLite crash recovery regression tests."""
from __future__ import annotations

from datetime import timedelta
import atexit
import http.client
import json
import os
from pathlib import Path
import signal
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock

from collector_service import shutdown, server, security_files
from collector_service.dataset_store import NormalizedDatasetStore
from collector_service.sync_worker import SyncWorker, SyncCycleOutcome
from collector.tests.test_sync_worker import _configuration, _committed
from collector.tests.test_dataset_store import _parsed, START
from collector_service.cez_csv_models import PndChannel, IntervalQuality
from decimal import Decimal


def _ready(directory: Path, value: str = "ready") -> None:
    (directory / "ready").write_text(value, encoding="ascii")


def _child(mode: str, directory: Path) -> int:
    guard = shutdown.ShutdownWatchdog()
    signal.signal(signal.SIGTERM, server._shutdown_signal_handler(guard))
    blocked = threading.Event()

    def hang(*args, **kwargs):
        _ready(directory)
        blocked.wait()

    if mode.startswith("sqlite_"):
        store = NormalizedDatasetStore(directory / "dataset.sqlite3", required_uid=None)
        original = store._connect

        class Interruption:
            def __init__(self):
                self.connection = original()
            def execute(self, sql, parameters=()):
                if mode == "sqlite_before" and sql == "BEGIN IMMEDIATE":
                    hang()
                result = self.connection.execute(sql, parameters)
                if mode == "sqlite_during" and "INSERT INTO measurements" in sql:
                    hang()
                return result
            def commit(self):
                self.connection.commit()
                if mode == "sqlite_after":
                    hang()
            def __getattr__(self, name):
                return getattr(self.connection, name)

        store._connect = Interruption
        values = ((Decimal("2"), IntervalQuality.VALID),)
        job = lambda: store.commit_dataset(_parsed(PndChannel.CONSUMPTION, values),
            _parsed(PndChannel.PRODUCTION, values), collected_at=START + timedelta(hours=1))
        thread = threading.Thread(target=job, daemon=True)
        thread.start()
        try:
            blocked.wait()
        except KeyboardInterrupt:
            blocked.wait()  # The real guard owns termination during the transaction.
        return 1

    if mode == "temp_write":
        # Interruption after a private write, before atomic replacement.
        path = directory / "pairing-state.json"
        original_fstat = os.fstat
        def owned_fstat(fd):
            result = original_fstat(fd)
            return SimpleNamespace(st_mode=result.st_mode, st_uid=2000)
        with mock.patch.object(security_files.os, "replace", side_effect=hang), \
             mock.patch.object(security_files.os, "fstat", side_effect=owned_fstat):
            thread = threading.Thread(target=lambda: security_files.atomic_write_private(
                path, b"synthetic", maximum_bytes=64), daemon=True)
            thread.start()
            try:
                blocked.wait()
            except KeyboardInterrupt:
                blocked.wait()
        return 1

    def operation(*_):
        if mode == "dns":
            with mock.patch.object(socket, "getaddrinfo", side_effect=hang):
                socket.getaddrinfo("offline.invalid", 443)
        elif mode == "connect":
            with mock.patch.object(socket, "create_connection", side_effect=hang):
                socket.create_connection(("127.0.0.1", 1))
        elif mode == "tls":
            with mock.patch.object(ssl.SSLContext, "wrap_socket", side_effect=hang):
                ssl.create_default_context().wrap_socket(None)
        elif mode == "write":
            with mock.patch.object(http.client.HTTPConnection, "send", side_effect=hang):
                http.client.HTTPConnection("offline.invalid").send(b"bounded")
        elif mode == "headers":
            with mock.patch.object(http.client.HTTPResponse, "begin", side_effect=hang):
                http.client.HTTPResponse(mock.Mock()).begin()
        elif mode == "body":
            with mock.patch.object(http.client.HTTPResponse, "read", side_effect=hang):
                http.client.HTTPResponse(mock.Mock()).read(64)
        elif mode in {"logger_lock", "logger_flush"}:
            from collector_service import structured_logging as logging
            if mode == "logger_lock":
                logging._WRITE_LOCK.acquire()
                _ready(directory)
                logging.write_json_line('{"event":"synthetic"}', flush=True)
            else:
                class Writer:
                    def write(self, _text):
                        pass
                    def flush(self):
                        hang()
                logging.write_json_line('{"event":"synthetic"}', file=Writer(), flush=True)
        elif mode == "retry":
            return SyncCycleOutcome(False, code="auth_operation_timeout")
        return SyncCycleOutcome(True, committed=_committed())

    worker = SyncWorker(_configuration(), current_day_cycle=operation,
        cycle=operation, store=NormalizedDatasetStore(directory / "sync.sqlite3", required_uid=None),
        emit=lambda _: None)
    original_wait = worker._wait

    def waiting(delay):
        _ready(directory)
        return original_wait(delay)

    worker._wait = waiting
    api_server = server.CollectorHttpServer(("127.0.0.1", 0), server.CollectorRequestHandler)
    config = SimpleNamespace(sync=None if mode in {"idle", "event", "handler", "finalize"} else _configuration(),
        source="test", managed_identity=None)
    event_waiting = threading.Event()
    if config.sync is None:
        if mode == "event":
            broker = api_server.event_broker
            cursor = broker.wait(None).cursor
            original_wait_for = broker._condition.wait_for
            def wait_for(predicate, timeout):
                event_waiting.set()
                return original_wait_for(predicate, timeout)
            broker._condition.wait_for = wait_for
            threading.Thread(target=lambda: broker.wait(cursor), daemon=True).start()
        elif mode == "handler":
            # A request blocked on headers is interrupted by server shutdown.
            client, accepted = socket.socketpair()
            client.sendall(b"GET /api/v1/health HTTP/1.1\r\n")
            api_server.process_request(accepted, ("127.0.0.1", 1))
        elif mode == "finalize":
            atexit.register(blocked.wait)
        original_serve = api_server.serve_forever
        def serve(**kwargs):
            if mode == "event" and not event_waiting.wait(2):
                raise RuntimeError("event waiter not ready")
            _ready(directory)
            return original_serve(**kwargs)
        api_server.serve_forever = serve
    with mock.patch("collector_service.sync_worker.SyncWorker", return_value=worker):
        return server._serve(config, api_server, None, None, guard)


@unittest.skipUnless(os.name == "posix", "requires Linux/POSIX SIGTERM process execution")
class ShutdownProcessTests(unittest.TestCase):
    def run_child(self, mode, directory, expected):
        root = Path(__file__).resolve().parents[2]
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(root) + os.pathsep + str(root / "collector")
        child = subprocess.Popen([sys.executable, "-B", str(Path(__file__).resolve()),
            "--child", mode, str(directory)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=environment)
        try:
            deadline = time.monotonic() + 10
            while not (directory / "ready").exists():
                if child.poll() is not None:
                    output, error = child.communicate()
                    self.fail(f"child failed before barrier: {output!r} {error!r}")
                self.assertLess(time.monotonic(), deadline, "child barrier not reached")
                time.sleep(.01)
            started = time.monotonic()
            child.send_signal(signal.SIGTERM)
            # Repeat signals cannot extend the first hard deadline.
            if expected == shutdown.FORCED_EXIT_STATUS:
                child.send_signal(signal.SIGTERM)
            output, error = child.communicate(timeout=14)
            elapsed = time.monotonic() - started
            self.assertEqual(child.returncode, expected, error.decode(errors="replace"))
            self.assertLess(elapsed, 14)
            if expected:
                self.assertGreaterEqual(elapsed, 9.5)
            self.assertNotIn(b"Traceback", error)
            self.assertNotIn(b"forced_shutdown", output)
            for secret in (b"private-user", b"private-password", b"private-elm"):
                self.assertNotIn(secret, output + error)
            print(f"shutdown {mode}: {elapsed:.3f}s exit={child.returncode}")
            self.assertIsNotNone(child.poll())
        finally:
            if child.poll() is None:
                child.kill()
            child.communicate()

    def test_blocked_dns(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.run_child("dns", Path(tmp), 70)

    def test_blocked_connect(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.run_child("connect", Path(tmp), 70)

    def test_blocked_tls(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.run_child("tls", Path(tmp), 70)

    def test_blocked_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.run_child("write", Path(tmp), 70)

    def test_blocked_headers(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.run_child("headers", Path(tmp), 70)

    def test_blocked_body(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.run_child("body", Path(tmp), 70)

    def test_blocked_logger_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.run_child("logger_lock", Path(tmp), 70)

    def test_blocked_logger_flush(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.run_child("logger_flush", Path(tmp), 70)

    def test_blocked_interpreter_finalization(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.run_child("finalize", Path(tmp), 70)

    def test_graceful_idle_scheduler_retry_history_event_and_handler(self):
        for mode in ("idle", "scheduler", "retry", "history", "event", "handler"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                self.run_child(mode, Path(tmp), 0)

    def test_sqlite_crash_recovery(self):
        for mode in ("sqlite_before", "sqlite_during", "sqlite_after"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                path = directory / "dataset.sqlite3"
                store = NormalizedDatasetStore(path, required_uid=None)
                values = ((Decimal("1"), IntervalQuality.VALID),)
                old = store.commit_dataset(_parsed(PndChannel.CONSUMPTION, values),
                    _parsed(PndChannel.PRODUCTION, values), collected_at=START)
                self.run_child(mode, directory, 70)
                with sqlite3.connect(path) as connection:
                    self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone()[0], "ok")
                    journal = connection.execute("PRAGMA journal_mode").fetchone()[0]
                    self.assertEqual(journal, "delete")
                    print(f"SQLite {mode}: journal_mode={journal}")
                status = store.read_status()
                page = store.read_measurements("2026-09-01T00:00:00Z", "2026-09-01T01:00:00Z", limit=10)
                self.assertEqual(len(page.rows), 2)
                expected_value = "2" if mode == "sqlite_after" else "1"
                self.assertTrue(all(row.value_kwh == expected_value for row in page.rows))
                self.assertTrue(all(row.revision == status.revision for row in page.rows))
                if mode != "sqlite_after":
                    self.assertEqual(status.revision, old.revision)
                store.commit_dataset(_parsed(PndChannel.CONSUMPTION, values),
                    _parsed(PndChannel.PRODUCTION, values), collected_at=START + timedelta(hours=2))


class ShutdownUnitTests(unittest.TestCase):
    def test_first_arm_wins_and_forced_path_is_silent(self):
        clock = [100]
        with mock.patch.object(shutdown.os, "_exit") as terminate, \
             mock.patch.object(shutdown.time, "monotonic", side_effect=lambda: clock[0]), \
             mock.patch.object(shutdown.threading, "Thread") as thread:
            guard = shutdown.ShutdownWatchdog()
            guard.arm()
            guard.arm()
            self.assertEqual(guard.deadline, 110)
            self.assertEqual(guard.cleanup_deadline, 108)
            self.assertEqual(guard.remaining(), 8)
            clock[0] = 111
            thread.call_args.kwargs["target"]()
            terminate.assert_called_once_with(70)
            self.assertTrue(thread.call_args.kwargs["daemon"])

    def test_all_components_stop_before_join_and_share_deadline(self):
        actions = []
        guard = mock.Mock(cleanup_deadline=123)
        guard.remaining.side_effect = [8, 8, 7, 6, 5, 4, 3]
        http = mock.Mock()
        http.server_close.return_value = True
        http.begin_shutdown.side_effect = lambda: actions.append("http_stop")
        http.server_close.side_effect = lambda **kw: (actions.append("http_join"), True)[1]
        worker = mock.Mock()
        worker.request_stop.side_effect = lambda: actions.append("sync_stop")
        worker.stop.side_effect = lambda **kw: (actions.append("sync_join"), True)[1]
        pairing = mock.Mock()
        pairing.request_stop.side_effect = lambda: actions.append("pairing_stop")
        pairing.stop.return_value = True
        config = SimpleNamespace(sync=_configuration(), managed_identity=None, source="test")
        with mock.patch("collector_service.sync_worker.SyncWorker", return_value=worker), \
             mock.patch.object(server, "write_json_line"):
            self.assertEqual(server._serve(config, http, pairing, None, guard), 0)
        self.assertEqual(actions[:4], ["sync_stop", "pairing_stop", "http_stop", "http_join"])
        http.server_close.assert_called_once_with(deadline=123)
        worker.stop.assert_called_once_with(timeout=6)
        pairing.stop.assert_called_once_with(timeout=4)

    def test_pairing_stop_wakes_wait_and_does_not_start_when_pre_stopped(self):
        from collector_service.pairing import PairingDiscoveryWorker
        worker = PairingDiscoveryWorker(mock.Mock(), mock.Mock(), mock.Mock(), lambda _: None)
        published = threading.Event()
        worker._publish_new = published.set
        worker.start()
        self.assertTrue(published.wait(1))
        worker.request_stop()
        self.assertTrue(worker.stop(timeout=1))
        worker = PairingDiscoveryWorker(mock.Mock(), mock.Mock(), mock.Mock(), lambda _: None)
        worker._publish_new = mock.Mock()
        worker.request_stop()
        worker.start()
        self.assertTrue(worker.stop(timeout=1))
        worker._publish_new.assert_not_called()

    def test_stop_at_dispatch_prevents_current_operation(self):
        operation = mock.Mock()
        worker = SyncWorker(_configuration(), current_day_cycle=operation,
            store=mock.Mock(), emit=lambda _: None)
        worker._emit = lambda _: worker.request_stop()
        worker._scheduled_current_day(START.date())
        operation.assert_not_called()

    def test_guard_deadline_cannot_be_disarmed(self):
        self.assertEqual(shutdown.HARD_STOP_SECONDS, 10)
        self.assertEqual(shutdown.COOPERATIVE_STOP_SECONDS, 8)
        self.assertFalse(hasattr(shutdown.ShutdownWatchdog, "disarm"))

    def test_expired_budget_starts_no_new_cleanup_or_logging(self):
        guard = mock.Mock(cleanup_deadline=123)
        guard.remaining.return_value = 0
        http, pairing = mock.Mock(), mock.Mock()
        config = SimpleNamespace(sync=None, managed_identity=None, source="test")
        with mock.patch.object(server, "write_json_line") as logging, \
             mock.patch.object(server.threading, "Event"):
            self.assertEqual(server._serve(config, http, pairing, None, guard), 1)
        pairing.request_stop.assert_called_once_with()
        http.begin_shutdown.assert_not_called()
        http.server_close.assert_not_called()
        pairing.stop.assert_not_called()
        # Only the pre-shutdown startup message was permitted.
        self.assertEqual(logging.call_count, 1)


@unittest.skipUnless(os.name == "posix", "requires directory FDs and O_NOFOLLOW")
class TemporaryRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.directory.chmod(0o700)
        original_stat, original_fstat = os.stat, os.fstat
        def owned(result):
            return SimpleNamespace(st_mode=result.st_mode, st_uid=2000,
                st_dev=result.st_dev, st_ino=result.st_ino)
        self.patches = (
            mock.patch.object(security_files, "PAIRING_RECOVERY_DIRECTORY", self.directory),
            mock.patch.object(security_files.os, "stat", side_effect=lambda *a, **k: owned(original_stat(*a, **k))),
            mock.patch.object(security_files.os, "fstat", side_effect=lambda *a, **k: owned(original_fstat(*a, **k))),
        )
        for patch in self.patches:
            patch.start()
            self.addCleanup(patch.stop)

    def orphan(self):
        path = self.directory / (".pairing-state.json." + "a" * 32 + ".tmp")
        path.write_bytes(b"synthetic")
        path.chmod(0o600)
        return path

    def test_orphan_removed_unknown_and_sqlite_untouched(self):
        orphan = self.orphan()
        for name in ("unknown.tmp", "cez-pnd.sqlite3-journal", ".identity.json." + "b" * 32 + ".tmp"):
            (self.directory / name).write_bytes(b"synthetic")
        security_files.recover_pairing_temporaries()
        self.assertFalse(orphan.exists())
        self.assertEqual(len(list(self.directory.iterdir())), 3)

    def test_symlink_rejected_not_followed(self):
        target = self.directory / "unknown.tmp"
        target.write_bytes(b"synthetic")
        link = self.orphan()
        link.unlink()
        link.symlink_to(target)
        with self.assertRaises(ValueError):
            security_files.recover_pairing_temporaries()
        self.assertTrue(target.exists())

    def test_wrong_owner_rejected(self):
        self.orphan()
        with mock.patch.object(security_files.os, "stat", return_value=SimpleNamespace(
            st_mode=0o100600, st_uid=2001)):
            with self.assertRaises(ValueError):
                security_files.recover_pairing_temporaries()

    def test_count_bounded_before_deletion(self):
        orphan = self.orphan()
        for index in range(security_files.MAX_RECOVERY_ENTRIES):
            (self.directory / f"unknown-{index}.tmp").write_bytes(b"synthetic")
        with self.assertRaises(ValueError):
            security_files.recover_pairing_temporaries()
        self.assertTrue(orphan.exists())

    def test_parent_symlink_rejected(self):
        link = self.directory / "link"
        link.symlink_to(self.directory, target_is_directory=True)
        with mock.patch.object(security_files, "PAIRING_RECOVERY_DIRECTORY", link):
            with self.assertRaises(OSError):
                security_files.recover_pairing_temporaries()

    def test_forced_write_leaves_recoverable_private_orphan(self):
        ShutdownProcessTests.run_child(self, "temp_write", self.directory, 70)
        orphan = list(self.directory.glob(".pairing-state.json.*.tmp"))
        self.assertEqual(len(orphan), 1)
        security_files.recover_pairing_temporaries()
        self.assertFalse(orphan[0].exists())


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--child":
        raise SystemExit(_child(sys.argv[2], Path(sys.argv[3])))
    unittest.main()
