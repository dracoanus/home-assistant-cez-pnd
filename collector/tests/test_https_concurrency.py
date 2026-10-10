"""Offline verified-TLS concurrency tests; no external connections."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import http.client
import io
import ipaddress
import json
from pathlib import Path
import socket
import ssl
import threading
import time
import unittest
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from collector_service.api import CollectorApi, TokenVerifier, SYNTHETIC_METER_ID
from collector_service.server import CollectorHttpServer, CollectorRequestHandler
from collector_service.event_broker import SyncEvent
from collector_service.structured_logging import structured_event_json, write_json_line
from collector.tests import test_api


class HttpsConcurrencyTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_api.CollectorApiTest()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        directory = Path(self.fixture.temporary.name)
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        now = datetime.now(timezone.utc)
        certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
            .sign(key, hashes.SHA256()))
        cert_path, key_path = directory / "test.pem", directory / "test-key.pem"
        cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(cert_path, key_path)
        self.context = ssl.create_default_context(cafile=str(cert_path))
        self.server = CollectorHttpServer(("127.0.0.1", 0), CollectorRequestHandler)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True, do_handshake_on_connect=False)
        self.server.collector_api = CollectorApi(self.fixture.verifier, self.fixture.store,
            event_broker=self.server.event_broker)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": .01})
        self.thread.start()
        self.addCleanup(self.stop)
        self.target = f"/api/v1/events?meter_id={SYNTHETIC_METER_ID}"

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)

    def get(self, path):
        connection = http.client.HTTPSConnection("127.0.0.1", self.server.server_port,
            context=self.context, timeout=3)
        try:
            connection.request("GET", path, headers=self.fixture.auth)
            response = connection.getresponse()
            return response.status, response.read(), dict(response.getheaders())
        finally:
            connection.close()

    def test_two_waiters_leave_api_capacity_and_shutdown_promptly(self):
        broker = self.server.event_broker
        cursor = broker.wait(None).cursor
        registered = threading.Event()
        original = broker._condition.wait_for
        def wait_for(predicate, timeout):
            if broker._waiters == 2:
                registered.set()
            return original(predicate, timeout)
        with mock.patch.object(broker._condition, "wait_for", side_effect=wait_for), ThreadPoolExecutor(2) as pool:
            futures = [pool.submit(self.get, self.target + "&cursor=" + cursor) for _ in range(2)]
            try:
                self.assertTrue(registered.wait(2))
                for path in ("/api/v1/health", f"/api/v1/status?meter_id={SYNTHETIC_METER_ID}",
                    f"/api/v1/measurements?meter_id={SYNTHETIC_METER_ID}&start=2026-08-01T00:00:00Z&end=2026-08-01T01:00:00Z"):
                    self.assertEqual(self.get(path)[0], 200)
                self.assertEqual(self.get(self.target + "&cursor=" + cursor)[0], 429)
            finally:
                started = time.monotonic()
                self.stop()
            for future in futures:
                try:
                    result = future.result(2)
                    self.assertEqual(result[0], 503)
                except (OSError, http.client.HTTPException):
                    pass  # Shutdown may close the TLS stream before the 503 is written.
            self.assertLess(time.monotonic() - started, 2)
            self.assertEqual(broker._waiters, 0)
            self.assertFalse(self.server._handlers)

    def test_stalled_tls_does_not_block_health_and_capacity_is_bounded(self):
        sockets = []
        try:
            sockets.append(socket.create_connection(self.server.server_address, timeout=2))
            self.assertEqual(self.get("/api/v1/health")[0], 200)
            for _ in range(7):
                sockets.append(socket.create_connection(self.server.server_address, timeout=2))
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                with self.server._handlers_lock:
                    if len(self.server._handlers) == 8:
                        break
                time.sleep(.01)
            with self.server._handlers_lock:
                self.assertEqual(len(self.server._handlers), 8)
            with socket.create_connection(self.server.server_address, timeout=2) as extra:
                self.assertEqual(extra.recv(1), b"")
            self.assertLessEqual(len(self.server._handlers), 8)
        finally:
            for connection in sockets:
                connection.close()

    def test_timeout_wire_response_is_empty_and_publish_is_delivered(self):
        broker = self.server.event_broker
        cursor = broker.wait(None).cursor
        original = broker.wait
        with mock.patch.object(broker, "wait", side_effect=lambda c: original(c, timeout=0)):
            status, body, headers = self.get(self.target + "&cursor=" + cursor)
        self.assertEqual((status, body), (204, b""))
        self.assertNotIn("Content-Length", headers)
        broker.publish(SyncEvent("current_day", "succeeded", "ds_" + "a" * 32))
        status, body, _ = self.get(self.target + "&cursor=" + cursor)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["event"], "sync_finished")
        self.assertEqual(json.loads(body)["dataset_revision"], "ds_" + "a" * 32)

    def test_sync_worker_wakes_authenticated_waiter_on_same_server_broker(self):
        from collector_service.sync_worker import SyncWorker, SyncCycleOutcome
        from collector.tests.test_sync_worker import _configuration, _committed
        from collector_service.cez_csv_models import PndChannel
        broker = self.server.event_broker
        cursor = broker.wait(None).cursor
        entered = threading.Event()
        original = broker._condition.wait_for
        def wait_for(predicate, timeout):
            entered.set()
            return original(predicate, timeout)
        def cycle(*_args):
            self.fixture.store.commit_dataset(
                test_api._profile(PndChannel.CONSUMPTION),
                test_api._profile(PndChannel.PRODUCTION),
                collected_at=test_api.START,
            )
            return SyncCycleOutcome(True, committed=_committed())
        worker = SyncWorker(_configuration(), store=self.fixture.store,
            cycle=cycle, emit=lambda _event: None, publish=broker.publish)
        with mock.patch.object(broker._condition, "wait_for", side_effect=wait_for), ThreadPoolExecutor(1) as pool:
            response = pool.submit(self.get, self.target + "&cursor=" + cursor)
            try:
                self.assertTrue(entered.wait(2))
                worker._scheduled_current_day(test_api.START.date())
                status, body, _headers = response.result(2)
            finally:
                if not response.done():
                    broker.close()
        self.assertEqual(status, 200)
        self.assertLessEqual(len(body), 4096)
        payload = json.loads(body)
        self.assertEqual(set(payload), {"schema_version", "event", "cursor",
            "sync_kind", "sync_result", "dataset_revision"})
        self.assertEqual(payload["event"], "sync_finished")
        self.assertEqual(payload["sync_kind"], "current_day")
        self.assertEqual(payload["sync_result"], "succeeded")
        self.assertEqual(payload["dataset_revision"], self.fixture.store.read_status().revision)
        self.assertNotEqual(payload["cursor"], cursor)
        previous = self.fixture.store.read_status()
        failure_cursor = payload["cursor"]
        worker = SyncWorker(_configuration(), store=self.fixture.store,
            cycle=lambda *_args: SyncCycleOutcome(False, code="data_probe_auth_failed"),
            emit=lambda _event: None, publish=broker.publish)
        try:
            worker._scheduled_current_day(test_api.START.date())
            status, body, _headers = self.get(self.target + "&cursor=" + failure_cursor)
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body)["sync_result"], "failed")
            self.assertEqual(json.loads(body)["dataset_revision"], previous.revision)
            self.assertEqual(self.fixture.store.read_status(), previous)
        finally:
            broker.close()

    def test_sqlite_writes_and_reads_are_independent_of_waiters(self):
        def read():
            return self.get(f"/api/v1/status?meter_id={SYNTHETIC_METER_ID}")[0]
        with ThreadPoolExecutor(4) as pool:
            futures = [pool.submit(read) for _ in range(3)]
            self.fixture.store.record_attempt(datetime.now(timezone.utc))
            self.assertEqual([future.result(3) for future in futures], [200] * 3)

    def test_pairing_transitions_during_ordinary_https_traffic(self):
        from collector_service import pairing
        from copy import deepcopy
        from types import SimpleNamespace
        import hashlib

        credentials = pairing.ManagedCredentialStore(SYNTHETIC_METER_ID,
            Path(self.fixture.temporary.name) / "state.json")
        # Model production atomic file replacement without requiring UID 2000 on Windows.
        state_lock = threading.Lock()
        state = pairing._empty_state()
        def read():
            with state_lock:
                return deepcopy(state)
        def write(value):
            nonlocal state
            pairing._validate_state(value)
            with state_lock:
                state = deepcopy(value)
        credentials._read = read
        credentials._write = write
        self.server.collector_api = CollectorApi(credentials, self.fixture.store,
            event_broker=self.server.event_broker)
        worker = pairing.PairingDiscoveryWorker(SimpleNamespace(), credentials, mock.Mock(), lambda _: None)
        self.server.pairing_api = pairing.PairingApi(credentials, worker.finalize)
        bootstrap = credentials.create_bootstrap()
        def post(operation, body):
            connection = http.client.HTTPSConnection("127.0.0.1", self.server.server_port,
                context=self.context, timeout=3)
            try:
                headers = {**self.fixture.auth, "Content-Type": "application/json"}
                connection.request("POST", pairing.PAIRING_PREFIX + "/" + operation, json.dumps(body), headers)
                response = connection.getresponse()
                response.read()
                return response.status
            finally:
                connection.close()
        self.assertEqual(self.get("/api/v1/health")[0], 401)
        with ThreadPoolExecutor(2) as pool:
            traffic = pool.submit(lambda: [self.get("/api/v1/health")[0] for _ in range(12)])
            self.assertEqual(post("claim", {"pairing_schema_version": 1,
                "pairing_id": bootstrap.pairing_id, "pairing_secret": bootstrap.secret,
                "api_token_sha256": hashlib.sha256(self.fixture.token.encode()).hexdigest()}), 200)
            self.assertEqual(self.get("/api/v1/health")[0], 401)
            self.assertEqual(post("activate", {}), 200)
            self.assertEqual(self.get("/api/v1/health")[0], 200)
            self.assertEqual(post("finalize", {}), 200)
            self.assertTrue(set(traffic.result(3)) <= {200, 401})
        self.assertIsNone(read()["pairing_id"])
        self.assertEqual(self.get("/api/v1/health")[0], 200)

    def test_absolute_deadline_closes_incomplete_request(self):
        from collector_service import server
        with mock.patch.object(server, "REQUEST_DEADLINE_SECONDS", .1):
            raw = socket.create_connection(self.server.server_address, timeout=2)
            with self.context.wrap_socket(raw, server_hostname="127.0.0.1") as client:
                client.settimeout(2)
                client.sendall(b"GET /api/v1/health HTTP/1.1\r\n")
                started = time.monotonic()
                self.assertEqual(client.recv(1), b"")
                self.assertLess(time.monotonic() - started, 2)


class ConcurrentLoggingTests(unittest.TestCase):
    def test_complete_json_lines(self):
        output = io.StringIO()
        def emit(index):
            write_json_line(structured_event_json({"event": "fixed", "index": index}), file=output)
        with ThreadPoolExecutor(8) as pool:
            list(pool.map(emit, range(200)))
        rows = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(len(rows), 200)
        self.assertEqual({row["index"] for row in rows}, set(range(200)))
