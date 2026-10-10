"""Offline broker and authenticated long-poll contract regressions."""

from concurrent.futures import ThreadPoolExecutor
import hashlib
import io
import json
import secrets
import threading
import unittest
from unittest import mock

from collector_service.api import CollectorApi, SYNTHETIC_METER_ID, TokenVerifier
from collector_service.event_broker import (
    EventBroker, EventBrokerError, SyncEvent, MAX_SEQUENCE, parse_event_cursor,
)


TEST_REVISION = "ds_" + "a" * 32
OTHER_REVISION = "ds_" + "b" * 32


class EventBrokerTests(unittest.TestCase):
    def test_initial_cursor_publication_coalescing_and_generation_reset(self):
        broker = EventBroker()
        initial = broker.wait(None)
        self.assertEqual(initial.as_dict(), {
            "schema_version": 1, "event": "state_reset", "cursor": initial.cursor,
        })
        self.assertEqual(parse_event_cursor(initial.cursor)[1], 0)
        first = SyncEvent("current_day", "succeeded", TEST_REVISION)
        broker.publish(first)
        broker.publish(SyncEvent("historical_correction", "failed", OTHER_REVISION))
        latest = broker.wait(initial.cursor)
        self.assertEqual(parse_event_cursor(latest.cursor)[1], 2)
        self.assertEqual(latest.event.sync_result, "failed")
        self.assertEqual(latest.event.dataset_revision, OTHER_REVISION)
        self.assertIsNone(EventBroker().wait(latest.cursor).event)
        generation, _ = parse_event_cursor(initial.cursor)
        self.assertIsNone(broker.wait(f"ev1_{generation}_999").event)
        with self.assertRaises(Exception):
            first.sync_result = "failed"

    def test_cursor_validation_and_event_allowlist(self):
        broker = EventBroker()
        for cursor in ("", "secret", "ev1_" + "a" * 32 + "_01",
                       "ev1_" + "a" * 32 + "_-1", "x" * 100,
                       "ev1_" + "a" * 32 + "_" + str(MAX_SEQUENCE + 1)):
            with self.subTest(cursor_type=type(cursor).__name__), self.assertRaises(EventBrokerError) as raised:
                broker.wait(cursor)
            self.assertEqual(str(raised.exception), "invalid_event_cursor")
        for kind, result, revision in (("secret", "failed", None),
                                        ("current_day", "secret", None),
                                        ("current_day", "failed", True),
                                        ("current_day", "failed", -1),
                                        ("current_day", "failed", "secret")):
            with self.assertRaises(ValueError):
                SyncEvent(kind, result, revision)

    def test_revision_contract_is_shared_and_preserved(self):
        from collector_service.api import REVISION_PATTERN as api_pattern
        from collector_service.event_broker import REVISION_PATTERN as event_pattern
        self.assertIs(api_pattern, event_pattern)
        for revision in ("ds_ab", TEST_REVISION, "ds_" + "f" * 77, None):
            with self.subTest(revision_type=type(revision).__name__):
                broker = EventBroker()
                cursor = broker.wait(None).cursor
                broker.publish(SyncEvent("current_day", "failed", revision))
                body = broker.wait(cursor).as_dict()
                self.assertEqual(body["dataset_revision"], revision)
                self.assertNotEqual(body["cursor"], revision)
                self.assertLess(len(json.dumps(body).encode()), 4096)
        for revision in (0, 1, True, False, "", "ds_", "ds_a", "ds_G0",
                         "ds_" + "a" * 78, TEST_REVISION + "\n", " " + TEST_REVISION,
                         "ev1_" + "a" * 32 + "_1", "private-test-value"):
            with self.subTest(revision_type=type(revision).__name__), self.assertRaises(ValueError) as error:
                SyncEvent("current_day", "failed", revision)
            self.assertEqual(str(error.exception), "invalid event revision")

    def test_timeout_is_bounded_and_empty(self):
        broker = EventBroker()
        cursor = broker.wait(None).cursor
        self.assertIsNone(broker.wait(cursor, timeout=0))
        for timeout in (-1, 26, True, float("nan")):
            with self.assertRaises(ValueError):
                broker.wait(cursor, timeout=timeout)

    def test_publish_and_close_wake_waiters_without_lost_wakeup(self):
        for close in (False, True):
            broker = EventBroker()
            cursor = broker.wait(None).cursor
            registered = threading.Event()
            original = broker._condition.wait_for

            def wait_for(predicate, timeout):
                registered.set()
                return original(predicate, timeout)

            with mock.patch.object(broker._condition, "wait_for", side_effect=wait_for), ThreadPoolExecutor(1) as executor:
                future = executor.submit(broker.wait, cursor)
                self.assertTrue(registered.wait(1))
                if close:
                    broker.close()
                    with self.assertRaises(EventBrokerError) as raised:
                        future.result(1)
                    self.assertEqual(raised.exception.code, "event_broker_stopping")
                else:
                    broker.publish(SyncEvent("current_day", "failed", None))
                    self.assertEqual(future.result(1).event.sync_result, "failed")
            self.assertEqual(broker._waiters, 0)

    def test_waiter_capacity_and_no_waiter_leak(self):
        broker = EventBroker()
        cursor = broker.wait(None).cursor
        registered = threading.Event()
        original = broker._condition.wait_for

        def wait_for(predicate, timeout):
            if broker._waiters == 2:
                registered.set()
            return original(predicate, timeout)

        with mock.patch.object(broker._condition, "wait_for", side_effect=wait_for), ThreadPoolExecutor(2) as executor:
            futures = [executor.submit(broker.wait, cursor) for _ in range(2)]
            try:
                self.assertTrue(registered.wait(1))
                with self.assertRaises(EventBrokerError) as raised:
                    broker.wait(cursor)
                self.assertEqual(raised.exception.code, "event_waiter_limit")
            finally:
                broker.publish(SyncEvent("current_day", "succeeded", TEST_REVISION))
            for future in futures:
                self.assertIsNotNone(future.result(1).event)
        self.assertEqual(broker._waiters, 0)


class EventApiTests(unittest.TestCase):
    def setUp(self):
        self.token = secrets.token_urlsafe(32)
        self.verifier = TokenVerifier(hashlib.sha256(self.token.encode()).hexdigest(),
                                     SYNTHETIC_METER_ID, frozenset({"status:read"}))
        self.broker = EventBroker()
        self.store = mock.Mock()
        self.api = CollectorApi(self.verifier, self.store, event_broker=self.broker)
        self.target = f"/api/v1/events?meter_id={SYNTHETIC_METER_ID}"
        self.auth = {"Authorization": f"Bearer {self.token}"}

    def test_initial_reset_and_exact_bounded_event_response(self):
        response = self.api.handle("GET", self.target, self.auth)
        self.assertEqual(response.status, 200)
        self.assertEqual(set(response.body), {"schema_version", "event", "cursor"})
        self.broker.publish(SyncEvent("current_day", "succeeded", TEST_REVISION))
        response = self.api.handle("GET", self.target + "&cursor=" + response.body["cursor"], self.auth)
        self.assertEqual(set(response.body), {
            "schema_version", "event", "cursor", "sync_kind", "sync_result", "dataset_revision",
        })
        self.assertEqual(response.body["dataset_revision"], TEST_REVISION)
        self.assertNotEqual(response.body["cursor"], TEST_REVISION)
        encoded = json.dumps(response.body)
        self.assertLess(len(encoded), 4096)
        for private in (self.token, self.verifier.token_sha256, SYNTHETIC_METER_ID):
            self.assertNotIn(private, encoded)
        self.assertEqual(self.store.mock_calls, [])

    def test_event_audit_logs_no_revision_cursor_or_credentials(self):
        from collector_service.server import _audit
        cursor = self.broker.wait(None).cursor
        self.broker.publish(SyncEvent("current_day", "succeeded", TEST_REVISION))
        response = self.api.handle("GET", self.target + "&cursor=" + cursor, self.auth)
        output = io.StringIO()
        with mock.patch("sys.stdout", output):
            _audit(response, "GET")
        logged = output.getvalue()
        self.assertEqual(json.loads(logged)["event"], "request_completed")
        for private in (self.token, self.verifier.token_sha256, SYNTHETIC_METER_ID,
                        TEST_REVISION, cursor, response.body["cursor"]):
            self.assertNotIn(private, logged)

    def test_auth_meter_method_and_query_rejection_before_wait(self):
        with mock.patch.object(self.broker, "wait") as wait:
            for auth in ({}, {"Authorization": "Bearer " + "x" * 43}):
                self.assertEqual(self.api.handle("GET", self.target, auth).status, 401)
            wrong_meter = "/api/v1/events?meter_id=mtr_" + "0" * 32
            self.assertEqual(self.api.handle("GET", wrong_meter, self.auth).status, 404)
            self.assertEqual(self.api.handle("POST", self.target, self.auth).status, 405)
            for target in ("/api/v1/events", self.target + "&token=secret", self.target + "&cursor=a&cursor=b"):
                self.assertEqual(self.api.handle("GET", target, self.auth).status, 400)
            wait.assert_not_called()

    def test_timeout_cursor_and_shutdown_errors(self):
        cursor = self.broker.wait(None).cursor
        original = self.broker.wait
        with mock.patch.object(self.broker, "wait", side_effect=lambda c: original(c, timeout=0)):
            response = self.api.handle("GET", self.target + "&cursor=" + cursor, self.auth)
        self.assertEqual((response.status, response.body), (204, {}))
        for cursor in ("bad", "x" * 57):
            response = self.api.handle("GET", self.target + "&cursor=" + cursor, self.auth)
            self.assertEqual(response.status, 400)
            self.assertNotIn(cursor, json.dumps(response.body))
        with mock.patch.object(self.broker, "wait", side_effect=EventBrokerError("event_waiter_limit")):
            self.assertEqual(self.api.handle("GET", self.target, self.auth).status, 429)
        self.broker.close()
        self.assertEqual(self.api.handle("GET", self.target, self.auth).status, 503)

    def test_authorization_rechecked_after_wait(self):
        verifier = mock.Mock(meter_id=SYNTHETIC_METER_ID)
        verifier.authorize.side_effect = (True, False)
        api = CollectorApi(verifier, self.store, event_broker=self.broker)
        response = api.handle("GET", self.target, self.auth)
        self.assertEqual(response.status, 401)
        self.assertEqual(verifier.authorize.call_count, 2)


if __name__ == "__main__":
    unittest.main()
