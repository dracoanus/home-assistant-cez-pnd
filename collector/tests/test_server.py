"""Small regression tests for service process lifecycle behavior."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import signal
import io
import re
import unittest
from unittest import mock

from collector_service import runtime_config, server
from collector_service.api import ApiResponse
from collector_service.server import _request_stop
from collector_service.structured_logging import structured_event_json


class CollectorServerLifecycleTest(unittest.TestCase):
    def test_structured_timestamp_is_utc_second_precision_and_first(self) -> None:
        encoded = structured_event_json(
            {"event": "example", "code": "fixed"},
            now=datetime(2026, 9, 9, 11, 42, 18, 999999, tzinfo=timezone.utc),
        )
        self.assertEqual(
            encoded,
            '{"timestamp":"2026-09-09T11:42:18Z","event":"example","code":"fixed"}',
        )

    def test_sigterm_handler_requests_orderly_server_shutdown(self) -> None:
        with self.assertRaises(KeyboardInterrupt):
            _request_stop(signal.SIGTERM, None)

    def test_private_configuration_diagnostic_logs_only_allowlisted_code(self) -> None:
        secret = "must-never-be-logged"
        error = runtime_config.PrivateConfigurationError(
            "private_config_missing_tls_certificate"
        )
        error.__cause__ = ValueError(secret)
        stderr = io.StringIO()
        with mock.patch.object(
            server.os, "geteuid", return_value=2000, create=True
        ), mock.patch.object(
            server.os, "getegid", return_value=2000, create=True
        ), mock.patch.object(
            server, "load_runtime_configuration", side_effect=error
        ), mock.patch(
            "sys.stderr", stderr
        ):
            self.assertEqual(server.main(), 1)
        output = stderr.getvalue()
        payload = json.loads(output)
        self.assertEqual(payload["event"], "startup_failed")
        self.assertRegex(
            payload["timestamp"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$"
        )
        self.assertIn('"code":"private_config_missing_tls_certificate"', output)
        self.assertNotIn(secret, output)
        self.assertNotIn("certificate contents", output)

    def test_request_audit_contains_timestamp_and_existing_fields(self) -> None:
        output = io.StringIO()
        response = ApiResponse(200, {}, "health", "request-fixed")
        with mock.patch("sys.stdout", output):
            server._audit(response, "GET")
        payload = json.loads(output.getvalue())
        self.assertEqual(
            {key: payload[key] for key in ("event", "request_id", "method", "route", "status")},
            {
                "event": "request_completed",
                "request_id": "request-fixed",
                "method": "GET",
                "route": "health",
                "status": 200,
            },
        )
        self.assertTrue(payload["timestamp"].endswith("Z"))
        self.assertTrue(re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", payload["timestamp"]))


if __name__ == "__main__":
    unittest.main()
