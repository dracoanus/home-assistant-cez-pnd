"""Small regression tests for service process lifecycle behavior."""

from __future__ import annotations

import signal
import io
import unittest
from unittest import mock

from collector_service import runtime_config, server
from collector_service.server import _request_stop


class CollectorServerLifecycleTest(unittest.TestCase):
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
        self.assertIn('"code":"private_config_missing_tls_certificate"', output)
        self.assertNotIn(secret, output)
        self.assertNotIn("certificate contents", output)


if __name__ == "__main__":
    unittest.main()
