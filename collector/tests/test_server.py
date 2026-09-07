"""Small regression tests for service process lifecycle behavior."""

from __future__ import annotations

import signal
import unittest

from collector_service.server import _request_stop


class CollectorServerLifecycleTest(unittest.TestCase):
    def test_sigterm_handler_requests_orderly_server_shutdown(self) -> None:
        with self.assertRaises(KeyboardInterrupt):
            _request_stop(signal.SIGTERM, None)


if __name__ == "__main__":
    unittest.main()
