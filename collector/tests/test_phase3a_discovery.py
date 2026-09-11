"""Targeted offline tests for the Phase 3A discovery security boundary."""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import socket
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

from collector_service.api import CollectorApi, SYNTHETIC_METER_ID, TokenVerifier
from collector_service import cez_discovery, restricted_proxy, runtime_config, server


START_URL = "https://login.example.invalid/login"
AUTH_ORIGIN = "https://login.example.invalid"
FINAL_URL = "https://portal.example.invalid/account"
ALLOWED_ORIGINS = frozenset(
    {AUTH_ORIGIN, "https://portal.example.invalid"}
)
USERNAME = "private-user@example.invalid"
PASSWORD = "private-password-value"


class _FakeElement:
    def __init__(self, attributes: dict[str, str], callback=None) -> None:
        self.attributes = attributes
        self.callback = callback
        self.sent: list[str] = []

    def find_elements(self, _by: str, _value: str):
        return []

    def get_attribute(self, name: str) -> str | None:
        return self.attributes.get(name)

    def is_displayed(self) -> bool:
        return True

    def is_enabled(self) -> bool:
        return True

    def send_keys(self, value: str) -> None:
        self.sent.append(value)
        if self.callback is not None:
            self.callback(value)


class _FakeForm(_FakeElement):
    def __init__(self, action: str, inputs: list[_FakeElement]) -> None:
        super().__init__({"action": action})
        self.inputs = inputs

    def find_elements(self, _by: str, value: str):
        return self.inputs if value == "input" else []


class _FakeDriver:
    def __init__(self, *, fail_navigation: bool = False) -> None:
        self.current_url = START_URL
        self.fail_navigation = fail_navigation
        self.cookies_deleted = False
        self.quit_called = False
        self.page_timeout = None
        self.script_timeout = None
        self.cdp_calls: list[tuple[str, dict[str, str]]] = []
        self.username = _FakeElement({"type": "email"})
        self.password = _FakeElement({"type": "password"}, self._password_input)
        self.forms = [_FakeForm(START_URL, [self.username, self.password])]

    def _password_input(self, value: str) -> None:
        if value == cez_discovery.WEBDRIVER_ENTER_KEY:
            self.current_url = FINAL_URL
            self.forms = []

    def find_elements(self, _by: str, value: str):
        return self.forms if value == "form" else []

    def get(self, url: str) -> None:
        if self.fail_navigation:
            raise RuntimeError("sensitive browser failure text")
        self.current_url = url

    def set_page_load_timeout(self, seconds: float) -> None:
        self.page_timeout = seconds

    def set_script_timeout(self, seconds: float) -> None:
        self.script_timeout = seconds

    def execute_cdp_cmd(self, command: str, parameters: dict[str, str]) -> None:
        self.cdp_calls.append((command, parameters))

    def delete_all_cookies(self) -> None:
        self.cookies_deleted = True

    def quit(self) -> None:
        self.quit_called = True


class _FakeService:
    def __init__(self) -> None:
        self.stopped = False

    def stop(self) -> None:
        self.stopped = True


@contextmanager
def _fake_proxy(_gate):
    yield 43123


def _configuration() -> runtime_config.DiscoveryConfiguration:
    return runtime_config.DiscoveryConfiguration(
        start_url=START_URL,
        auth_origin=AUTH_ORIGIN,
        allowed_origins=ALLOWED_ORIGINS,
        username=USERNAME,
        password=PASSWORD,
    )


class Phase3ADiscoveryTests(unittest.TestCase):
    def test_discovery_json_emitter_adds_timestamp_without_changing_event(self) -> None:
        output = io.StringIO()
        with mock.patch("sys.stdout", output):
            cez_discovery.emit_json_event(
                cez_discovery.SafeDiscoveryEvent("browser_started")
            )
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["event"], "browser_started")
        self.assertRegex(
            payload["timestamp"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$"
        )

    def test_discovery_configuration_is_optional_for_normal_startup(self) -> None:
        self.assertIsNone(
            runtime_config._load_discovery_configuration(
                {
                    "cez_discovery_mode": False,
                    "cez_username": USERNAME,
                    "cez_password": PASSWORD,
                }
            )
        )

    def test_normal_runtime_discards_discovery_secret_references(self) -> None:
        token = secrets.token_urlsafe(32)
        options = {
            "meter_id": SYNTHETIC_METER_ID,
            "api_token_sha256": hashlib.sha256(token.encode("ascii")).hexdigest(),
            "tls_certificate_b64": "Y2VydGlmaWNhdGU=",
            "tls_private_key_b64": "cHJpdmF0ZS1rZXk=",
            "cez_discovery_mode": False,
            "cez_username": USERNAME,
            "cez_password": PASSWORD,
        }
        with mock.patch.dict(
            os.environ, {"SUPERVISOR_TOKEN": "platform-token"}, clear=True
        ), mock.patch.object(
            runtime_config, "_read_supervisor_options", return_value=options
        ), mock.patch.object(
            runtime_config, "_context_from_memory", return_value=mock.Mock()
        ):
            configuration = runtime_config.load_runtime_configuration()
        self.assertIsNone(configuration.discovery)
        self.assertNotIn("cez_username", options)
        self.assertNotIn("cez_password", options)

    def test_enabled_configuration_is_strict_and_hides_credentials(self) -> None:
        configuration = runtime_config._load_discovery_configuration(
            {
                "cez_discovery_mode": True,
                "cez_start_url": START_URL,
                "cez_auth_origin": AUTH_ORIGIN,
                "cez_allowed_origins": list(ALLOWED_ORIGINS),
                "cez_username": USERNAME,
                "cez_password": PASSWORD,
            }
        )
        self.assertEqual(configuration.auth_origin, AUTH_ORIGIN)
        representation = repr(configuration)
        self.assertNotIn(USERNAME, representation)
        self.assertNotIn(PASSWORD, representation)

    def test_missing_credentials_have_only_fixed_diagnostic_codes(self) -> None:
        base = {
            "cez_discovery_mode": True,
            "cez_start_url": START_URL,
            "cez_auth_origin": AUTH_ORIGIN,
            "cez_allowed_origins": list(ALLOWED_ORIGINS),
        }
        for field, code in (
            ("cez_username", "discovery_config_missing_username"),
            ("cez_password", "discovery_config_missing_password"),
        ):
            options = {**base, "cez_username": USERNAME, "cez_password": PASSWORD}
            del options[field]
            with self.subTest(field=field), self.assertRaises(
                runtime_config.DiscoveryConfigurationError
            ) as raised:
                runtime_config._load_discovery_configuration(options)
            self.assertEqual(raised.exception.code, code)
            self.assertNotIn(USERNAME, str(raised.exception))
            self.assertNotIn(PASSWORD, str(raised.exception))

    def test_webdriver_control_characters_in_credentials_fail_closed(self) -> None:
        options = {
            "cez_discovery_mode": True,
            "cez_start_url": START_URL,
            "cez_auth_origin": AUTH_ORIGIN,
            "cez_allowed_origins": list(ALLOWED_ORIGINS),
            "cez_username": USERNAME,
            "cez_password": f"unsafe{cez_discovery.WEBDRIVER_ENTER_KEY}",
        }
        with self.assertRaises(runtime_config.DiscoveryConfigurationError) as raised:
            runtime_config._load_discovery_configuration(options)
        self.assertEqual(raised.exception.code, "discovery_config_invalid_password")

    def test_url_sanitization_drops_query_and_fragment(self) -> None:
        hostname, category = cez_discovery.safe_location(
            "https://login.example.invalid/auth/callback?code=secret#token"
        )
        self.assertEqual(hostname, "login.example.invalid")
        self.assertEqual(category, "login_like")
        encoded = json.dumps(
            cez_discovery.SafeDiscoveryEvent(
                "login_page_reached", hostname, category
            ).as_dict()
        )
        self.assertNotIn("code=", encoded)
        self.assertNotIn("secret", encoded)
        self.assertNotIn("#token", encoded)
        with self.assertRaises(ValueError):
            cez_discovery.SafeDiscoveryEvent(
                "login_page_reached", "https://login.example.invalid/?secret", "other"
            )

    def test_unexpected_origins_and_ip_destinations_fail_closed(self) -> None:
        with self.assertRaisesRegex(Exception, "unexpected_origin"):
            cez_discovery._validate_observed_location(
                "https://unexpected.example.invalid/login", ALLOWED_ORIGINS
            )
        gate = restricted_proxy.EgressGate(ALLOWED_ORIGINS)
        self.assertIsNone(gate.parse_allowed_target("unexpected.example.invalid:443"))
        self.assertIsNone(gate.parse_allowed_target("127.0.0.1:443"))
        self.assertEqual(
            gate.parse_allowed_target("login.example.invalid:443"),
            "login.example.invalid",
        )

    def test_loopback_proxy_rejects_unexpected_connect_without_outbound_io(
        self,
    ) -> None:
        gate = restricted_proxy.EgressGate(ALLOWED_ORIGINS)
        with restricted_proxy.local_egress_proxy(gate) as port:
            with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
                client.sendall(
                    b"CONNECT unexpected.example.invalid:443 HTTP/1.1\r\n"
                    b"Host: unexpected.example.invalid:443\r\n\r\n"
                )
                response = client.recv(1024)
        self.assertIn(b" 403 ", response)
        self.assertTrue(gate.rejection_detected)
        self.assertEqual(gate.rejected_hostname, "unexpected.example.invalid")

    def test_forbidden_sandbox_arguments_are_not_configured(self) -> None:
        arguments = cez_discovery.chromium_arguments(Path("/tmp/profile"), 43123)
        switches = {argument.split("=", 1)[0] for argument in arguments}
        self.assertFalse(switches & cez_discovery.FORBIDDEN_CHROMIUM_ARGUMENTS)
        self.assertIn("--headless=new", arguments)
        self.assertIn("--host-resolver-rules=MAP * ~NOTFOUND", arguments)
        self.assertIn("--incognito", arguments)

    def test_success_cleans_browser_profile_and_emits_only_safe_events(self) -> None:
        driver = _FakeDriver()
        service = _FakeService()
        events: list[cez_discovery.SafeDiscoveryEvent] = []
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            cez_discovery, "TMP_DIRECTORY", Path(directory)
        ), mock.patch.object(
            cez_discovery, "local_egress_proxy", _fake_proxy
        ), mock.patch.object(
            cez_discovery.os, "geteuid", return_value=2000, create=True
        ), mock.patch.object(
            cez_discovery.os, "getegid", return_value=2000, create=True
        ):
            outcome = cez_discovery.run_discovery(
                _configuration(),
                events.append,
                driver_factory=lambda _arguments: (driver, service),
            )
            self.assertEqual(list(Path(directory).iterdir()), [])
        self.assertTrue(outcome.succeeded)
        self.assertTrue(outcome.cleanup_verified)
        self.assertTrue(driver.cookies_deleted)
        self.assertTrue(driver.quit_called)
        self.assertTrue(service.stopped)
        self.assertEqual(driver.username.sent, [USERNAME])
        self.assertEqual(
            driver.password.sent,
            [PASSWORD, cez_discovery.WEBDRIVER_ENTER_KEY],
        )
        names = [event.event for event in events]
        self.assertEqual(
            names,
            [
                "browser_started",
                "login_page_reached",
                "credentials_submitted",
                "authentication_succeeded",
                "browser_cleanup_complete",
            ],
        )
        encoded = json.dumps([event.as_dict() for event in events])
        self.assertNotIn(USERNAME, encoded)
        self.assertNotIn(PASSWORD, encoded)

    def test_failure_still_cleans_browser_and_suppresses_exception_text(self) -> None:
        driver = _FakeDriver(fail_navigation=True)
        service = _FakeService()
        events: list[cez_discovery.SafeDiscoveryEvent] = []
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            cez_discovery, "TMP_DIRECTORY", Path(directory)
        ), mock.patch.object(
            cez_discovery, "local_egress_proxy", _fake_proxy
        ), mock.patch.object(
            cez_discovery.os, "geteuid", return_value=2000, create=True
        ), mock.patch.object(
            cez_discovery.os, "getegid", return_value=2000, create=True
        ):
            outcome = cez_discovery.run_discovery(
                _configuration(),
                events.append,
                driver_factory=lambda _arguments: (driver, service),
            )
        self.assertFalse(outcome.succeeded)
        self.assertTrue(outcome.cleanup_verified)
        self.assertEqual(
            [event.event for event in events],
            ["browser_started", "authentication_failed", "browser_cleanup_complete"],
        )
        self.assertNotIn(
            "sensitive browser failure text", json.dumps(events, default=str)
        )

    def test_destination_is_rechecked_before_password_entry(self) -> None:
        driver = _FakeDriver()
        driver.username.callback = lambda _value: driver.forms[0].attributes.update(
            {"action": "https://unexpected.example.invalid/collect"}
        )
        service = _FakeService()
        events: list[cez_discovery.SafeDiscoveryEvent] = []
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            cez_discovery, "TMP_DIRECTORY", Path(directory)
        ), mock.patch.object(
            cez_discovery, "local_egress_proxy", _fake_proxy
        ), mock.patch.object(
            cez_discovery.os, "geteuid", return_value=2000, create=True
        ), mock.patch.object(
            cez_discovery.os, "getegid", return_value=2000, create=True
        ):
            outcome = cez_discovery.run_discovery(
                _configuration(),
                events.append,
                driver_factory=lambda _arguments: (driver, service),
            )
        self.assertFalse(outcome.succeeded)
        self.assertEqual(driver.password.sent, [])
        self.assertIn("unexpected_origin", [event.event for event in events])
        self.assertTrue(outcome.cleanup_verified)

    def test_normal_server_start_does_not_run_discovery(self) -> None:
        fake_server = mock.Mock()
        fake_server.socket = object()
        fake_server.serve_forever.side_effect = KeyboardInterrupt
        configuration = SimpleNamespace(
            verifier=mock.Mock(),
            tls_context=mock.Mock(
                wrap_socket=mock.Mock(return_value=object())
            ),
            source="test",
            discovery=None,
        )
        with mock.patch.object(
            server.os, "geteuid", return_value=2000, create=True
        ), mock.patch.object(
            server.os, "getegid", return_value=2000, create=True
        ), mock.patch.object(
            server, "load_runtime_configuration", return_value=configuration
        ), mock.patch.object(
            server, "CollectorHttpServer", return_value=fake_server
        ), mock.patch.object(
            server, "run_discovery"
        ) as discovery, mock.patch.object(
            server.signal, "signal"
        ), mock.patch("sys.stdout", io.StringIO()):
            self.assertEqual(server.main(), 0)
        discovery.assert_not_called()

    def test_discovery_configuration_error_log_is_fixed_and_non_secret(self) -> None:
        error = runtime_config.DiscoveryConfigurationError(
            "discovery_config_missing_password"
        )
        error.__cause__ = ValueError(PASSWORD)
        stderr = io.StringIO()
        with mock.patch.object(
            server.os, "geteuid", return_value=2000, create=True
        ), mock.patch.object(
            server.os, "getegid", return_value=2000, create=True
        ), mock.patch.object(
            server, "load_runtime_configuration", side_effect=error
        ), mock.patch("sys.stderr", stderr):
            self.assertEqual(server.main(), 1)
        output = stderr.getvalue()
        self.assertIn('"code":"discovery_config_missing_password"', output)
        self.assertNotIn(PASSWORD, output)

    def test_real_api_without_dataset_fails_closed_and_contains_no_credentials(self) -> None:
        token = secrets.token_urlsafe(32)
        verifier = TokenVerifier(
            hashlib.sha256(token.encode("ascii")).hexdigest(),
            SYNTHETIC_METER_ID,
            frozenset({"health:read", "status:read", "measurements:read"}),
        )
        store = mock.Mock()
        store.read_status.return_value = None
        store.read_measurements.return_value = None
        api = CollectorApi(verifier, store)
        authorization = {"Authorization": f"Bearer {token}"}
        responses = (
            api.handle("GET", "/api/v1/health", authorization),
            api.handle(
                "GET",
                f"/api/v1/status?meter_id={SYNTHETIC_METER_ID}",
                authorization,
            ),
            api.handle(
                "GET",
                f"/api/v1/measurements?meter_id={SYNTHETIC_METER_ID}"
                "&start=2026-08-01T00:00:00Z&end=2026-08-01T00:30:00Z",
                authorization,
            ),
        )
        encoded = json.dumps([response.body for response in responses])
        self.assertNotIn(USERNAME, encoded)
        self.assertNotIn(PASSWORD, encoded)
        self.assertEqual(responses[0].status, 200)
        self.assertEqual(responses[1].status, 503)
        self.assertEqual(responses[2].status, 503)
        self.assertEqual(responses[2].body["error"]["code"], "dataset_unavailable")


if __name__ == "__main__":
    unittest.main()
