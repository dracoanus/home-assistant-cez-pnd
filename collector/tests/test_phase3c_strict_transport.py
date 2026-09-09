"""Focused offline tests for pinned-resolution TLS and HTTP one-shot mode."""

from __future__ import annotations

import io
import socket
import ssl
from types import SimpleNamespace
import unittest
from unittest import mock

from collector_service import cez_http_auth, runtime_config, server
from collector_service.strict_http_transport import (
    StrictHttpsTransport,
    StrictTransportError,
    create_strict_tls_context,
)


HOST = "pnd.cezdistribuce.cz"
IPV4 = "93.184.216.34"
IPV6 = "2606:2800:220:1:248:1893:25c8:1946"


class _FakeSocket:
    def __init__(self, family: int, _kind: int, *, connect_error=None) -> None:
        self.family = family
        self.connect_error = connect_error
        self.connected_to = None
        self.timeouts: list[float] = []
        self.closed = False

    def settimeout(self, value: float) -> None:
        self.timeouts.append(value)

    def connect(self, endpoint) -> None:
        self.connected_to = endpoint
        if self.connect_error is not None:
            raise self.connect_error

    def close(self) -> None:
        self.closed = True


class _FakeTlsContext:
    check_hostname = True
    verify_mode = ssl.CERT_REQUIRED
    minimum_version = ssl.TLSVersion.TLSv1_2

    def __init__(self) -> None:
        self.server_hostname = None

    def wrap_socket(self, sock, *, server_hostname: str):
        self.server_hostname = server_hostname
        return sock


class _FakeResponse:
    def __init__(self, status=200, headers=(), body=b"ok", read_error=None) -> None:
        self.status = status
        self._headers = tuple(headers)
        self._body = body
        self._offset = 0
        self._read_error = read_error

    def getheaders(self):
        return self._headers

    def read(self, size: int) -> bytes:
        if self._read_error is not None:
            raise self._read_error
        chunk = self._body[self._offset : self._offset + size]
        self._offset += len(chunk)
        return chunk


class _FakeConnection:
    def __init__(self, host, port, response: _FakeResponse) -> None:
        self.host = host
        self.port = port
        self.response = response
        self.sock = None
        self.method = None
        self.target = None
        self.headers: list[tuple[str, str]] = []
        self.body = None

    def putrequest(self, method, target, **_kwargs) -> None:
        self.method = method
        self.target = target

    def putheader(self, name, value) -> None:
        self.headers.append((name, value))

    def endheaders(self, body=None) -> None:
        self.body = body

    def getresponse(self):
        return self.response

    def close(self) -> None:
        if self.sock is not None:
            self.sock.close()


class _Harness:
    def __init__(self, response: _FakeResponse | None = None, connect_error=None):
        self.resolve_calls = 0
        self.sockets: list[_FakeSocket] = []
        self.context = _FakeTlsContext()
        self.connection = None
        self.response = response or _FakeResponse()
        self.connect_error = connect_error

    def resolve(self, _hostname: str, _port: int):
        self.resolve_calls += 1
        return (IPV4,)

    def socket_factory(self, family: int, kind: int):
        sock = _FakeSocket(family, kind, connect_error=self.connect_error)
        self.sockets.append(sock)
        return sock

    def connection_factory(self, host: str, port: int):
        self.connection = _FakeConnection(host, port, self.response)
        return self.connection

    def transport(self) -> StrictHttpsTransport:
        return StrictHttpsTransport(
            tls_context=self.context,
            resolver=self.resolve,
            socket_factory=self.socket_factory,
            connection_factory=self.connection_factory,
        )


def _destination(transport: StrictHttpsTransport):
    return cez_http_auth.validate_destination(
        cez_http_auth.CEZ_PND_START_URL,
        cez_http_auth.AuthState.PREAUTH,
        "GET",
        transport.resolve,
    )


def _request(transport: StrictHttpsTransport, destination, method="GET", body=None):
    return transport.request(
        method,
        destination,
        headers={"Accept": "text/html"},
        body=body,
        connect_timeout=2.0,
        read_timeout=3.0,
        total_timeout=5.0,
        maximum_body_bytes=1024,
    )


class Phase3CStrictTransportTests(unittest.TestCase):
    def test_resolution_once_numeric_connect_and_original_tls_http_identity(self) -> None:
        harness = _Harness()
        transport = harness.transport()
        destination = _destination(transport)
        response = _request(transport, destination)

        self.assertEqual(harness.resolve_calls, 1)
        self.assertEqual(harness.sockets[0].connected_to, (IPV4, 443))
        self.assertEqual(harness.context.server_hostname, HOST)
        self.assertTrue(harness.context.check_hostname)
        self.assertEqual(harness.connection.host, HOST)
        self.assertIn(("Host", HOST), harness.connection.headers)
        self.assertEqual(response.status, 200)

    def test_ipv6_uses_validated_numeric_endpoint(self) -> None:
        harness = _Harness()
        harness.resolve = lambda _host, _port: (IPV6,)
        transport = harness.transport()
        _request(transport, _destination(transport))
        self.assertEqual(
            harness.sockets[0].connected_to, (IPV6, 443, 0, 0)
        )

    def test_mixed_safe_and_unsafe_dns_results_fail_before_connect(self) -> None:
        harness = _Harness()
        harness.resolve = lambda _host, _port: (IPV4, "127.0.0.1")
        transport = harness.transport()
        with self.assertRaises(Exception) as raised:
            _destination(transport)
        self.assertEqual(raised.exception.args, ("auth_dns_resolution_failed",))
        self.assertEqual(harness.sockets, [])

        forged = cez_http_auth.ValidatedDestination(
            cez_http_auth.CEZ_PND_START_URL, HOST, 443, (IPV4, "10.0.0.1")
        )
        with self.assertRaises(StrictTransportError) as transport_error:
            _request(transport, forged)
        self.assertEqual(transport_error.exception.code, "auth_dns_resolution_failed")
        self.assertEqual(harness.sockets, [])

    def test_tls_policy_cannot_be_disabled_and_requires_tls12(self) -> None:
        context = create_strict_tls_context()
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertGreaterEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)

        for attribute, value in (
            ("check_hostname", False),
            ("minimum_version", ssl.TLSVersion.TLSv1),
        ):
            fake = _FakeTlsContext()
            setattr(fake, attribute, value)
            with self.subTest(attribute=attribute), self.assertRaises(ValueError):
                StrictHttpsTransport(tls_context=fake)

    def test_no_proxy_redirect_or_arbitrary_method_support(self) -> None:
        harness = _Harness(_FakeResponse(status=302, headers=(("Location", "/next"),)))
        transport = harness.transport()
        self.assertFalse(transport.trust_environment)
        self.assertFalse(transport.follows_redirects)
        response = _request(transport, _destination(transport))
        self.assertEqual(response.status, 302)
        self.assertEqual(len(harness.sockets), 1)

        second = _Harness().transport()
        destination = _destination(second)
        with self.assertRaises(StrictTransportError):
            _request(second, destination, method="DELETE")

    def test_get_and_post_use_expected_request_target(self) -> None:
        get_harness = _Harness()
        get_transport = get_harness.transport()
        _request(get_transport, _destination(get_transport))
        self.assertEqual(get_harness.connection.method, "GET")
        self.assertEqual(
            get_harness.connection.target, "/cezpnd2/external/dashboard/view"
        )

        post_harness = _Harness()
        post_transport = post_harness.transport()
        destination = cez_http_auth.validate_destination(
            "https://mepas.cez.cz/cas/login",
            cez_http_auth.AuthState.CREDENTIAL_SUBMISSION,
            "POST",
            post_transport.resolve,
        )
        _request(post_transport, destination, method="POST", body=b"a=b")
        self.assertEqual(post_harness.connection.method, "POST")
        self.assertEqual(post_harness.connection.body, b"a=b")

    def test_response_body_and_header_bounds(self) -> None:
        for response in (
            _FakeResponse(body=b"x" * 1025),
            _FakeResponse(headers=(("X-Large", "x" * (64 * 1024)),)),
        ):
            harness = _Harness(response)
            transport = harness.transport()
            with self.subTest(response=response), self.assertRaises(StrictTransportError):
                _request(transport, _destination(transport))

    def test_connect_read_and_total_timeout_fail_closed(self) -> None:
        for harness in (
            _Harness(connect_error=socket.timeout()),
            _Harness(_FakeResponse(read_error=socket.timeout())),
        ):
            transport = harness.transport()
            with self.subTest(harness=harness), self.assertRaises(
                StrictTransportError
            ) as raised:
                _request(transport, _destination(transport))
            self.assertEqual(raised.exception.code, "auth_operation_timeout")

    def test_transport_closes_active_resources(self) -> None:
        harness = _Harness()
        transport = harness.transport()
        _request(transport, _destination(transport))
        self.assertTrue(harness.sockets[0].closed)
        transport.close()
        with self.assertRaises(StrictTransportError):
            transport.resolve(HOST, 443)


class Phase3COneShotModeTests(unittest.TestCase):
    def test_http_mode_is_disabled_by_default(self) -> None:
        self.assertIsNone(
            runtime_config._load_http_auth_discovery_configuration({})
        )

    def test_http_mode_uses_only_masked_credentials(self) -> None:
        configuration = runtime_config._load_http_auth_discovery_configuration(
            {
                "cez_http_auth_discovery_mode": True,
                "cez_username": "private-user",
                "cez_password": "private-password",
            }
        )
        rendered = repr(configuration)
        self.assertNotIn("private-user", rendered)
        self.assertNotIn("private-password", rendered)

    def test_safe_events_cannot_contain_secrets_or_unreviewed_hosts(self) -> None:
        event = cez_http_auth.SafeHttpAuthEvent(
            "preauth_reached", "mepas.cez.cz"
        )
        rendered = repr(event.as_dict())
        self.assertNotIn("private-user", rendered)
        self.assertNotIn("private-password", rendered)
        with self.assertRaises(ValueError):
            cez_http_auth.SafeHttpAuthEvent("preauth_reached", "attacker.invalid")

    def test_http_auth_failed_result_emits_only_fixed_status_and_code(self) -> None:
        configuration = SimpleNamespace(
            discovery=None,
            http_auth_discovery=runtime_config.HttpAuthDiscoveryConfiguration(
                username="private-user", password="private-password"
            ),
        )
        result = cez_http_auth.AuthResult(
            cez_http_auth.AuthStatus.FAILED, "auth_state_unverified"
        )
        output = io.StringIO()
        with mock.patch.object(server.os, "geteuid", return_value=2000, create=True), mock.patch.object(
            server.os, "getegid", return_value=2000, create=True
        ), mock.patch.object(
            server, "load_runtime_configuration", return_value=configuration
        ), mock.patch(
            "collector_service.strict_http_transport.StrictHttpsTransport"
        ), mock.patch.object(
            server.CezHttpAuthClient, "authenticate", return_value=result
        ), mock.patch("sys.stdout", output):
            self.assertEqual(server.main(), 1)
        self.assertEqual(
            output.getvalue().strip(),
            '{"event":"http_auth_result","status":"failed","code":"auth_state_unverified"}',
        )
        self.assertNotIn("private-user", output.getvalue())
        self.assertNotIn("private-password", output.getvalue())

    def test_http_auth_unverified_result_emits_fixed_status_and_code(self) -> None:
        result = cez_http_auth.AuthResult(
            cez_http_auth.AuthStatus.NEEDS_LIVE_VERIFICATION,
            "auth_success_condition_needs_live_verification",
        )
        event = cez_http_auth.SafeHttpAuthEvent.from_result(result)
        self.assertEqual(
            event.as_dict(),
            {
                "event": "http_auth_result",
                "status": "needs_live_verification",
                "code": "auth_success_condition_needs_live_verification",
            },
        )

    def test_http_auth_result_rejects_unapproved_code(self) -> None:
        with self.assertRaises(ValueError):
            cez_http_auth.AuthResult(
                cez_http_auth.AuthStatus.FAILED, "raw private exception detail"
            )
        with self.assertRaises(ValueError):
            cez_http_auth.AuthResult("failed", "auth_state_unverified")  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            cez_http_auth.SafeHttpAuthEvent(
                "http_auth_result",
                status=cez_http_auth.AuthStatus.FAILED,
                code="raw private exception detail",
            )

    def test_conflicting_modes_fail_before_browser_or_network(self) -> None:
        with mock.patch("socket.getaddrinfo") as resolver, mock.patch.object(
            server, "run_discovery"
        ) as browser:
            with self.assertRaises(runtime_config.DiscoveryConfigurationError) as raised:
                runtime_config._validate_discovery_modes(
                    {
                        "cez_discovery_mode": True,
                        "cez_http_auth_discovery_mode": True,
                    }
                )
        self.assertEqual(raised.exception.code, "discovery_config_conflicting_modes")
        resolver.assert_not_called()
        browser.assert_not_called()

    def test_server_executes_http_discovery_exactly_once(self) -> None:
        configuration = SimpleNamespace(
            discovery=None,
            http_auth_discovery=runtime_config.HttpAuthDiscoveryConfiguration(
                username="private-user", password="private-password"
            ),
        )
        result = cez_http_auth.AuthResult(
            cez_http_auth.AuthStatus.NEEDS_LIVE_VERIFICATION,
            "auth_success_condition_needs_live_verification",
        )
        fake_transport = mock.Mock()
        fake_transport.resolve = mock.Mock()
        with mock.patch.object(server.os, "geteuid", return_value=2000, create=True), mock.patch.object(
            server.os, "getegid", return_value=2000, create=True
        ), mock.patch.object(
            server, "load_runtime_configuration", return_value=configuration
        ), mock.patch(
            "collector_service.strict_http_transport.StrictHttpsTransport",
            return_value=fake_transport,
        ), mock.patch.object(
            server.CezHttpAuthClient, "authenticate", return_value=result
        ) as authenticate, mock.patch.object(
            server, "run_discovery"
        ) as browser, mock.patch("sys.stdout", io.StringIO()):
            self.assertEqual(server.main(), 0)
        authenticate.assert_called_once_with()
        browser.assert_not_called()

    def test_transport_setup_failure_emits_only_fixed_event(self) -> None:
        configuration = SimpleNamespace(
            discovery=None,
            http_auth_discovery=runtime_config.HttpAuthDiscoveryConfiguration(
                username="private-user", password="private-password"
            ),
        )
        output = io.StringIO()
        with mock.patch.object(server.os, "geteuid", return_value=2000, create=True), mock.patch.object(
            server.os, "getegid", return_value=2000, create=True
        ), mock.patch.object(
            server, "load_runtime_configuration", return_value=configuration
        ), mock.patch(
            "collector_service.strict_http_transport.StrictHttpsTransport",
            side_effect=RuntimeError("private transport detail"),
        ), mock.patch("sys.stdout", output):
            self.assertEqual(server.main(), 1)
        self.assertEqual(output.getvalue().strip(), '{"event":"protocol_error"}')


if __name__ == "__main__":
    unittest.main()
