"""Offline tests for the temporary requests.Session PREAUTH experiment."""

from __future__ import annotations

from dataclasses import dataclass
import io
import json
from types import SimpleNamespace
import unittest
from unittest import mock

from collector_service import cez_http_auth, runtime_config, server
from collector_service.requests_preauth import RequestsPreauthCompatibilityClient


GLOBAL_IP = "93.184.216.34"
LOGIN_URL = "https://mepas.cez.cz/cas/login?service=opaque"


class _Headers(dict[str, str]):
    pass


class _Cookies(list[object]):
    def __init__(self) -> None:
        super().__init__()
        self.cleared = False

    def clear(self) -> None:
        self.cleared = True
        super().clear()


@dataclass
class _Response:
    status_code: int
    headers: _Headers
    chunks: tuple[bytes, ...] = (b"bounded",)
    new_cookies: tuple[object, ...] = ()
    closed: bool = False

    def iter_content(self, chunk_size: int):
        self.chunk_size = chunk_size
        return iter(self.chunks)

    def close(self) -> None:
        self.closed = True


class _Session:
    def __init__(self, responses: list[_Response]) -> None:
        self.trust_env = False
        self.proxies: dict[str, str] = {}
        self.cookies = _Cookies()
        self.responses = list(responses)
        self.calls: list[tuple[str, str, dict[str, object]]] = []
        self.closed = False
        self.cookie_names_before_request: list[tuple[str, ...]] = []

    def request(self, method: str, url: str, **kwargs: object) -> _Response:
        self.cookie_names_before_request.append(
            tuple(str(cookie.name) for cookie in self.cookies)
        )
        self.calls.append((method, url, kwargs))
        response = self.responses.pop(0)
        self.cookies.extend(response.new_cookies)
        return response

    def close(self) -> None:
        self.closed = True


def _resolver(hostname: str, port: int) -> tuple[str, ...]:
    assert hostname in cez_http_auth.REVIEWED_HOSTNAMES
    assert port == 443
    return (GLOBAL_IP,)


class RequestsPreauthTests(unittest.TestCase):
    def test_active_auth_reuses_session_through_form_post_and_auth_redirects(self) -> None:
        class _Cookie:
            domain = ".cez.cz"
            name = "session"
            value = "private-cookie-value"

        form = b'''<html><form method="post" action="/cas/login">
        <input type="hidden" name="execution" value="e1s1">
        <input name="username"><input name="password" type="password">
        </form></html>'''
        session = _Session(
            [
                _Response(302, _Headers(Location=LOGIN_URL)),
                _Response(200, _Headers(), (form,), (_Cookie(),)),
                _Response(
                    302,
                    _Headers(
                        Location="https://pnd.cezdistribuce.cz/cezpnd2/external/dashboard/view"
                    ),
                ),
                _Response(200, _Headers()),
                _Response(
                    200,
                    _Headers({"Content-Type": "application/json"}),
                    (b'{"meters":[]}',),
                ),
            ]
        )
        resolved: list[tuple[str, int]] = []

        def resolving(hostname: str, port: int) -> tuple[str, ...]:
            resolved.append((hostname, port))
            return _resolver(hostname, port)

        transport = __import__(
            "collector_service.requests_preauth", fromlist=["RequestsSessionTransport"]
        ).RequestsSessionTransport(
            resolver=resolving,
            session_factory=lambda: session,
        )
        events: list[cez_http_auth.SafeHttpAuthEvent] = []
        configuration = runtime_config.HttpAuthDiscoveryConfiguration(
            username="private-user", password="private-password"
        )
        result = cez_http_auth.CezHttpAuthClient(
            configuration,
            transport,
            resolver=transport.resolve,
            emit=events.append,
        ).authenticate()
        self.assertEqual(result.status, cez_http_auth.AuthStatus.AUTHENTICATED)
        self.assertEqual(
            [call[0] for call in session.calls],
            ["GET", "GET", "POST", "GET", "GET"],
        )
        self.assertEqual(
            resolved,
            [
                ("pnd.cezdistribuce.cz", 443),
                ("mepas.cez.cz", 443),
                ("mepas.cez.cz", 443),
                ("pnd.cezdistribuce.cz", 443),
                ("pnd.cezdistribuce.cz", 443),
            ],
        )
        self.assertTrue(all(call[2]["allow_redirects"] is False for call in session.calls))
        posts = [call for call in session.calls if call[0] == "POST"]
        self.assertEqual(len(posts), 1)
        self.assertIn(b"username=private-user", posts[0][2]["data"])
        self.assertIn(b"password=private-password", posts[0][2]["data"])
        self.assertEqual(session.cookie_names_before_request[2], ("session",))
        self.assertEqual(session.cookie_names_before_request[4], ("session",))
        self.assertEqual(
            session.calls[-1][1], cez_http_auth.CEZ_PND_AUTH_CHECK_URL
        )
        self.assertEqual(
            session.calls[-1][2]["headers"]["Accept"], "*/*"
        )
        self.assertTrue(
            all(
                call[2]["headers"]["User-Agent"]
                == cez_http_auth.CEZ_HTTP_USER_AGENT
                for call in session.calls
            )
        )
        self.assertIsNone(session.calls[-1][2]["data"])
        self.assertNotIn("Referer", session.calls[-1][2]["headers"])
        self.assertNotIn("X-Requested-With", session.calls[-1][2]["headers"])
        self.assertNotIn("Content-Type", session.calls[-1][2]["headers"])
        rendered_events = repr([event.as_dict() for event in events])
        self.assertNotIn("private-user", rendered_events)
        self.assertNotIn("private-password", rendered_events)
        self.assertNotIn("private-cookie-value", rendered_events)
        self.assertEqual(
            [event.event for event in events],
            [
                "http_auth_started",
                "auth_redirect_observed",
                "preauth_reached",
                "login_form_validated",
                "credentials_submitted",
                "auth_redirect_observed",
                "authenticated",
                "http_auth_cleanup_complete",
            ],
        )
        self.assertTrue(session.cookies.cleared)
        self.assertTrue(session.closed)

    def test_login_page_at_auth_check_is_not_authentication_proof(self) -> None:
        session = self._active_auth_session(
            _Response(
                200,
                _Headers({"Content-Type": "text/html"}),
                (b"<html><form action='/cas/login'></form></html>",),
            )
        )
        result = self._run_active_auth(session)
        self.assertEqual(result.status, cez_http_auth.AuthStatus.FAILED)
        self.assertEqual(result.code, "auth_state_unverified")

    def test_redirect_to_login_at_auth_check_is_not_followed(self) -> None:
        session = self._active_auth_session(
            _Response(302, _Headers(Location=LOGIN_URL), ())
        )
        result = self._run_active_auth(session)
        self.assertEqual(result.status, cez_http_auth.AuthStatus.FAILED)
        self.assertEqual(result.code, "auth_state_unverified")
        self.assertEqual(len(session.calls), 5)

    def test_non_object_json_is_not_authentication_proof(self) -> None:
        for body in (b"not-json", b"[]"):
            with self.subTest(body=body):
                session = self._active_auth_session(
                    _Response(
                        200,
                        _Headers({"Content-Type": "application/json"}),
                        (body,),
                    )
                )
                result = self._run_active_auth(session)
                self.assertEqual(result.status, cez_http_auth.AuthStatus.FAILED)
                self.assertEqual(result.code, "auth_state_unverified")

    @staticmethod
    def _active_auth_session(verification: _Response) -> _Session:
        form = b'''<html><form method="post" action="/cas/login">
        <input type="hidden" name="execution" value="e1s1">
        <input name="username"><input name="password" type="password">
        </form></html>'''
        return _Session(
            [
                _Response(302, _Headers(Location=LOGIN_URL)),
                _Response(200, _Headers(), (form,)),
                _Response(
                    302,
                    _Headers(
                        Location="https://pnd.cezdistribuce.cz/cezpnd2/external/dashboard/view"
                    ),
                ),
                _Response(200, _Headers()),
                verification,
            ]
        )

    @staticmethod
    def _run_active_auth(session: _Session) -> cez_http_auth.AuthResult:
        transport = __import__(
            "collector_service.requests_preauth", fromlist=["RequestsSessionTransport"]
        ).RequestsSessionTransport(
            resolver=_resolver,
            session_factory=lambda: session,
        )
        return cez_http_auth.CezHttpAuthClient(
            runtime_config.HttpAuthDiscoveryConfiguration(
                username="private-user", password="private-password"
            ),
            transport,
            resolver=transport.resolve,
        ).authenticate()

    def test_mode_is_explicit_and_mutually_exclusive(self) -> None:
        self.assertFalse(runtime_config._load_requests_preauth_compatibility_mode({}))
        self.assertTrue(
            runtime_config._load_requests_preauth_compatibility_mode(
                {"cez_requests_preauth_compatibility_mode": True}
            )
        )
        for other_mode in ("cez_discovery_mode", "cez_http_auth_discovery_mode"):
            with self.subTest(other_mode=other_mode), self.assertRaises(
                runtime_config.DiscoveryConfigurationError
            ) as raised:
                runtime_config._validate_discovery_modes(
                    {
                        other_mode: True,
                        "cez_requests_preauth_compatibility_mode": True,
                    }
                )
            self.assertEqual(raised.exception.code, "discovery_config_conflicting_modes")

    def test_manual_redirects_validate_every_hop_and_stop_before_credentials(self) -> None:
        session = _Session(
            [
                _Response(302, _Headers(Location=LOGIN_URL)),
                _Response(200, _Headers()),
            ]
        )
        events: list[cez_http_auth.SafeHttpAuthEvent] = []
        result = RequestsPreauthCompatibilityClient(
            resolver=_resolver,
            session_factory=lambda: session,
            emit=events.append,
        ).run()
        self.assertEqual(result.status, cez_http_auth.AuthStatus.NEEDS_LIVE_VERIFICATION)
        self.assertEqual([call[0] for call in session.calls], ["GET", "GET"])
        self.assertTrue(all(call[2]["allow_redirects"] is False for call in session.calls))
        self.assertTrue(all(call[2]["verify"] is True for call in session.calls))
        self.assertTrue(
            all(call[2]["data"] is None and "auth" not in call[2] for call in session.calls)
        )
        self.assertEqual(
            [event.event for event in events],
            [
                "http_auth_started",
                "auth_redirect_observed",
                "preauth_reached",
                "http_auth_cleanup_complete",
            ],
        )
        self.assertTrue(session.cookies.cleared)
        self.assertTrue(session.closed)

    def test_unreviewed_redirect_is_rejected_before_second_request(self) -> None:
        session = _Session(
            [_Response(302, _Headers(Location="https://attacker.example/login"))]
        )
        result = RequestsPreauthCompatibilityClient(
            resolver=_resolver, session_factory=lambda: session
        ).run()
        self.assertEqual(result.code, "auth_destination_rejected")
        self.assertEqual(len(session.calls), 1)

    def test_reviewed_host_with_unapproved_path_is_rejected_before_request(self) -> None:
        session = _Session(
            [_Response(302, _Headers(Location="https://mepas.cez.cz/unapproved"))]
        )
        result = RequestsPreauthCompatibilityClient(
            resolver=_resolver, session_factory=lambda: session
        ).run()
        self.assertEqual(result.code, "auth_destination_rejected")
        self.assertEqual(len(session.calls), 1)

    def test_non_global_dns_is_rejected_before_request(self) -> None:
        session = _Session([])
        result = RequestsPreauthCompatibilityClient(
            resolver=lambda _host, _port: ("127.0.0.1",),
            session_factory=lambda: session,
        ).run()
        self.assertEqual(result.code, "auth_destination_rejected")
        self.assertEqual(session.calls, [])

    def test_redirect_limit_is_enforced(self) -> None:
        session = _Session(
            [
                _Response(
                    302,
                    _Headers(
                        Location="https://pnd.cezdistribuce.cz/cezpnd2/external/dashboard/view"
                    ),
                )
                for _ in range(cez_http_auth.MAX_REDIRECTS + 1)
            ]
        )
        result = RequestsPreauthCompatibilityClient(
            resolver=_resolver, session_factory=lambda: session
        ).run()
        self.assertEqual(result.code, "auth_redirect_limit")
        self.assertEqual(len(session.calls), cez_http_auth.MAX_REDIRECTS + 1)

    def test_cookie_policy_remains_bounded_and_reviewed(self) -> None:
        class _Cookie:
            domain = ".attacker.example"
            name = "session"
            value = "private-value"

        session = _Session([_Response(200, _Headers())])
        session.cookies.append(_Cookie())
        result = RequestsPreauthCompatibilityClient(
            resolver=_resolver, session_factory=lambda: session
        ).run()
        self.assertEqual(result.code, "auth_cookie_domain_not_allowed")
        self.assertTrue(session.cookies.cleared)

    def test_both_reviewed_cookie_boundaries_are_accepted(self) -> None:
        class _Cookie:
            name = "session"
            value = "private"

            def __init__(self, domain: str) -> None:
                self.domain = domain

        transport_class = __import__(
            "collector_service.requests_preauth", fromlist=["RequestsSessionTransport"]
        ).RequestsSessionTransport
        transport_class._validate_memory_cookies(
            [_Cookie(".cez.cz"), _Cookie("pnd.cezdistribuce.cz")]
        )
        for domain in ("cz", "evilcez.cz", "attacker.example"):
            with self.subTest(domain=domain), self.assertRaises(
                cez_http_auth._AuthFailure
            ) as raised:
                transport_class._validate_memory_cookies([_Cookie(domain)])
            self.assertEqual(raised.exception.code, "auth_cookie_domain_not_allowed")

    def test_server_selects_only_the_explicit_compatibility_mode(self) -> None:
        configuration = SimpleNamespace(
            discovery=None,
            requests_preauth_compatibility=True,
            http_auth_discovery=None,
        )
        result = cez_http_auth.AuthResult(
            cez_http_auth.AuthStatus.NEEDS_LIVE_VERIFICATION,
            "auth_success_condition_needs_live_verification",
        )
        output = io.StringIO()
        with mock.patch.object(server.os, "geteuid", return_value=2000, create=True), mock.patch.object(
            server.os, "getegid", return_value=2000, create=True
        ), mock.patch.object(
            server, "load_runtime_configuration", return_value=configuration
        ), mock.patch(
            "collector_service.requests_preauth.RequestsPreauthCompatibilityClient.run",
            return_value=result,
        ) as run, mock.patch.object(
            server, "run_discovery"
        ) as selenium, mock.patch.object(
            server.CezHttpAuthClient, "authenticate"
        ) as credential_auth, mock.patch(
            "sys.stdout", output
        ):
            self.assertEqual(server.main(), 0)
        run.assert_called_once_with()
        selenium.assert_not_called()
        credential_auth.assert_not_called()
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["event"], "http_auth_result")

    def test_server_active_http_auth_uses_requests_transport(self) -> None:
        configuration = SimpleNamespace(
            discovery=None,
            requests_preauth_compatibility=False,
            http_auth_discovery=runtime_config.HttpAuthDiscoveryConfiguration(
                username="private-user", password="private-password"
            ),
        )
        result = cez_http_auth.AuthResult(
            cez_http_auth.AuthStatus.FAILED, "auth_state_unverified"
        )
        fake_transport = mock.Mock()
        fake_transport.resolve = mock.Mock()
        with mock.patch.object(server.os, "geteuid", return_value=2000, create=True), mock.patch.object(
            server.os, "getegid", return_value=2000, create=True
        ), mock.patch.object(
            server, "load_runtime_configuration", return_value=configuration
        ), mock.patch(
            "collector_service.requests_preauth.RequestsSessionTransport",
            return_value=fake_transport,
        ) as transport_class, mock.patch.object(
            server.CezHttpAuthClient, "authenticate", return_value=result
        ) as authenticate, mock.patch(
            "sys.stdout", io.StringIO()
        ):
            self.assertEqual(server.main(), 1)
        transport_class.assert_called_once_with()
        authenticate.assert_called_once_with()

    def test_server_accepts_only_positive_active_auth_proof(self) -> None:
        configuration = SimpleNamespace(
            discovery=None,
            requests_preauth_compatibility=False,
            http_auth_discovery=runtime_config.HttpAuthDiscoveryConfiguration(
                username="private-user", password="private-password"
            ),
        )
        result = cez_http_auth.AuthResult(
            cez_http_auth.AuthStatus.AUTHENTICATED,
            "auth_authenticated_endpoint_verified",
        )
        fake_transport = mock.Mock()
        fake_transport.resolve = mock.Mock()
        with mock.patch.object(server.os, "geteuid", return_value=2000, create=True), mock.patch.object(
            server.os, "getegid", return_value=2000, create=True
        ), mock.patch.object(
            server, "load_runtime_configuration", return_value=configuration
        ), mock.patch(
            "collector_service.requests_preauth.RequestsSessionTransport",
            return_value=fake_transport,
        ), mock.patch.object(
            server.CezHttpAuthClient, "authenticate", return_value=result
        ), mock.patch(
            "sys.stdout", io.StringIO()
        ):
            self.assertEqual(server.main(), 0)



if __name__ == "__main__":
    unittest.main()
