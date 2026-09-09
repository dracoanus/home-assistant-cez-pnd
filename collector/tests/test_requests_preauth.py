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

    def request(self, method: str, url: str, **kwargs: object) -> _Response:
        self.calls.append((method, url, kwargs))
        return self.responses.pop(0)

    def close(self) -> None:
        self.closed = True


def _resolver(hostname: str, port: int) -> tuple[str, ...]:
    assert hostname in cez_http_auth.REVIEWED_HOSTNAMES
    assert port == 443
    return (GLOBAL_IP,)


class RequestsPreauthTests(unittest.TestCase):
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
        self.assertTrue(all("data" not in call[2] and "auth" not in call[2] for call in session.calls))
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



if __name__ == "__main__":
    unittest.main()
