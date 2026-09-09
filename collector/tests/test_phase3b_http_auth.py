"""Focused offline tests for the Phase 3B HTTP authentication foundation."""

from __future__ import annotations

import hashlib
import io
import os
import secrets
from types import SimpleNamespace
import unittest
from unittest import mock

from collector_service.api import CollectorApi, SYNTHETIC_METER_ID, TokenVerifier
from collector_service import cez_http_auth, runtime_config, server


USERNAME = "phase3b-user@example.invalid"
PASSWORD = "phase3b-private-password"
GLOBAL_IP = "93.184.216.34"
LOGIN_URL = "https://mepas.cez.cz/cas/login?service=opaque"
FORM_HTML = b"""<!doctype html><html><body>
<form id="fm1" method="post" action="/cas/login">
<input type="hidden" name="execution" value="e1s1">
<input type="hidden" name="_eventId" value="submit">
<input type="text" name="username" value="">
<input type="password" name="password" value="">
</form></body></html>"""


def _resolver(_hostname: str, _port: int) -> tuple[str, ...]:
    return (GLOBAL_IP,)


def _response(
    status: int,
    body: bytes = b"",
    *headers: tuple[str, str],
) -> cez_http_auth.HttpResponse:
    return cez_http_auth.HttpResponse(status, tuple(headers), body)


class _FakeTransport:
    trust_environment = False
    follows_redirects = False

    def __init__(self, responses: list[cez_http_auth.HttpResponse]) -> None:
        self.responses = list(responses)
        self.requests: list[tuple[str, str, dict[str, str], bytes | None]] = []
        self.closed = False

    def request(
        self,
        method: str,
        destination: cez_http_auth.ValidatedDestination,
        *,
        headers,
        body,
        connect_timeout,
        read_timeout,
        total_timeout,
        maximum_body_bytes,
    ) -> cez_http_auth.HttpResponse:
        self.requests.append((method, destination.url, dict(headers), body))
        if not self.responses:
            raise RuntimeError("fake transport exhausted")
        return self.responses.pop(0)

    def close(self) -> None:
        self.closed = True


class _CloseFailureTransport(_FakeTransport):
    def close(self) -> None:
        self.closed = True
        raise OSError("private close detail")


def _configuration() -> runtime_config.DiscoveryConfiguration:
    return runtime_config.DiscoveryConfiguration(
        start_url=cez_http_auth.CEZ_PND_START_URL,
        auth_origin="https://mepas.cez.cz",
        allowed_origins=frozenset(
            {
                "https://pnd.cezdistribuce.cz",
                "https://mepas.cez.cz",
                "https://dip.cezdistribuce.cz",
            }
        ),
        username=USERNAME,
        password=PASSWORD,
    )


def _successful_responses() -> list[cez_http_auth.HttpResponse]:
    return [
        _response(302, b"", ("Location", LOGIN_URL), ("Set-Cookie", "preauth=a; Secure")),
        _response(200, FORM_HTML, ("Content-Type", "text/html")),
        _response(
            302,
            b"",
            (
                "Location",
                "https://pnd.cezdistribuce.cz/cezpnd2/external/dashboard/view",
            ),
            ("Set-Cookie", "ticket=b; Secure"),
        ),
        _response(200, b"candidate application response"),
    ]


class Phase3BHttpAuthTests(unittest.TestCase):
    def test_approved_preauth_destination(self) -> None:
        normalized = cez_http_auth.validate_destination(
            cez_http_auth.CEZ_PND_START_URL,
            cez_http_auth.AuthState.PREAUTH,
            "GET",
            _resolver,
        )
        self.assertEqual(normalized.url, cez_http_auth.CEZ_PND_START_URL)
        self.assertEqual(normalized.addresses, (GLOBAL_IP,))

    def test_rejects_non_https_wrong_host_and_wrong_port(self) -> None:
        for url in (
            "http://pnd.cezdistribuce.cz/cezpnd2/external/dashboard/view",
            "https://attacker.invalid/cezpnd2/external/dashboard/view",
            "https://pnd.cezdistribuce.cz:8443/cezpnd2/external/dashboard/view",
        ):
            with self.subTest(url=url), self.assertRaises(Exception) as raised:
                cez_http_auth.validate_destination(
                    url, cez_http_auth.AuthState.PREAUTH, "GET", _resolver
                )
            self.assertEqual(raised.exception.args, ("auth_destination_rejected",))

    def test_rejects_private_reserved_or_unresolved_addresses(self) -> None:
        for addresses in (("127.0.0.1",), ("10.0.0.2",), ("192.0.2.1",), ()):
            with self.subTest(addresses=addresses), self.assertRaises(Exception):
                cez_http_auth.validate_destination(
                    cez_http_auth.CEZ_PND_START_URL,
                    cez_http_auth.AuthState.PREAUTH,
                    "GET",
                    lambda _host, _port, values=addresses: values,
                )

    def test_redirects_are_explicitly_validated_before_request(self) -> None:
        transport = _FakeTransport(
            [_response(302, b"", ("Location", "https://attacker.invalid/login"))]
        )
        result = cez_http_auth.CezHttpAuthClient(
            _configuration(), transport, resolver=_resolver
        ).authenticate()
        self.assertEqual(result.code, "auth_destination_rejected")
        self.assertEqual(len(transport.requests), 1)
        self.assertTrue(transport.closed)

    def test_redirect_loop_is_bounded(self) -> None:
        transport = _FakeTransport(
            [
                _response(302, b"", ("Location", cez_http_auth.CEZ_PND_START_URL))
                for _ in range(cez_http_auth.MAX_REDIRECTS + 1)
            ]
        )
        result = cez_http_auth.CezHttpAuthClient(
            _configuration(), transport, resolver=_resolver
        ).authenticate()
        self.assertEqual(result.code, "auth_redirect_limit")
        self.assertEqual(len(transport.requests), cez_http_auth.MAX_REDIRECTS + 1)

    def test_credentials_post_only_to_approved_idp_without_query(self) -> None:
        invalid_form = FORM_HTML.replace(b'action="/cas/login"', b'action="https://pnd.cezdistribuce.cz/cezpnd2/login"')
        transport = _FakeTransport(
            [
                _response(302, b"", ("Location", LOGIN_URL)),
                _response(200, invalid_form),
            ]
        )
        result = cez_http_auth.CezHttpAuthClient(
            _configuration(), transport, resolver=_resolver
        ).authenticate()
        self.assertEqual(result.code, "auth_destination_rejected")
        self.assertNotIn("POST", [request[0] for request in transport.requests])

        with self.assertRaises(Exception):
            cez_http_auth.validate_destination(
                "https://mepas.cez.cz/cas/login?unexpected=secret",
                cez_http_auth.AuthState.CREDENTIAL_SUBMISSION,
                "POST",
                _resolver,
            )

    def test_ambiguous_login_forms_are_rejected(self) -> None:
        doubled = FORM_HTML.replace(b"</body>", FORM_HTML.split(b"<body>", 1)[1].split(b"</body>", 1)[0] + b"</body>")
        transport = _FakeTransport(
            [_response(302, b"", ("Location", LOGIN_URL)), _response(200, doubled)]
        )
        result = cez_http_auth.CezHttpAuthClient(
            _configuration(), transport, resolver=_resolver
        ).authenticate()
        self.assertEqual(result.code, "auth_form_ambiguous")

    def test_non_post_login_form_is_rejected(self) -> None:
        html = FORM_HTML.replace(b'method="post"', b'method="get"')
        transport = _FakeTransport(
            [_response(302, b"", ("Location", LOGIN_URL)), _response(200, html)]
        )
        result = cez_http_auth.CezHttpAuthClient(
            _configuration(), transport, resolver=_resolver
        ).authenticate()
        self.assertEqual(result.code, "auth_form_invalid")

    def test_duplicate_critical_fields_are_rejected(self) -> None:
        html = FORM_HTML.replace(
            b'<input type="password" name="password" value="">',
            b'<input type="password" name="password" value=""><input type="hidden" name="password" value="duplicate">',
        )
        transport = _FakeTransport(
            [_response(302, b"", ("Location", LOGIN_URL)), _response(200, html)]
        )
        result = cez_http_auth.CezHttpAuthClient(
            _configuration(), transport, resolver=_resolver
        ).authenticate()
        self.assertEqual(result.code, "auth_form_invalid")

    def test_oversized_response_form_and_value_are_rejected(self) -> None:
        cases = (
            (
                _response(200, b"x" * (cez_http_auth.MAX_RESPONSE_BODY_BYTES + 1)),
                "auth_response_too_large",
            ),
            (
                _response(200, b"<form>" + b"x" * cez_http_auth.MAX_HTML_BYTES),
                "auth_form_too_large",
            ),
            (
                _response(
                    200,
                    FORM_HTML.replace(
                        b'value="e1s1"',
                        b'value="' + b"x" * (cez_http_auth.MAX_FORM_VALUE_BYTES + 1) + b'"',
                    ),
                ),
                "auth_form_too_large",
            ),
        )
        for response, code in cases:
            transport = _FakeTransport(
                [_response(302, b"", ("Location", LOGIN_URL)), response]
            )
            with self.subTest(code=code):
                result = cez_http_auth.CezHttpAuthClient(
                    _configuration(), transport, resolver=_resolver
                ).authenticate()
                self.assertEqual(result.code, code)

    def test_excessive_form_controls_and_malformed_html_are_rejected(self) -> None:
        excessive = (
            b'<html><body><form method="post" action="/cas/login">'
            + b'<input type="hidden" name="field" value="x">'
            * (cez_http_auth.MAX_FORM_CONTROLS + 1)
            + b'<input name="username"><input type="password" name="password">'
            + b"</form></body></html>"
        )
        malformed = FORM_HTML.replace(b"</form>", b"")
        for html, code in (
            (excessive, "auth_form_too_large"),
            (malformed, "auth_form_invalid"),
        ):
            transport = _FakeTransport(
                [_response(302, b"", ("Location", LOGIN_URL)), _response(200, html)]
            )
            with self.subTest(code=code):
                result = cez_http_auth.CezHttpAuthClient(
                    _configuration(), transport, resolver=_resolver
                ).authenticate()
                self.assertEqual(result.code, code)

    def test_total_operation_deadline_fails_closed(self) -> None:
        times = iter((0.0, 0.0, 61.0))
        transport = _FakeTransport(
            [_response(302, b"", ("Location", LOGIN_URL))]
        )
        result = cez_http_auth.CezHttpAuthClient(
            _configuration(),
            transport,
            resolver=_resolver,
            monotonic=lambda: next(times),
        ).authenticate()
        self.assertEqual(result.code, "auth_operation_timeout")

    def test_candidate_flow_returns_needs_live_verification_not_authenticated(self) -> None:
        transport = _FakeTransport(_successful_responses())
        client = cez_http_auth.CezHttpAuthClient(
            _configuration(), transport, resolver=_resolver
        )
        result = client.authenticate()
        self.assertEqual(
            result.status, cez_http_auth.AuthStatus.NEEDS_LIVE_VERIFICATION
        )
        self.assertEqual(
            result.code, "auth_success_condition_needs_live_verification"
        )
        self.assertEqual([request[0] for request in transport.requests], ["GET", "GET", "POST", "GET"])
        self.assertEqual(client._cookies.count, 0)
        self.assertTrue(transport.closed)

    def test_credentials_absent_from_result_repr_and_exception_display(self) -> None:
        transport = _FakeTransport(_successful_responses())
        client = cez_http_auth.CezHttpAuthClient(
            _configuration(), transport, resolver=_resolver
        )
        result = client.authenticate()
        rendered = repr(client) + repr(result) + str(result)
        self.assertNotIn(USERNAME, rendered)
        self.assertNotIn(PASSWORD, rendered)

    def test_cookie_session_is_cleared_on_failure(self) -> None:
        transport = _FakeTransport(
            [
                _response(
                    302,
                    b"",
                    ("Location", "https://attacker.invalid/login"),
                    ("Set-Cookie", "session=private-cookie; Secure"),
                )
            ]
        )
        client = cez_http_auth.CezHttpAuthClient(
            _configuration(), transport, resolver=_resolver
        )
        result = client.authenticate()
        self.assertEqual(result.status, cez_http_auth.AuthStatus.FAILED)
        self.assertEqual(client._cookies.count, 0)
        self.assertTrue(transport.closed)

    def test_cleanup_failure_is_fixed_and_fail_closed(self) -> None:
        transport = _CloseFailureTransport(_successful_responses())
        events: list[cez_http_auth.SafeHttpAuthEvent] = []
        client = cez_http_auth.CezHttpAuthClient(
            _configuration(), transport, resolver=_resolver, emit=events.append
        )
        result = client.authenticate()
        self.assertEqual(result.code, "auth_cleanup_failed")
        self.assertEqual(events[-1].event, "http_auth_cleanup_failed")
        self.assertNotIn("private close detail", repr(result) + repr(events))

    def test_proxy_environment_is_not_inherited(self) -> None:
        transport = _FakeTransport(_successful_responses())
        with mock.patch.dict(
            os.environ,
            {
                "HTTP_PROXY": "http://127.0.0.1:9999",
                "HTTPS_PROXY": "http://127.0.0.1:9999",
                "ALL_PROXY": "http://127.0.0.1:9999",
            },
            clear=False,
        ):
            result = cez_http_auth.CezHttpAuthClient(
                _configuration(), transport, resolver=_resolver
            ).authenticate()
        self.assertEqual(
            result.status, cez_http_auth.AuthStatus.NEEDS_LIVE_VERIFICATION
        )
        self.assertFalse(transport.trust_environment)

        unsafe_transport = _FakeTransport([])
        unsafe_transport.trust_environment = True
        rejected = cez_http_auth.CezHttpAuthClient(
            _configuration(), unsafe_transport, resolver=_resolver
        ).authenticate()
        self.assertEqual(rejected.code, "auth_transport_policy_invalid")

    def test_normal_collector_start_does_not_authenticate(self) -> None:
        fake_server = mock.Mock()
        fake_server.socket = object()
        fake_server.serve_forever.side_effect = KeyboardInterrupt
        configuration = SimpleNamespace(
            verifier=mock.Mock(),
            tls_context=mock.Mock(wrap_socket=mock.Mock(return_value=object())),
            source="test",
            discovery=None,
        )
        with mock.patch.object(server.os, "geteuid", return_value=2000, create=True), mock.patch.object(
            server.os, "getegid", return_value=2000, create=True
        ), mock.patch.object(
            server, "load_runtime_configuration", return_value=configuration
        ), mock.patch.object(
            server, "CollectorHttpServer", return_value=fake_server
        ), mock.patch.object(
            cez_http_auth.CezHttpAuthClient, "authenticate"
        ) as authenticate, mock.patch.object(
            server.signal, "signal"
        ), mock.patch("sys.stdout", io.StringIO()):
            self.assertEqual(server.main(), 0)
        authenticate.assert_not_called()

    def test_current_synthetic_api_semantics_are_unchanged(self) -> None:
        token = secrets.token_urlsafe(32)
        verifier = TokenVerifier(
            hashlib.sha256(token.encode("ascii")).hexdigest(),
            SYNTHETIC_METER_ID,
            frozenset({"health:read", "status:read", "measurements:read"}),
        )
        response = CollectorApi(verifier).handle(
            "GET",
            f"/api/v1/measurements?meter_id={SYNTHETIC_METER_ID}"
            "&start=2026-08-01T00:00:00Z&end=2026-08-01T00:30:00Z",
            {"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(response.status, 200)
        missing = [item for item in response.body["values"] if item["quality"] == "missing"]
        self.assertEqual(len(missing), 1)
        self.assertIsNone(missing[0]["value_kwh"])


if __name__ == "__main__":
    unittest.main()
