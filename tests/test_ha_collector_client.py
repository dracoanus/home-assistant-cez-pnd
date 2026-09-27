"""Targeted tests for the Home Assistant Collector client contract."""

from __future__ import annotations

import asyncio
import importlib.util
import json
from pathlib import Path
import ssl
import sys
import types
import unittest
from unittest.mock import patch


class _ClientTimeout:
    def __init__(self, **values: int) -> None:
        self.values = values


class _AiohttpError(Exception):
    pass


def _load_client_module():
    fake = types.ModuleType("aiohttp")
    fake.ClientTimeout = _ClientTimeout
    fake.ClientSession = object
    for name in (
        "ClientConnectorCertificateError",
        "ClientConnectorSSLError",
        "ClientSSLError",
        "ServerFingerprintMismatch",
        "ClientConnectionError",
        "ClientPayloadError",
    ):
        setattr(fake, name, type(name, (_AiohttpError,), {}))
    sys.modules["aiohttp"] = fake
    path = Path(__file__).parents[1] / "custom_components" / "cez_pnd" / "client.py"
    spec = importlib.util.spec_from_file_location("cez_pnd_client_test_target", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


client_module = _load_client_module()
METER_ID = "mtr_7f93b3e31d514db18cd62c0fcaa19a8e"
TOKEN = "A" * 43


def _status_payload() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "meter_id": METER_ID,
        "dataset_revision": "ds_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "data_timestamp": "2026-08-01T00:15:00Z",
        "last_attempt": "2026-08-01T01:00:00Z",
        "last_success": None,
        "completeness": {
            "state": "partial",
            "expected_count": 2,
            "valid_count": 1,
            "missing_count": 1,
            "invalid_count": 0,
        },
        "source_status": "partial",
    }


def _measurements_payload() -> dict[str, object]:
    payload = _status_payload()
    payload["completeness"] = {
        **payload["completeness"],
        "requested_start": "2026-08-01T00:00:00Z",
        "requested_end": "2026-08-01T00:30:00Z",
    }
    payload.update(
        {
            "values": [
                {
                    "channel": "grid_import",
                    "interval_start": "2026-08-01T00:00:00Z",
                    "interval_end": "2026-08-01T00:15:00Z",
                    "value_kwh": "0.125",
                    "quality": "valid",
                    "source_timezone": "Europe/Prague",
                    "source_profile": "+A",
                    "collected_at": "2026-08-01T01:00:00Z",
                    "revision": "ds_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                },
                {
                    "channel": "grid_import",
                    "interval_start": "2026-08-01T00:15:00Z",
                    "interval_end": "2026-08-01T00:30:00Z",
                    "value_kwh": None,
                    "quality": "missing",
                    "source_timezone": "Europe/Prague",
                    "source_profile": "+A",
                    "collected_at": "2026-08-01T01:00:00Z",
                    "revision": "ds_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                },
            ],
            "missing": [
                {
                    "channel": "grid_import",
                    "interval_start": "2026-08-01T00:15:00Z",
                    "interval_end": "2026-08-01T00:30:00Z",
                    "reason": "source_missing",
                }
            ],
            "next_cursor": None,
        }
    )
    return payload


def _page(values, missing, cursor, *, revision="ds_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", expected=2, valid=1, missing_count=1):
    payload = _measurements_payload()
    payload["dataset_revision"] = revision
    payload["values"] = values
    payload["missing"] = missing
    payload["next_cursor"] = cursor
    payload["completeness"].update({"expected_count": expected, "valid_count": valid,
        "missing_count": missing_count, "invalid_count": expected - valid - missing_count})
    for item in values:
        item["revision"] = revision
    return payload


class _Content:
    def __init__(self, body: bytes) -> None:
        self.body = body

    async def iter_chunked(self, _size: int):
        yield self.body


class _RawResponse:
    def __init__(self, body: bytes) -> None:
        self.status = 200
        self.headers = {"Content-Type": "application/json"}
        self.content = _Content(body)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False


class _Response:
    def __init__(
        self,
        status: int,
        payload: object,
        content_type: str = "application/json",
    ) -> None:
        self.status = status
        self.headers = {"Content-Type": content_type}
        self.content = _Content(json.dumps(payload).encode())

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False


class _Session:
    def __init__(self, responses: list[_Response]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, dict[str, object]]] = []
        self.post_calls: list[tuple[str, dict[str, object]]] = []

    def get(self, url: str, **kwargs: object) -> _Response:
        self.calls.append((url, kwargs))
        return self.responses.pop(0)

    def post(self, url: str, **kwargs: object) -> _Response:
        self.post_calls.append((url, kwargs))
        return self.responses.pop(0)


class _FailingPostSession:
    def __init__(self, failure: Exception) -> None:
        self.failure = failure

    def post(self, _url: str, **_kwargs: object):
        raise self.failure


class CollectorClientTests(unittest.IsolatedAsyncioTestCase):
    def _client(self, responses: list[_Response]):
        session = _Session(responses)
        client = client_module.CollectorClient(
            session,
            "https://606197c3-cez-pnd-collector:8443",
            METER_ID,
            TOKEN,
            object(),
        )
        return client, session

    async def test_request_is_bounded_authenticated_and_does_not_redirect(self) -> None:
        client, session = self._client(
            [_Response(200, {"schema_version": "1.0", "service_status": "ok"})]
        )
        self.assertEqual(await client.async_health(), "ok")
        url, kwargs = session.calls[0]
        self.assertEqual(url, "https://606197c3-cez-pnd-collector:8443/api/v1/health")
        self.assertEqual(kwargs["headers"]["Authorization"], f"Bearer {TOKEN}")
        self.assertIs(kwargs["ssl"], client._ssl_context)
        self.assertFalse(kwargs["allow_redirects"])
        self.assertEqual(
            kwargs["timeout"].values,
            {"total": 10, "connect": 5, "sock_read": 8},
        )

    async def test_authentication_and_redirect_errors_are_explicit(self) -> None:
        client, _ = self._client([_Response(401, {})])
        with self.assertRaises(client_module.CollectorAuthenticationError):
            await client.async_health()
        client, _ = self._client([_Response(302, {})])
        with self.assertRaises(client_module.CollectorProtocolError):
            await client.async_health()

    async def test_only_documented_status_and_measurement_routes_are_used(self) -> None:
        client, session = self._client(
            [_Response(200, _status_payload()), _Response(200, _measurements_payload())]
        )
        await client.async_status()
        await client.async_measurements(
            "2026-08-01T00:00:00Z", "2026-08-01T00:30:00Z"
        )
        self.assertEqual(session.calls[0][0].rsplit(":8443", 1)[1], "/api/v1/status")
        self.assertEqual(session.calls[0][1]["params"], {"meter_id": METER_ID})
        self.assertEqual(
            session.calls[1][0].rsplit(":8443", 1)[1], "/api/v1/measurements"
        )
        self.assertEqual(
            session.calls[1][1]["params"],
            {
                "meter_id": METER_ID,
                "start": "2026-08-01T00:00:00Z",
                "end": "2026-08-01T00:30:00Z",
            },
        )

    async def test_status_accepts_large_bounded_dataset_counts(self) -> None:
        payload = _status_payload()
        payload["completeness"].update(
            {
                "expected_count": 17_864,
                "valid_count": 17_828,
                "missing_count": 0,
                "invalid_count": 36,
            }
        )
        client, _ = self._client([_Response(200, payload)])
        status = await client.async_status()
        self.assertEqual(status.completeness.expected_count, 17_864)
        self.assertEqual(status.completeness.valid_count, 17_828)
        self.assertEqual(status.completeness.invalid_count, 36)

        payload = _status_payload()
        payload["completeness"].update(
            {
                "expected_count": client_module.MAX_METADATA_COUNT,
                "valid_count": client_module.MAX_METADATA_COUNT,
                "missing_count": 0,
                "invalid_count": 0,
            }
        )
        client, _ = self._client([_Response(200, payload)])
        status = await client.async_status()
        self.assertEqual(
            status.completeness.expected_count, client_module.MAX_METADATA_COUNT
        )

    async def test_status_rejects_invalid_metadata_counts(self) -> None:
        for invalid in (-1, True, client_module.MAX_METADATA_COUNT + 1):
            with self.subTest(invalid=invalid):
                payload = _status_payload()
                payload["completeness"]["expected_count"] = invalid
                client, _ = self._client([_Response(200, payload)])
                with self.assertRaisesRegex(
                    client_module.CollectorProtocolError, "invalid_completeness"
                ):
                    await client.async_status()

    async def test_timeout_is_explicit_and_does_not_expose_token(self) -> None:
        class TimeoutSession:
            def get(self, *_args, **_kwargs):
                raise asyncio.TimeoutError

        client = client_module.CollectorClient(
            TimeoutSession(),
            "https://606197c3-cez-pnd-collector:8443",
            METER_ID,
            TOKEN,
            object(),
        )
        with self.assertRaises(client_module.CollectorConnectionError) as caught:
            await client.async_health()
        self.assertNotIn(TOKEN, str(caught.exception))

    async def test_tls_failure_is_classified_without_secret_text(self) -> None:
        class TlsSession:
            def get(self, *_args, **_kwargs):
                raise client_module.aiohttp.ClientConnectorSSLError("tls failed")

        client = client_module.CollectorClient(
            TlsSession(),
            "https://606197c3-cez-pnd-collector:8443",
            METER_ID,
            TOKEN,
            object(),
        )
        with self.assertRaises(client_module.CollectorTlsError) as caught:
            await client.async_health()
        self.assertNotIn(TOKEN, str(caught.exception))

    async def test_response_size_is_bounded(self) -> None:
        client, _ = self._client([])
        client._session.responses.append(
            _RawResponse(b"{" + b" " * client_module.MAX_RESPONSE_BYTES + b"}")
        )
        with self.assertRaises(client_module.CollectorProtocolError):
            await client.async_health()

    async def test_missing_measurement_remains_none_and_never_zero(self) -> None:
        client, _ = self._client([_Response(200, _measurements_payload())])
        result = await client.async_measurements(
            "2026-08-01T00:00:00Z", "2026-08-01T00:30:00Z"
        )
        self.assertIsNone(result.values[1].value_kwh)
        self.assertEqual(result.values[1].quality, "missing")
        self.assertEqual(result.missing[0].reason, "source_missing")
        self.assertEqual(str(result.latest_valid_grid_import.value_kwh), "0.125")
        self.assertIsNone(result.last_success)
        self.assertNotEqual(result.last_attempt, result.last_success)
        self.assertEqual(result.completeness.missing_count, 1)
        self.assertEqual(
            result.requested_start.isoformat(), "2026-08-01T00:00:00+00:00"
        )
        self.assertEqual(result.requested_end.isoformat(), "2026-08-01T00:30:00+00:00")

    async def test_missing_measurement_with_zero_fails_closed(self) -> None:
        payload = _measurements_payload()
        payload["values"][1]["value_kwh"] = "0"
        client, _ = self._client([_Response(200, payload)])
        with self.assertRaises(client_module.CollectorProtocolError):
            await client.async_measurements(
                "2026-08-01T00:00:00Z", "2026-08-01T00:30:00Z"
            )

    async def test_multiple_pages_are_combined_with_consistent_metadata(self) -> None:
        complete = _measurements_payload()
        first_value, second_value = complete["values"]
        missing = complete["missing"][0]
        first = _page([first_value], [], "cursor_one")
        second = _page([second_value], [missing], None)
        client, session = self._client([_Response(200, first), _Response(200, second)])
        result = await client.async_measurements("2026-08-01T00:00:00Z", "2026-08-01T00:30:00Z")
        self.assertEqual(len(result.values), 2)
        self.assertEqual(len(result.missing), 1)
        self.assertNotIn("cursor", session.calls[0][1]["params"])
        self.assertEqual(session.calls[1][1]["params"]["cursor"], "cursor_one")

    async def test_revision_change_cursor_loop_and_duplicate_fail_closed(self) -> None:
        complete = _measurements_payload()
        value = complete["values"][0]
        first = _page([dict(value)], [], "cursor_one", expected=2, valid=2, missing_count=0)
        changed = _page([], [], None, revision="ds_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", expected=2, valid=2, missing_count=0)
        client, _ = self._client([_Response(200, first), _Response(200, changed)])
        with self.assertRaises(client_module.CollectorProtocolError):
            await client.async_measurements("2026-08-01T00:00:00Z", "2026-08-01T00:30:00Z")

        loop_first = _page([], [], "cursor_one", expected=0, valid=0, missing_count=0)
        loop_second = _page([], [], "cursor_one", expected=0, valid=0, missing_count=0)
        client, _ = self._client([_Response(200, loop_first), _Response(200, loop_second)])
        with self.assertRaisesRegex(client_module.CollectorProtocolError, "cursor_loop"):
            await client.async_measurements("2026-08-01T00:00:00Z", "2026-08-01T00:30:00Z")

        duplicate_first = _page([dict(value)], [], "cursor_one", expected=2, valid=2, missing_count=0)
        duplicate_second = _page([dict(value)], [], None, expected=2, valid=2, missing_count=0)
        client, _ = self._client([_Response(200, duplicate_first), _Response(200, duplicate_second)])
        with self.assertRaisesRegex(client_module.CollectorProtocolError, "duplicate_measurement_interval"):
            await client.async_measurements("2026-08-01T00:00:00Z", "2026-08-01T00:30:00Z")

    async def test_excessive_pages_fail_closed(self) -> None:
        responses = [_Response(200, _page([], [], f"cursor_{index}", expected=0, valid=0, missing_count=0))
            for index in range(client_module.MAX_PAGES)]
        client, _ = self._client(responses)
        with self.assertRaisesRegex(client_module.CollectorProtocolError, "too_many_pages"):
            await client.async_measurements("2026-08-01T00:00:00Z", "2026-08-01T00:30:00Z")

    async def test_combined_measurement_limit_remains_enforced(self) -> None:
        complete = _measurements_payload()
        first_value, second_value = complete["values"]
        first = _page(
            [first_value], [], "cursor_one", expected=2, valid=2, missing_count=0
        )
        second = _page(
            [second_value], [], None, expected=2, valid=2, missing_count=0
        )
        client, _ = self._client([_Response(200, first), _Response(200, second)])
        with patch.object(client_module, "MAX_COMBINED_ITEMS", 1), self.assertRaisesRegex(
            client_module.CollectorProtocolError, "too_many_measurements"
        ):
            await client.async_measurements(
                "2026-08-01T00:00:00Z", "2026-08-01T00:30:00Z"
            )

    async def test_unexpected_fields_fail_closed(self) -> None:
        payload = _status_payload()
        payload["unexpected"] = "value"
        client, _ = self._client([_Response(200, payload)])
        with self.assertRaises(client_module.CollectorProtocolError):
            await client.async_status()

    def test_only_https_origin_on_expected_port_is_accepted(self) -> None:
        for value in (
            "http://collector:8443",
            "https://collector",
            "https://user:password@collector:8443",
            "https://collector:8443/path",
        ):
            with self.subTest(value=value), self.assertRaises(
                client_module.CollectorConfigurationError
            ):
                client_module.normalize_collector_url(value)

    def test_ssl_context_uses_only_supplied_ca_and_hostname_verification(self) -> None:
        fake_context = unittest.mock.Mock()
        with patch.object(
            client_module.ssl, "SSLContext", return_value=fake_context
        ) as factory:
            result = client_module.create_collector_ssl_context(
                ("-----BEGIN " + "CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----")
            )
        self.assertIs(result, fake_context)
        factory.assert_called_once_with(ssl.PROTOCOL_TLS_CLIENT)
        self.assertTrue(fake_context.check_hostname)
        self.assertEqual(fake_context.verify_mode, ssl.CERT_REQUIRED)
        self.assertEqual(fake_context.minimum_version, ssl.TLSVersion.TLSv1_2)
        fake_context.load_verify_locations.assert_called_once()


class CollectorPairingClientTests(unittest.IsolatedAsyncioTestCase):
    def _client(self, responses: list[_Response]):
        session = _Session(responses)
        client = client_module.CollectorPairingClient(
            session,
            "https://606197c3-cez-pnd-collector:8443",
            object(),
        )
        return client, session

    async def test_claim_sends_exact_verifier_request_without_api_token(self) -> None:
        client, session = self._client(
            [_Response(200, {"pairing_schema_version": 1, "status": "pairing_claimed"})]
        )
        verifier = "b" * 64
        secret = "C" * 43
        await client.async_claim("a" * 32, secret, verifier)
        url, kwargs = session.post_calls[0]
        self.assertEqual(url.rsplit(":8443", 1)[1], "/pairing/v1/claim")
        self.assertEqual(
            kwargs["json"],
            {
                "pairing_schema_version": 1,
                "pairing_id": "a" * 32,
                "pairing_secret": secret,
                "api_token_sha256": verifier,
            },
        )
        self.assertNotIn("Authorization", kwargs["headers"])
        self.assertNotIn(TOKEN, json.dumps(kwargs["json"]))
        self.assertFalse(kwargs["allow_redirects"])
        self.assertIs(kwargs["ssl"], client._ssl_context)

    async def test_claim_inputs_and_timeout_fail_before_secret_exposure(self) -> None:
        client, session = self._client([])
        for pairing_id, secret, verifier in (
            ("invalid", "C" * 43, "b" * 64),
            ("a" * 32, "short", "b" * 64),
            ("a" * 32, "C" * 43, "invalid"),
        ):
            with self.subTest(pairing_id=pairing_id), self.assertRaises(
                client_module.CollectorConfigurationError
            ):
                await client.async_claim(pairing_id, secret, verifier)
        self.assertEqual(session.post_calls, [])

        failing = _FailingPostSession(asyncio.TimeoutError("secret-detail"))
        client = client_module.CollectorPairingClient(
            failing,
            "https://606197c3-cez-pnd-collector:8443",
            object(),
        )
        with self.assertRaisesRegex(
            client_module.CollectorConnectionError, "collector_connection_failed"
        ) as raised:
            await client.async_claim("a" * 32, "C" * 43, "b" * 64)
        self.assertNotIn("secret-detail", str(raised.exception))

    async def test_activation_uses_bearer_and_empty_body(self) -> None:
        client, session = self._client(
            [_Response(200, {"pairing_schema_version": 1, "status": "pairing_activated"})]
        )
        await client.async_activate(TOKEN)
        url, kwargs = session.post_calls[0]
        self.assertEqual(url.rsplit(":8443", 1)[1], "/pairing/v1/activate")
        self.assertEqual(kwargs["headers"]["Authorization"], f"Bearer {TOKEN}")
        self.assertEqual(kwargs["data"], b"")
        self.assertFalse(kwargs["allow_redirects"])

    async def test_finalize_uses_only_fixed_route_bearer_and_empty_body(self) -> None:
        client, session = self._client(
            [_Response(200, {"pairing_schema_version": 1, "status": "pairing_finalized"})]
        )
        await client.async_finalize(TOKEN)
        url, kwargs = session.post_calls[0]
        self.assertEqual(url.rsplit(":8443", 1)[1], "/pairing/v1/finalize")
        self.assertEqual(kwargs["headers"]["Authorization"], f"Bearer {TOKEN}")
        self.assertEqual(kwargs["data"], b"")
        self.assertFalse(kwargs["allow_redirects"])

    async def test_payload_read_failure_is_bounded(self) -> None:
        failure = client_module.aiohttp.ClientPayloadError("secret-detail")
        client = client_module.CollectorPairingClient(
            _FailingPostSession(failure),
            "https://606197c3-cez-pnd-collector:8443",
            object(),
        )
        with self.assertRaisesRegex(
            client_module.CollectorConnectionError, "collector_connection_failed"
        ) as raised:
            await client.async_finalize(TOKEN)
        self.assertNotIn("secret-detail", str(raised.exception))

    async def test_pairing_failures_are_bounded_and_explicit(self) -> None:
        for status, exception in (
            (401, client_module.PairingRejectedError),
            (503, client_module.PairingUnavailableError),
            (302, client_module.PairingUnavailableError),
        ):
            with self.subTest(status=status):
                client, _ = self._client([_Response(status, {})])
                with self.assertRaises(exception):
                    await client.async_claim("a" * 32, "C" * 43, "b" * 64)

    async def test_malformed_duplicate_and_oversized_responses_fail(self) -> None:
        bodies = (
            b'{"pairing_schema_version":1,"pairing_schema_version":1,"status":"pairing_claimed"}',
            b'{"pairing_schema_version":true,"status":"pairing_claimed"}',
            b"{" + b" " * client_module.MAX_PAIRING_RESPONSE_BYTES + b"}",
        )
        for body in bodies:
            with self.subTest(size=len(body)):
                response = _RawResponse(body)
                client, _ = self._client([response])
                with self.assertRaises(client_module.PairingUnavailableError):
                    await client.async_claim("a" * 32, "C" * 43, "b" * 64)


if __name__ == "__main__":
    unittest.main()
