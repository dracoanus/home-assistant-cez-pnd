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
        "dataset_revision": "synthetic-20260801-0001",
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
        "source_status": "synthetic_offline_partial",
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
                    "source_timezone": "Etc/UTC",
                    "source_profile": "synthetic_v1",
                    "collected_at": "2026-08-01T01:00:00Z",
                    "revision": "synthetic-20260801-0001",
                },
                {
                    "channel": "grid_import",
                    "interval_start": "2026-08-01T00:15:00Z",
                    "interval_end": "2026-08-01T00:30:00Z",
                    "value_kwh": None,
                    "quality": "missing",
                    "source_timezone": "Etc/UTC",
                    "source_profile": "synthetic_v1",
                    "collected_at": "2026-08-01T01:00:00Z",
                    "revision": "synthetic-20260801-0001",
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

    def get(self, url: str, **kwargs: object) -> _Response:
        self.calls.append((url, kwargs))
        return self.responses.pop(0)


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
                "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----"
            )
        self.assertIs(result, fake_context)
        factory.assert_called_once_with(ssl.PROTOCOL_TLS_CLIENT)
        self.assertTrue(fake_context.check_hostname)
        self.assertEqual(fake_context.verify_mode, ssl.CERT_REQUIRED)
        self.assertEqual(fake_context.minimum_version, ssl.TLSVersion.TLSv1_2)
        fake_context.load_verify_locations.assert_called_once()


if __name__ == "__main__":
    unittest.main()
