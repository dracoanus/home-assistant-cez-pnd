"""Focused offline tests for the one-shot authenticated CEZ data probe."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
import io
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
from urllib.parse import parse_qs, urlsplit

from collector_service import (
    cez_data_probe,
    cez_http_auth,
    requests_preauth,
    runtime_config,
    server,
)
from collector_service.cez_csv_models import IntervalQuality, IntervalRecord, ParsedPndData, PndChannel
from collector_service.dataset_store import NormalizedDatasetStore


GLOBAL_IP = "93.184.216.34"
LOGIN_URL = "https://mepas.cez.cz/cas/login?service=opaque"
FORM = b'''<html><form method="post" action="/cas/login">
<input name="username"><input name="password" type="password">
</form></html>'''
FINAL_APP = b"<html><main id='app'></main></html>"
CONSUMPTION = b"private-consumption-csv\n"
PRODUCTION = b"private-production-csv\n"
TEST_EAN = "8" * 18
OTHER_TEST_EAN = "7" * 18
MATCHED_METADATA = b'{"meters":[{"elm":"secret-elm"}]}'


def _parsed(channel: PndChannel) -> ParsedPndData:
    start = datetime(2026, 9, 8, tzinfo=UTC)
    return ParsedPndData(channel, channel.profile_marker, "utf-8", ";", (
        IntervalRecord(channel, start, start + timedelta(minutes=15), Decimal("1.25"), IntervalQuality.VALID, date(2026, 9, 8)),
    ))


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

    def iter_content(self, chunk_size: int):
        return iter(self.chunks)

    def close(self) -> None:
        pass


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


class _ProbeClient:
    def __init__(
        self, responses: list[cez_http_auth.HttpResponse | BaseException]
    ) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, cez_http_auth.AuthState, dict[str, str]]] = []

    def new_operation_deadline(self) -> float:
        return 60.0

    def request_data_probe(
        self,
        url: str,
        state: cez_http_auth.AuthState,
        deadline: float,
        *,
        extra_headers: dict[str, str] | None = None,
    ) -> cez_http_auth.HttpResponse:
        self.calls.append((url, state, dict(extra_headers or {})))
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response


def _configuration(
    elm: str | None = "secret-elm", ean: str | None = None
) -> runtime_config.DataProbeConfiguration:
    return runtime_config.DataProbeConfiguration(
        "private-user", "private-password", date(2026, 9, 8), elm, ean
    )


def _http_response(
    status: int, body: bytes, content_type: str = "application/json"
) -> cez_http_auth.HttpResponse:
    return cez_http_auth.HttpResponse(
        status, (("Content-Type", content_type),), body
    )


def _resolver(hostname: str, port: int) -> tuple[str, ...]:
    assert hostname in cez_http_auth.REVIEWED_HOSTNAMES
    assert port == 443
    return (GLOBAL_IP,)


def _successful_session() -> _Session:
    metadata = b'{"idDeviceSet":"secret-device","meters":[{"elm":"secret-elm"}]}'
    return _Session(
        [
            _Response(302, _Headers(Location=LOGIN_URL), (b"",)),
            _Response(200, _Headers(), (FORM,)),
            _Response(
                302,
                _Headers(Location=cez_http_auth.CEZ_PND_START_URL),
                (b"",),
            ),
            _Response(200, _Headers({"Content-Type": "text/html"}), (FINAL_APP,)),
            _Response(200, _Headers({"Content-Type": "application/json"}), (metadata,)),
            _Response(200, _Headers({"Content-Type": "text/csv"}), (CONSUMPTION,)),
            _Response(
                200,
                _Headers({"Content-Type": "application/octet-stream"}),
                (PRODUCTION,),
            ),
        ]
    )


class CezDataProbeTests(unittest.TestCase):
    def _metadata_failure(
        self,
        response: cez_http_auth.HttpResponse,
        configuration: runtime_config.DataProbeConfiguration | None = None,
    ) -> tuple[str, dict[str, object], dict[str, object]]:
        events: list[cez_http_auth.SafeHttpAuthEvent] = []
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "probe"
            probe = cez_data_probe.CezDataProbe(
                configuration or _configuration(None),
                output_directory=output,
                emit=events.append,
            )
            with self.assertRaises(cez_http_auth._AuthFailure) as raised:
                probe.collect(_ProbeClient([response]))  # type: ignore[arg-type]
            summary = json.loads(
                (output / cez_data_probe.METADATA_SUMMARY_NAME).read_text()
            )
        observed = next(
            event.as_dict()
            for event in events
            if event.event == "dashboard_metadata_response_observed"
        )
        return raised.exception.code, observed, summary

    def test_mode_is_explicit_and_mutually_exclusive(self) -> None:
        self.assertIsNone(runtime_config._load_data_probe_configuration({}))
        base = {
            "cez_data_probe_mode": True,
            "cez_data_probe_date": "2026-09-08",
            "cez_username": "private-user",
            "cez_password": "private-password",
        }
        loaded = runtime_config._load_data_probe_configuration(base)
        self.assertEqual(loaded.probe_date, date(2026, 9, 8))
        for other in (
            "cez_discovery_mode",
            "cez_http_auth_discovery_mode",
            "cez_requests_preauth_compatibility_mode",
        ):
            with self.subTest(other=other), self.assertRaises(
                runtime_config.DiscoveryConfigurationError
            ) as raised:
                runtime_config._validate_discovery_modes({**base, other: True})
            self.assertEqual(raised.exception.code, "discovery_config_conflicting_modes")

    def test_ean_and_elm_configuration_validation(self) -> None:
        base = {
            "cez_data_probe_mode": True,
            "cez_data_probe_date": "2026-09-08",
            "cez_username": "private-user",
            "cez_password": "private-password",
        }
        loaded = runtime_config._load_data_probe_configuration(
            {**base, "cez_ean": TEST_EAN, "cez_elm": "private-elm"}
        )
        self.assertEqual(loaded.ean, TEST_EAN)
        self.assertEqual(loaded.electrometer_id, "private-elm")
        for invalid in ("1" * 17, "1" * 19, "1" * 17 + "x", "１" * 18):
            with self.subTest(ean=invalid), self.assertRaises(
                runtime_config.DiscoveryConfigurationError
            ) as raised:
                runtime_config._load_data_probe_configuration(
                    {**base, "cez_ean": invalid}
                )
            self.assertEqual(raised.exception.code, "data_probe_config_invalid_ean")
        for invalid in (" private", "private ", "x" * 129, "private\nvalue"):
            with self.subTest(elm=invalid), self.assertRaises(
                runtime_config.DiscoveryConfigurationError
            ) as raised:
                runtime_config._load_data_probe_configuration(
                    {**base, "cez_elm": invalid}
                )
            self.assertEqual(raised.exception.code, "data_probe_config_invalid_elm")

    def test_invalid_or_missing_probe_date_fails_closed(self) -> None:
        base = {
            "cez_data_probe_mode": True,
            "cez_username": "private-user",
            "cez_password": "private-password",
        }
        for value, code in (
            (None, "data_probe_config_missing_date"),
            ("08.09.2026", "data_probe_config_invalid_date"),
            ("2026-09-08 ", "data_probe_config_invalid_date"),
            ("2026-02-30", "data_probe_config_invalid_date"),
        ):
            options = dict(base)
            if value is not None:
                options["cez_data_probe_date"] = value
            with self.subTest(value=value), self.assertRaises(
                runtime_config.DiscoveryConfigurationError
            ) as raised:
                runtime_config._load_data_probe_configuration(options)
            self.assertEqual(raised.exception.code, code)

    def test_same_authenticated_session_fetches_metadata_and_both_exports(self) -> None:
        session = _successful_session()
        transport = requests_preauth.RequestsSessionTransport(
            resolver=_resolver, session_factory=lambda: session
        )
        events: list[cez_http_auth.SafeHttpAuthEvent] = []
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "probe"
            store = NormalizedDatasetStore(Path(temporary) / "dataset.sqlite3", required_uid=None)
            timestamps = iter((datetime(2026, 9, 8, tzinfo=UTC), datetime(2026, 9, 8, 1, tzinfo=UTC)))
            with mock.patch.object(cez_data_probe, "parse_pnd_csv", side_effect=[_parsed(PndChannel.CONSUMPTION), _parsed(PndChannel.PRODUCTION)]):
                result = cez_data_probe.run_data_probe(
                    _configuration(), transport, resolver=transport.resolve,
                    output_directory=output, dataset_store=store,
                    now=lambda: next(timestamps), emit=events.append,
                )
            self.assertEqual(result.status, cez_http_auth.AuthStatus.AUTHENTICATED)
            self.assertEqual(len(session.calls), 7)
            self.assertEqual(session.calls[4][1], cez_http_auth.CEZ_PND_DASHBOARD_DATA_URL)
            export_calls = session.calls[5:]
            self.assertTrue(all(urlsplit(call[1]).path == "/cezpnd2/external/data/export" for call in export_calls))
            for _, _, request in export_calls:
                self.assertFalse(request["allow_redirects"])
                self.assertEqual(request["headers"]["Accept"], "*/*")
                self.assertEqual(
                    request["headers"]["Referer"], cez_http_auth.CEZ_PND_START_URL
                )
                self.assertEqual(
                    request["headers"]["User-Agent"],
                    cez_http_auth.CEZ_HTTP_USER_AGENT,
                )
            queries = [parse_qs(urlsplit(call[1]).query) for call in export_calls]
            self.assertEqual([query["idAssembly"] for query in queries], [["-1001"], ["-1002"]])
            for query in queries:
                self.assertEqual(query["format"], ["csv"])
                self.assertEqual(query["intervalFrom"], ["08.09.2026 00:00"])
                self.assertEqual(query["intervalTo"], ["09.09.2026 00:00"])
                self.assertEqual(query["idDeviceSet"], ["secret-device"])
                self.assertEqual(query["electrometerId"], ["secret-elm"])
            self.assertEqual((output / cez_data_probe.CONSUMPTION_NAME).read_bytes(), CONSUMPTION)
            self.assertEqual((output / cez_data_probe.PRODUCTION_NAME).read_bytes(), PRODUCTION)
            summary = json.loads((output / cez_data_probe.METADATA_SUMMARY_NAME).read_text())
            self.assertEqual(summary["schema_version"], "1")
            self.assertTrue(summary["dashboard_json_object"])
            self.assertTrue(summary["id_device_set_present"])
            self.assertEqual(summary["id_device_set_type"], "string")
            self.assertTrue(summary["meter_collection_present"])
            self.assertEqual(summary["collection_types"], {"meters": "array"})
            self.assertEqual(summary["top_level_key_count"], 2)
            self.assertEqual(summary["top_level_keys"], ["idDeviceSet", "meters"])
            self.assertEqual(summary["consumption_bytes"], len(CONSUMPTION))
            self.assertEqual(summary["production_bytes"], len(PRODUCTION))
            self.assertEqual(store.read_status().last_attempt, "2026-09-08T00:00:00Z")
            self.assertEqual(store.read_status().last_success, "2026-09-08T01:00:00Z")
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
                for name in (
                    cez_data_probe.METADATA_SUMMARY_NAME,
                    cez_data_probe.CONSUMPTION_NAME,
                    cez_data_probe.PRODUCTION_NAME,
                ):
                    self.assertEqual(
                        stat.S_IMODE((output / name).stat().st_mode), 0o600
                    )
        self.assertTrue(session.closed)
        self.assertTrue(session.cookies.cleared)
        rendered = repr([event.as_dict() for event in events])
        for secret in (
            "private-user",
            "private-password",
            "secret-device",
            "secret-elm",
            "private-consumption-csv",
            "private-production-csv",
        ):
            self.assertNotIn(secret, rendered)
        expected = [
            "data_probe_started",
            "authenticated",
            "dashboard_metadata_response_observed",
            "dashboard_metadata_verified",
            "data_probe_export_response_observed",
            "consumption_export_received",
            "data_probe_complete",
            "http_auth_cleanup_complete",
        ]
        names = [event.event for event in events]
        filtered = [name for name in names if name in expected]
        self.assertEqual(filtered.count("data_probe_export_response_observed"), 2)
        self.assertLess(
            filtered.index("consumption_export_received"),
            filtered.index("data_probe_complete"),
        )
        self.assertIn("production_export_received", names)
        self.assertIn("data_probe_consumption_parsed", names)
        self.assertIn("data_probe_production_parsed", names)
        self.assertIn("data_probe_dataset_committed", names)

    def test_automatic_collection_does_not_persist_raw_responses(self) -> None:
        session = _successful_session()
        transport = requests_preauth.RequestsSessionTransport(
            resolver=_resolver, session_factory=lambda: session
        )
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "must-not-exist"
            store = NormalizedDatasetStore(
                Path(temporary) / "dataset.sqlite3", required_uid=None
            )
            timestamps = iter(
                (
                    datetime(2026, 9, 8, tzinfo=UTC),
                    datetime(2026, 9, 8, 1, tzinfo=UTC),
                )
            )
            with mock.patch.object(
                cez_data_probe,
                "parse_pnd_csv",
                side_effect=[
                    _parsed(PndChannel.CONSUMPTION),
                    _parsed(PndChannel.PRODUCTION),
                ],
            ):
                result = cez_data_probe.run_data_probe(
                    _configuration(),
                    transport,
                    resolver=transport.resolve,
                    output_directory=output,
                    dataset_store=store,
                    persist_raw_outputs=False,
                    now=lambda: next(timestamps),
                    emit=lambda _event: None,
                )
            self.assertEqual(result.status, cez_http_auth.AuthStatus.AUTHENTICATED)
            self.assertFalse(output.exists())
            self.assertIsNotNone(store.read_status())

    def test_bounded_ranges_use_inclusive_start_and_exclusive_end(self) -> None:
        cases = (
            (date(2026, 3, 1), date(2026, 4, 1), "01.03.2026 00:00", "01.04.2026 00:00"),
            (date(2026, 10, 1), date(2026, 11, 1), "01.10.2026 00:00", "01.11.2026 00:00"),
        )
        for start_day, end_day, expected_from, expected_to in cases:
            with self.subTest(start_day=start_day), tempfile.TemporaryDirectory() as temporary:
                session = _successful_session()
                transport = requests_preauth.RequestsSessionTransport(
                    resolver=_resolver, session_factory=lambda: session
                )
                store = NormalizedDatasetStore(
                    Path(temporary) / "dataset.sqlite3", required_uid=None
                )
                timestamps = iter(
                    (
                        datetime(2026, 9, 8, tzinfo=UTC),
                        datetime(2026, 9, 8, 1, tzinfo=UTC),
                    )
                )
                with mock.patch.object(
                    cez_data_probe,
                    "parse_pnd_csv",
                    side_effect=[
                        _parsed(PndChannel.CONSUMPTION),
                        _parsed(PndChannel.PRODUCTION),
                    ],
                ):
                    result = cez_data_probe.run_data_probe(
                        _configuration(),
                        transport,
                        resolver=transport.resolve,
                        dataset_store=store,
                        persist_raw_outputs=False,
                        start_day=start_day,
                        end_day=end_day,
                        now=lambda: next(timestamps),
                        emit=lambda _event: None,
                    )
                self.assertEqual(
                    result.status, cez_http_auth.AuthStatus.AUTHENTICATED
                )
                queries = [
                    parse_qs(urlsplit(call[1]).query) for call in session.calls[5:]
                ]
                self.assertEqual(len(queries), 2)
                for query in queries:
                    self.assertEqual(query["intervalFrom"], [expected_from])
                    self.assertEqual(query["intervalTo"], [expected_to])

    def test_collection_range_is_bounded_to_31_days(self) -> None:
        with self.assertRaisesRegex(ValueError, "invalid collection range"):
            cez_data_probe.CezDataProbe(
                _configuration(),
                start_day=date(2026, 1, 1),
                end_day=date(2026, 2, 2),
            )

    def test_meter_identity_is_required(self) -> None:
        client = _ProbeClient(
            [
                _http_response(200, b"{}"),
            ]
        )
        with tempfile.TemporaryDirectory() as temporary, self.assertRaises(
            cez_http_auth._AuthFailure
        ) as raised:
            cez_data_probe.CezDataProbe(
                _configuration(None), output_directory=Path(temporary) / "probe"
            ).collect(client)  # type: ignore[arg-type]
        self.assertEqual(raised.exception.code, "data_probe_meter_identity_required")

    def test_non_200_metadata_remains_request_failure(self) -> None:
        events: list[cez_http_auth.SafeHttpAuthEvent] = []
        with self.assertRaises(cez_http_auth._AuthFailure) as raised:
            cez_data_probe.CezDataProbe(
                _configuration(None), emit=events.append
            ).collect(_ProbeClient([_http_response(503, b"{}")] ))  # type: ignore[arg-type]
        self.assertEqual(raised.exception.code, "data_probe_metadata_failed")
        self.assertNotIn(
            "dashboard_metadata_response_observed",
            [event.event for event in events],
        )

    def test_metadata_failure_subcodes_are_distinct(self) -> None:
        cases = (
            (
                _http_response(200, b"{}", "text/html"),
                _configuration(None),
                "data_probe_metadata_content_type_invalid",
            ),
            (
                _http_response(200, b"\xff"),
                _configuration(None),
                "data_probe_metadata_utf8_invalid",
            ),
            (
                _http_response(200, b"not-json"),
                _configuration(None),
                "data_probe_metadata_json_invalid",
            ),
            (
                _http_response(200, b'{"idDeviceSet":true}'),
                _configuration(None),
                "data_probe_metadata_id_device_set_invalid",
            ),
            (
                _http_response(200, b'{"meters":{}}'),
                _configuration(None),
                "data_probe_metadata_meter_collection_invalid",
            ),
        )
        for response, configuration, expected in cases:
            with self.subTest(expected=expected):
                code, observed, summary = self._metadata_failure(
                    response, configuration
                )
                self.assertEqual(code, expected)
                self.assertEqual(observed["status"], 200)
                self.assertEqual(summary["status"], 200)

    def test_empty_meter_lookup_is_best_effort_with_configured_elm(self) -> None:
        events: list[cez_http_auth.SafeHttpAuthEvent] = []
        client = _ProbeClient(
            [
                _http_response(200, b'{"meters":[]}'),
                _http_response(200, b"[]"),
                _http_response(200, b"consumption\n", "text/csv"),
                _http_response(200, b"production\n", "text/csv"),
            ]
        )
        with tempfile.TemporaryDirectory() as temporary:
            cez_data_probe.CezDataProbe(
                _configuration(),
                output_directory=Path(temporary) / "probe",
                emit=events.append,
            ).collect(client)  # type: ignore[arg-type]
        self.assertIn(
            {"event": "data_probe_meter_lookup_unavailable", "reason": "empty", "status": 200},
            [event.as_dict() for event in events],
        )

    def test_live_array_metadata_is_best_effort_and_exports_continue(self) -> None:
        events: list[cez_http_auth.SafeHttpAuthEvent] = []
        client = _ProbeClient(
            [
                _http_response(200, b'[{"private":"value"}]'),
                _http_response(200, b'[{"elm":"secret-elm"}]'),
                _http_response(200, b"consumption\n", "text/csv"),
                _http_response(200, b"production\n", "text/csv"),
            ]
        )
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "probe"
            cez_data_probe.CezDataProbe(
                _configuration(), output_directory=output, emit=events.append
            ).collect(client)  # type: ignore[arg-type]
            summary = json.loads(
                (output / cez_data_probe.METADATA_SUMMARY_NAME).read_text()
            )
        self.assertFalse(summary["dashboard_json_object"])
        self.assertFalse(summary["id_device_set_present"])
        self.assertEqual(summary["json_root_type"], "array")
        self.assertIn(
            {
                "event": "dashboard_metadata_unusable",
                "json_root_type": "array",
            },
            [event.as_dict() for event in events],
        )
        self.assertNotIn(
            "dashboard_metadata_verified", [event.event for event in events]
        )
        self.assertEqual(len(client.calls), 4)
        for url, state, _ in client.calls[2:]:
            self.assertEqual(state, cez_http_auth.AuthState.DATA_PROBE_EXPORT)
            query = parse_qs(urlsplit(url).query)
            self.assertNotIn("idDeviceSet", query)
            self.assertEqual(query["electrometerId"], ["secret-elm"])
        self.assertEqual(
            [parse_qs(urlsplit(call[0]).query)["idAssembly"] for call in client.calls[2:]],
            [["-1001"], ["-1002"]],
        )

    def test_configured_elm_uses_exact_meters_fallback_without_logging_values(self) -> None:
        events: list[cez_http_auth.SafeHttpAuthEvent] = []
        private_elm = "secret-elm"
        client = _ProbeClient(
            [
                _http_response(200, b"[]"),
                _http_response(200, b'[{"elm":"secret-elm"}]'),
                _http_response(200, b"consumption\n", "text/csv"),
                _http_response(200, b"production\n", "text/csv"),
            ]
        )
        with tempfile.TemporaryDirectory() as temporary:
            cez_data_probe.CezDataProbe(
                _configuration(private_elm),
                output_directory=Path(temporary) / "probe",
                emit=events.append,
            ).collect(client)  # type: ignore[arg-type]
        meters_url, meters_state, meters_headers = client.calls[1]
        self.assertEqual(meters_url, cez_data_probe.CEZ_PND_METERS_URL)
        self.assertEqual(meters_state, cez_http_auth.AuthState.DATA_PROBE_METERS)
        self.assertEqual(meters_headers, {"Accept": "*/*"})
        for url, _, _ in client.calls[2:]:
            self.assertEqual(
                parse_qs(urlsplit(url).query)["electrometerId"], [private_elm]
            )
        self.assertNotIn(
            private_elm, json.dumps([event.as_dict() for event in events])
        )

    def test_unavailable_meter_lookup_is_best_effort_with_configured_elm(self) -> None:
        cases: tuple[
            tuple[cez_http_auth.HttpResponse | BaseException, str, int | None], ...
        ] = (
            (cez_http_auth._AuthFailure("auth_transport_failed"), "request_failed", None),
            (cez_http_auth._AuthFailure("auth_operation_timeout"), "request_failed", None),
            (_http_response(503, b"failure"), "status", 503),
            (_http_response(200, b"[]", "text/plain"), "content_type", 200),
            (_http_response(200, b"not-json"), "json", 200),
            (_http_response(200, b"{}"), "root_type", 200),
            (_http_response(200, b"[]"), "empty", 200),
        )
        for meter_response, reason, status in cases:
            with self.subTest(reason=reason, response=type(meter_response).__name__):
                events: list[cez_http_auth.SafeHttpAuthEvent] = []
                client = _ProbeClient(
                    [
                        _http_response(200, b"[]"),
                        meter_response,
                        _http_response(200, b"consumption\n", "text/csv"),
                        _http_response(200, b"production\n", "text/csv"),
                    ]
                )
                with tempfile.TemporaryDirectory() as temporary:
                    cez_data_probe.CezDataProbe(
                        _configuration(),
                        output_directory=Path(temporary) / "probe",
                        emit=events.append,
                    ).collect(client)  # type: ignore[arg-type]
                observed = next(
                    event.as_dict()
                    for event in events
                    if event.event == "data_probe_meter_lookup_unavailable"
                )
                expected: dict[str, object] = {
                    "event": "data_probe_meter_lookup_unavailable",
                    "reason": reason,
                }
                if status is not None:
                    expected["status"] = status
                self.assertEqual(observed, expected)
                self.assertIn("consumption_export_received", [event.event for event in events])
                self.assertIn("production_export_received", [event.event for event in events])
                for url, _, _ in client.calls[2:]:
                    query = parse_qs(urlsplit(url).query)
                    self.assertEqual(query["electrometerId"], ["secret-elm"])

    def test_invalid_utf8_meter_lookup_is_best_effort_with_configured_elm(self) -> None:
        client, events, error = self._run_unavailable_meter_lookup(
            _configuration(), _http_response(200, b"\xff")
        )
        self.assertIsNone(error)
        self.assertEqual(
            next(
                event.as_dict()["reason"]
                for event in events
                if event.event == "data_probe_meter_lookup_unavailable"
            ),
            "utf8",
        )
        self.assertEqual(
            parse_qs(urlsplit(client.calls[2][0]).query)["electrometerId"],
            ["secret-elm"],
        )

    def test_ean_and_elm_use_best_effort_when_lookup_is_unavailable(self) -> None:
        client, events, error = self._run_unavailable_meter_lookup(
            _configuration("private-elm", TEST_EAN),
            cez_http_auth._AuthFailure("auth_transport_failed"),
        )
        self.assertIsNone(error)
        self.assertEqual(
            parse_qs(urlsplit(client.calls[2][0]).query)["electrometerId"],
            ["private-elm"],
        )
        rendered = json.dumps([event.as_dict() for event in events])
        self.assertNotIn(TEST_EAN, rendered)
        self.assertNotIn("private-elm", rendered)

    def test_ean_only_lookup_failure_is_fatal(self) -> None:
        _, events, error = self._run_unavailable_meter_lookup(
            _configuration(None, TEST_EAN),
            cez_http_auth._AuthFailure("auth_operation_timeout"),
        )
        self.assertEqual(error, "data_probe_meter_lookup_failed")
        self.assertIn(
            {"event": "data_probe_meter_lookup_unavailable", "reason": "request_failed"},
            [event.as_dict() for event in events],
        )

    def _run_unavailable_meter_lookup(
        self,
        configuration: runtime_config.DataProbeConfiguration,
        meter_response: cez_http_auth.HttpResponse | BaseException,
    ) -> tuple[_ProbeClient, list[cez_http_auth.SafeHttpAuthEvent], str | None]:
        client = _ProbeClient(
            [
                _http_response(200, b"[]"),
                meter_response,
                _http_response(200, b"consumption\n", "text/csv"),
                _http_response(200, b"production\n", "text/csv"),
            ]
        )
        events: list[cez_http_auth.SafeHttpAuthEvent] = []
        error_code = None
        with tempfile.TemporaryDirectory() as temporary:
            try:
                cez_data_probe.CezDataProbe(
                    configuration,
                    output_directory=Path(temporary) / "probe",
                    emit=events.append,
                ).collect(client)  # type: ignore[arg-type]
            except cez_http_auth._AuthFailure as error:
                error_code = error.code
        return client, events, error_code

    def _run_meter_selection(
        self,
        configuration: runtime_config.DataProbeConfiguration,
        meters: list[object],
    ) -> tuple[
        _ProbeClient,
        list[cez_http_auth.SafeHttpAuthEvent],
        str | None,
    ]:
        client = _ProbeClient(
            [
                _http_response(200, b"[]"),
                _http_response(200, json.dumps(meters).encode()),
                _http_response(200, b"consumption\n", "text/csv"),
                _http_response(200, b"production\n", "text/csv"),
            ]
        )
        events: list[cez_http_auth.SafeHttpAuthEvent] = []
        error_code = None
        with tempfile.TemporaryDirectory() as temporary:
            try:
                cez_data_probe.CezDataProbe(
                    configuration,
                    output_directory=Path(temporary) / "probe",
                    emit=events.append,
                ).collect(client)  # type: ignore[arg-type]
            except cez_http_auth._AuthFailure as error:
                error_code = error.code
        return client, events, error_code

    def test_both_ean_and_elm_require_same_exact_meter(self) -> None:
        client, events, error = self._run_meter_selection(
            _configuration("private-elm", TEST_EAN),
            [{"ean": TEST_EAN, "elm": "private-elm", "ignored": "private"}],
        )
        self.assertIsNone(error)
        observed = next(
            event.as_dict()
            for event in events
            if event.event == "data_probe_meter_selection_observed"
        )
        self.assertEqual(observed["selection_mode"], "both")
        self.assertEqual(observed["matches_by_ean"], 1)
        self.assertEqual(observed["matches_by_elm"], 1)
        for url, _, _ in client.calls[2:]:
            query = parse_qs(urlsplit(url).query)
            self.assertEqual(query["electrometerId"], ["private-elm"])
            self.assertNotIn("ean", {key.lower() for key in query})

    def test_ean_only_extracts_verified_elm_in_memory(self) -> None:
        client, events, error = self._run_meter_selection(
            _configuration(None, TEST_EAN),
            [{"ean": TEST_EAN, "elm": "derived-private-elm"}],
        )
        self.assertIsNone(error)
        for url, _, _ in client.calls[2:]:
            query = parse_qs(urlsplit(url).query)
            self.assertEqual(query["electrometerId"], ["derived-private-elm"])
            self.assertNotIn("ean", {key.lower() for key in query})
        rendered = json.dumps([event.as_dict() for event in events])
        self.assertNotIn(TEST_EAN, rendered)
        self.assertNotIn("derived-private-elm", rendered)

    def test_elm_only_selects_exactly_one_meter(self) -> None:
        client, events, error = self._run_meter_selection(
            _configuration("private-elm"),
            [{"ean": TEST_EAN, "elm": "private-elm"}],
        )
        self.assertIsNone(error)
        self.assertEqual(
            next(
                event.as_dict()["selection_mode"]
                for event in events
                if event.event == "data_probe_meter_selection_observed"
            ),
            "elm_only",
        )
        self.assertTrue(
            all(
                parse_qs(urlsplit(url).query)["electrometerId"] == ["private-elm"]
                for url, _, _ in client.calls[2:]
            )
        )

    def test_meter_identity_mismatch_is_rejected_without_secret_diagnostics(self) -> None:
        _, events, error = self._run_meter_selection(
            _configuration("private-elm", TEST_EAN),
            [
                {"ean": TEST_EAN, "elm": "other-private-elm"},
                {"ean": OTHER_TEST_EAN, "elm": "private-elm"},
            ],
        )
        self.assertEqual(error, "data_probe_meter_identity_mismatch")
        observed = next(
            event.as_dict()
            for event in events
            if event.event == "data_probe_meter_selection_observed"
        )
        self.assertEqual(observed["selection_mode"], "mismatch")
        rendered = json.dumps(observed)
        for private in (
            TEST_EAN,
            OTHER_TEST_EAN,
            "private-elm",
            "other-private-elm",
        ):
            self.assertNotIn(private, rendered)

    def test_zero_and_multiple_meter_matches_fail_closed(self) -> None:
        cases = (
            ([{"ean": OTHER_TEST_EAN, "elm": "other"}], "data_probe_meter_not_found", "none"),
            ([{"ean": TEST_EAN, "elm": "first"}, {"ean": TEST_EAN, "elm": "second"}], "data_probe_meter_selection_ambiguous", "ambiguous"),
            ([{"ean": TEST_EAN, "elm": "same"}, {"ean": TEST_EAN, "elm": "same"}], "data_probe_meter_selection_ambiguous", "ambiguous"),
        )
        for meters, expected, mode in cases:
            with self.subTest(expected=expected):
                _, events, error = self._run_meter_selection(
                    _configuration(None, TEST_EAN), meters
                )
                self.assertEqual(error, expected)
                observed = next(
                    event.as_dict()
                    for event in events
                    if event.event == "data_probe_meter_selection_observed"
                )
                self.assertEqual(observed["selection_mode"], mode)

    def test_meter_endpoint_requires_list_root(self) -> None:
        client = _ProbeClient(
            [_http_response(200, b"[]"), _http_response(200, b'{"elm":"private-elm"}')]
        )
        events: list[cez_http_auth.SafeHttpAuthEvent] = []
        with tempfile.TemporaryDirectory() as temporary, self.assertRaises(
            cez_http_auth._AuthFailure
        ) as raised:
            cez_data_probe.CezDataProbe(
                _configuration(None, TEST_EAN),
                output_directory=Path(temporary) / "probe",
                emit=events.append,
            ).collect(client)  # type: ignore[arg-type]
        self.assertEqual(raised.exception.code, "data_probe_meter_lookup_failed")
        observed = next(
            event.as_dict()
            for event in events
            if event.event == "data_probe_meter_lookup_unavailable"
        )
        self.assertEqual(observed["reason"], "root_type")
        self.assertEqual(observed["status"], 200)

    def test_structural_observation_contains_only_bounded_safe_schema(self) -> None:
        private_values = (
            "private-device-value",
            "private-ean-value",
            "private-elm-value",
            "private-nested-value",
        )
        payload: dict[str, object] = {
            "idDeviceSet": private_values[0],
            "meters": [{"ean": private_values[1], "elm": private_values[2]}],
            "nested": {"secret": private_values[3]},
            "unsafe key": "hidden",
            "x" * 65: "hidden",
        }
        payload.update({f"safeKey{index}": None for index in range(60)})
        response = _http_response(
            200,
            json.dumps(payload).encode(),
            "Application/JSON; charset=UTF-8",
        )
        events: list[cez_http_auth.SafeHttpAuthEvent] = []
        with tempfile.TemporaryDirectory() as temporary:
            probe = cez_data_probe.CezDataProbe(
                _configuration(None),
                output_directory=Path(temporary) / "probe",
                emit=events.append,
            )
            probe._validate_metadata(response)
            summary = json.loads(
                (
                    Path(temporary)
                    / "probe"
                    / cez_data_probe.METADATA_SUMMARY_NAME
                ).read_text()
            )
        observed = events[0].as_dict()
        self.assertEqual(observed["content_type_base"], "application/json")
        self.assertEqual(observed["json_root_type"], "object")
        self.assertTrue(observed["json_parseable"])
        self.assertEqual(observed["top_level_key_count"], len(payload))
        self.assertLessEqual(len(observed["top_level_keys"]), 50)
        self.assertIn("[redacted-key]", observed["top_level_keys"])
        self.assertEqual(observed["collection_types"], {"meters": "array"})
        self.assertTrue(observed["id_device_set_present"])
        self.assertEqual(observed["id_device_set_type"], "string")
        rendered = json.dumps({"event": observed, "summary": summary})
        for private in private_values:
            self.assertNotIn(private, rendered)
        self.assertNotIn("secret", rendered)
        self.assertNotIn("ean", rendered.lower())
        self.assertNotIn("elm", rendered.lower())

    def test_invalid_json_and_exception_details_never_enter_diagnostics(self) -> None:
        private_text = "private-parser-detail"
        code, observed, summary = self._metadata_failure(
            _http_response(200, private_text.encode())
        )
        self.assertEqual(code, "data_probe_metadata_json_invalid")
        rendered = json.dumps({"event": observed, "summary": summary})
        self.assertNotIn(private_text, rendered)
        self.assertEqual(observed["json_root_type"], "unknown")
        self.assertFalse(observed["json_parseable"])

    def test_metadata_and_export_redirects_fail_closed(self) -> None:
        redirect = cez_http_auth.HttpResponse(
            302, (("Location", cez_http_auth.CEZ_PND_START_URL),), b""
        )
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "probe"
            client = _ProbeClient([redirect])
            with self.assertRaises(cez_http_auth._AuthFailure) as raised:
                cez_data_probe.CezDataProbe(
                    _configuration(None), output_directory=output
                ).collect(client)  # type: ignore[arg-type]
            self.assertEqual(raised.exception.code, "data_probe_metadata_failed")

            client = _ProbeClient([_http_response(200, MATCHED_METADATA), redirect])
            with self.assertRaises(cez_http_auth._AuthFailure) as raised:
                cez_data_probe.CezDataProbe(
                    _configuration(), output_directory=output
                ).collect(client)  # type: ignore[arg-type]
            self.assertEqual(
                raised.exception.code, "data_probe_consumption_export_status_failed"
            )

            client = _ProbeClient(
                [
                    _http_response(200, MATCHED_METADATA),
                    _http_response(200, b"csv\n", "text/csv"),
                    redirect,
                ]
            )
            with self.assertRaises(cez_http_auth._AuthFailure) as raised:
                cez_data_probe.CezDataProbe(
                    _configuration(), output_directory=output
                ).collect(client)  # type: ignore[arg-type]
            self.assertEqual(
                raised.exception.code, "data_probe_production_export_status_failed"
            )

    def test_html_empty_and_oversized_exports_are_rejected(self) -> None:
        cases = (
            (
                _http_response(200, b"", "text/csv"),
                "data_probe_consumption_export_empty",
            ),
            (
                _http_response(200, b"<html><form></form></html>", "text/html"),
                "data_probe_consumption_export_html_rejected",
            ),
            (
                _http_response(
                    200,
                    b"x" * (cez_http_auth.MAX_RESPONSE_BODY_BYTES + 1),
                    "text/csv",
                ),
                "data_probe_consumption_export_too_large",
            ),
            (
                _http_response(200, b'{"error":true}', "application/json"),
                "data_probe_consumption_export_content_type_invalid",
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "probe"
            for response, expected in cases:
                client = _ProbeClient([_http_response(200, MATCHED_METADATA), response])
                with self.subTest(expected=expected), self.assertRaises(
                    cez_http_auth._AuthFailure
                ) as raised:
                    cez_data_probe.CezDataProbe(
                        _configuration(), output_directory=output
                    ).collect(client)  # type: ignore[arg-type]
                self.assertEqual(raised.exception.code, expected)

    def test_export_observation_is_structural_and_channel_specific(self) -> None:
        private_body = b"private-household-csv\n"
        response = cez_http_auth.HttpResponse(
            503,
            (
                ("Content-Type", "Text/Plain; charset=utf-8"),
                ("Content-Disposition", "private-filename"),
                ("Content-Encoding", "private-encoding"),
            ),
            private_body,
        )
        events: list[cez_http_auth.SafeHttpAuthEvent] = []
        client = _ProbeClient([_http_response(200, MATCHED_METADATA), response])
        with tempfile.TemporaryDirectory() as temporary, self.assertRaises(
            cez_http_auth._AuthFailure
        ) as raised:
            cez_data_probe.CezDataProbe(
                _configuration(),
                output_directory=Path(temporary) / "probe",
                emit=events.append,
            ).collect(client)  # type: ignore[arg-type]
        self.assertEqual(
            raised.exception.code, "data_probe_consumption_export_status_failed"
        )
        observed = next(
            event.as_dict()
            for event in events
            if event.event == "data_probe_export_response_observed"
        )
        self.assertEqual(observed["channel"], "consumption")
        self.assertEqual(observed["status"], 503)
        self.assertEqual(observed["body_bytes"], len(private_body))
        self.assertEqual(observed["content_type_base"], "text/plain")
        self.assertFalse(observed["body_empty"])
        self.assertFalse(observed["body_limit_exceeded"])
        self.assertFalse(observed["looks_like_html"])
        self.assertFalse(observed["looks_like_login"])
        self.assertFalse(observed["looks_like_json"])
        self.assertTrue(observed["content_disposition_present"])
        self.assertTrue(observed["content_encoding_present"])
        rendered = json.dumps(observed)
        self.assertNotIn(private_body.decode().strip(), rendered)
        self.assertNotIn("private-filename", rendered)
        self.assertNotIn("private-encoding", rendered)

    def test_atomic_writes_overwrite_without_accumulating_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "probe"
            output.mkdir()
            (output / cez_data_probe.CONSUMPTION_NAME).write_bytes(b"old")
            probe = cez_data_probe.CezDataProbe(
                _configuration(None), output_directory=output
            )
            probe._store(b"{}", b"new-consumption", b"new-production")
            probe._store(b"{}", b"newer-consumption", b"newer-production")
            self.assertEqual(
                {path.name for path in output.iterdir()},
                {
                    cez_data_probe.METADATA_SUMMARY_NAME,
                    cez_data_probe.CONSUMPTION_NAME,
                    cez_data_probe.PRODUCTION_NAME,
                },
            )
            self.assertEqual(
                (output / cez_data_probe.CONSUMPTION_NAME).read_bytes(),
                b"newer-consumption",
            )

    def test_exact_probe_destination_contract_rejects_subpaths(self) -> None:
        for state, url in (
            (
                cez_http_auth.AuthState.DATA_PROBE_METADATA,
                cez_http_auth.CEZ_PND_DASHBOARD_DATA_URL + "/extra",
            ),
            (
                cez_http_auth.AuthState.DATA_PROBE_EXPORT,
                cez_data_probe.CEZ_PND_EXPORT_URL + "/extra",
            ),
            (
                cez_http_auth.AuthState.DATA_PROBE_METERS,
                cez_data_probe.CEZ_PND_METERS_URL + "/extra",
            ),
        ):
            with self.subTest(state=state), self.assertRaises(
                cez_http_auth._AuthFailure
            ) as raised:
                cez_http_auth.validate_destination(url, state, "GET", _resolver)
            self.assertEqual(raised.exception.code, "auth_destination_rejected")

    def test_storage_failure_is_fail_closed_and_session_is_cleaned(self) -> None:
        session = _successful_session()
        transport = requests_preauth.RequestsSessionTransport(
            resolver=_resolver, session_factory=lambda: session
        )
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            cez_data_probe.CezDataProbe, "_store", side_effect=OSError("private")
        ):
            result = cez_data_probe.run_data_probe(
                _configuration(), transport, resolver=transport.resolve,
                dataset_store=NormalizedDatasetStore(Path(temporary) / "dataset.sqlite3", required_uid=None),
            )
        self.assertEqual(result.status, cez_http_auth.AuthStatus.FAILED)
        self.assertEqual(result.code, "data_probe_storage_failed")
        self.assertTrue(session.closed)
        self.assertTrue(session.cookies.cleared)

    def test_parser_failure_does_not_replace_previous_dataset(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            events: list[cez_http_auth.SafeHttpAuthEvent] = []
            store = NormalizedDatasetStore(Path(temporary) / "dataset.sqlite3", required_uid=None,
                revision_factory=lambda: "ds_" + "b" * 32)
            previous = store.commit_dataset(_parsed(PndChannel.CONSUMPTION),
                _parsed(PndChannel.PRODUCTION), collected_at=datetime(2026, 9, 8, tzinfo=UTC))
            probe = cez_data_probe.CezDataProbe(_configuration(),
                output_directory=Path(temporary) / "raw", dataset_store=store,
                collected_at=datetime(2026, 9, 9, tzinfo=UTC), emit=events.append)
            client = _ProbeClient([
                _http_response(200, MATCHED_METADATA),
                _http_response(200, CONSUMPTION, "text/csv"),
                _http_response(200, PRODUCTION, "text/csv"),
            ])
            with mock.patch.object(cez_data_probe, "parse_pnd_csv",
                side_effect=cez_data_probe.PndCsvParseError("csv_schema_invalid")), self.assertRaises(cez_http_auth._AuthFailure) as raised:
                probe.collect(client)  # type: ignore[arg-type]
            self.assertEqual(raised.exception.code, "data_probe_consumption_parse_failed")
            self.assertEqual(store.read_status().revision, previous.revision)
            diagnostic = next(event.as_dict() for event in events if event.event == "data_probe_csv_parse_failed")
            self.assertEqual(diagnostic, {
                "event": "data_probe_csv_parse_failed",
                "channel": "consumption",
                "code": "csv_schema_invalid",
            })
            for forbidden in ("private-consumption-csv", "secret-elm", "2026-09-09"):
                self.assertNotIn(forbidden, repr(diagnostic))
            with self.assertRaises(ValueError):
                cez_http_auth.DataProbeCsvParseFailureObservation("consumption", "arbitrary")

    def test_server_selects_explicit_data_probe_mode(self) -> None:
        configuration = SimpleNamespace(
            discovery=None,
            requests_preauth_compatibility=False,
            data_probe=_configuration(),
            http_auth_discovery=None,
        )
        result = cez_http_auth.AuthResult(
            cez_http_auth.AuthStatus.AUTHENTICATED,
            "auth_authenticated_endpoint_verified",
        )
        fake_transport = mock.Mock()
        fake_transport.resolve = mock.Mock()
        output = io.StringIO()
        with mock.patch.object(
            server.os, "geteuid", return_value=2000, create=True
        ), mock.patch.object(
            server.os, "getegid", return_value=2000, create=True
        ), mock.patch.object(
            server, "load_runtime_configuration", return_value=configuration
        ), mock.patch(
            "collector_service.requests_preauth.RequestsSessionTransport",
            return_value=fake_transport,
        ), mock.patch(
            "collector_service.cez_data_probe.run_data_probe", return_value=result
        ) as run, mock.patch(
            "sys.stdout", output
        ):
            self.assertEqual(server.main(), 0)
        run.assert_called_once_with(
            configuration.data_probe,
            fake_transport,
            resolver=fake_transport.resolve,
            emit=cez_http_auth.emit_json_event,
        )
        self.assertEqual(json.loads(output.getvalue())["event"], "http_auth_result")


if __name__ == "__main__":
    unittest.main()
