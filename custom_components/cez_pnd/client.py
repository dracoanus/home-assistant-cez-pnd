"""Narrow asynchronous client for the local CEZ PND Collector API."""

from __future__ import annotations

import asyncio
import json
import re
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import aiohttp

API_SCHEMA_VERSION = "1.0"
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_COLLECTION_ITEMS = 1000
MAX_TEXT_LENGTH = 255
REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=10, connect=5, sock_read=8)
METER_ID_PATTERN = re.compile(r"^mtr_[a-f0-9]{32}$")
TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43,128}$")
DECIMAL_PATTERN = re.compile(r"^(?:0|[1-9]\d{0,11})(?:\.\d{1,9})?$")


class CollectorError(Exception):
    """Base class for bounded Collector failures."""


class CollectorConfigurationError(CollectorError):
    """Local Collector client configuration is invalid."""


class CollectorAuthenticationError(CollectorError):
    """Collector rejected the limited API credential."""


class CollectorTlsError(CollectorError):
    """Collector TLS identity validation failed."""


class CollectorConnectionError(CollectorError):
    """Collector could not be reached within the request bounds."""


class CollectorHttpError(CollectorError):
    """Collector returned a non-success HTTP response."""

    def __init__(self, status: int) -> None:
        self.status = status
        super().__init__(f"collector returned HTTP status {status}")


class CollectorProtocolError(CollectorError):
    """Collector response violated the bounded API contract."""


@dataclass(frozen=True)
class CollectorCompleteness:
    """Validated completeness summary."""

    state: str
    expected_count: int
    valid_count: int
    missing_count: int
    invalid_count: int


@dataclass(frozen=True)
class CollectorStatus:
    """Validated Collector status."""

    meter_id: str
    dataset_revision: str
    data_timestamp: datetime | None
    last_attempt: datetime | None
    last_success: datetime | None
    completeness: CollectorCompleteness
    source_status: str


@dataclass(frozen=True)
class CollectorMeasurement:
    """One validated measurement interval."""

    channel: str
    interval_start: datetime
    interval_end: datetime
    value_kwh: Decimal | None
    quality: str
    revision: str


@dataclass(frozen=True)
class CollectorMissingInterval:
    """One explicitly missing interval."""

    channel: str
    interval_start: datetime
    interval_end: datetime
    reason: str


@dataclass(frozen=True)
class CollectorMeasurements:
    """Validated immutable measurement page."""

    meter_id: str
    dataset_revision: str
    data_timestamp: datetime | None
    last_attempt: datetime | None
    last_success: datetime | None
    completeness: CollectorCompleteness
    source_status: str
    requested_start: datetime
    requested_end: datetime
    values: tuple[CollectorMeasurement, ...]
    missing: tuple[CollectorMissingInterval, ...]

    @property
    def latest_valid_grid_import(self) -> CollectorMeasurement | None:
        """Return the latest valid grid-import interval, never a missing zero."""

        valid = (
            item
            for item in self.values
            if item.channel == "grid_import"
            and item.quality == "valid"
            and item.value_kwh is not None
        )
        return max(valid, key=lambda item: item.interval_end, default=None)


def normalize_collector_url(value: str) -> str:
    """Validate and normalize the configured HTTPS Collector origin."""

    if not isinstance(value, str) or not value or len(value) > 512:
        raise CollectorConfigurationError("invalid_collector_url")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise CollectorConfigurationError("invalid_collector_url") from error
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or port != 8443
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise CollectorConfigurationError("invalid_collector_url")
    return urlunsplit(("https", parsed.netloc, "", "", ""))


def create_collector_ssl_context(ca_certificate: str) -> ssl.SSLContext:
    """Create an exclusive trust context for the owner-supplied Collector CA."""

    if (
        not isinstance(ca_certificate, str)
        or not ca_certificate
        or len(ca_certificate.encode("utf-8")) > 64 * 1024
        or ("-----BEGIN " + "CERTIFICATE-----") not in ca_certificate
        or "-----END CERTIFICATE-----" not in ca_certificate
    ):
        raise CollectorConfigurationError("invalid_ca_certificate")
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cadata=ca_certificate)
    except (OSError, ValueError, ssl.SSLError) as error:
        raise CollectorConfigurationError("invalid_ca_certificate") from error
    return context


class CollectorClient:
    """Authenticated client exposing only the three Collector read routes."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
        meter_id: str,
        api_token: str,
        ssl_context: ssl.SSLContext,
    ) -> None:
        self._session = session
        self._base_url = normalize_collector_url(base_url)
        if not METER_ID_PATTERN.fullmatch(meter_id):
            raise CollectorConfigurationError("invalid_meter_id")
        if not TOKEN_PATTERN.fullmatch(api_token):
            raise CollectorConfigurationError("invalid_api_token")
        self._meter_id = meter_id
        self._authorization = f"Bearer {api_token}"
        self._ssl_context = ssl_context

    async def async_health(self) -> str:
        """Return the validated service health state."""

        payload = await self._async_get("/api/v1/health")
        _require_exact_keys(payload, {"schema_version", "service_status"})
        _require_schema(payload)
        if payload["service_status"] != "ok":
            raise CollectorProtocolError("invalid_health_status")
        return "ok"

    async def async_status(self) -> CollectorStatus:
        """Return validated status for the configured meter."""

        payload = await self._async_get(
            "/api/v1/status", params={"meter_id": self._meter_id}
        )
        return _parse_status(payload, self._meter_id)

    async def async_measurements(
        self, start: str, end: str
    ) -> CollectorMeasurements:
        """Return one validated bounded measurement response."""

        payload = await self._async_get(
            "/api/v1/measurements",
            params={"meter_id": self._meter_id, "start": start, "end": end},
        )
        return _parse_measurements(payload, self._meter_id)

    async def _async_get(
        self, path: str, params: dict[str, str] | None = None
    ) -> dict[str, Any]:
        url = f"{self._base_url}{path}"
        try:
            async with self._session.get(
                url,
                params=params,
                headers={
                    "Authorization": self._authorization,
                    "Accept": "application/json",
                },
                ssl=self._ssl_context,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False,
            ) as response:
                if 300 <= response.status < 400:
                    raise CollectorProtocolError("collector_redirect_rejected")
                if response.status in (401, 403):
                    raise CollectorAuthenticationError(
                        "collector_authentication_failed"
                    )
                if response.status < 200 or response.status >= 300:
                    raise CollectorHttpError(response.status)
                content_type = response.headers.get("Content-Type", "").split(";", 1)[0]
                if content_type.strip().lower() != "application/json":
                    raise CollectorProtocolError("invalid_content_type")
                body = bytearray()
                async for chunk in response.content.iter_chunked(16 * 1024):
                    body.extend(chunk)
                    if len(body) > MAX_RESPONSE_BYTES:
                        raise CollectorProtocolError("response_too_large")
        except CollectorError:
            raise
        except (
            aiohttp.ClientConnectorCertificateError,
            aiohttp.ClientConnectorSSLError,
            aiohttp.ClientSSLError,
            aiohttp.ServerFingerprintMismatch,
            ssl.SSLError,
        ) as error:
            raise CollectorTlsError("collector_tls_verification_failed") from error
        except (aiohttp.ClientConnectionError, asyncio.TimeoutError) as error:
            raise CollectorConnectionError("collector_connection_failed") from error
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
            raise CollectorProtocolError("invalid_json") from error
        if not isinstance(payload, dict):
            raise CollectorProtocolError("invalid_json_root")
        return payload


def _parse_status(payload: dict[str, Any], expected_meter_id: str) -> CollectorStatus:
    _require_exact_keys(
        payload,
        {
            "schema_version",
            "meter_id",
            "dataset_revision",
            "data_timestamp",
            "last_attempt",
            "last_success",
            "completeness",
            "source_status",
        },
    )
    _require_schema(payload)
    meter_id = _require_meter(payload["meter_id"], expected_meter_id)
    return CollectorStatus(
        meter_id=meter_id,
        dataset_revision=_require_text(payload["dataset_revision"], "dataset_revision"),
        data_timestamp=_parse_nullable_utc(payload["data_timestamp"]),
        last_attempt=_parse_nullable_utc(payload["last_attempt"]),
        last_success=_parse_nullable_utc(payload["last_success"]),
        completeness=_parse_completeness(payload["completeness"], include_range=False),
        source_status=_require_text(payload["source_status"], "source_status"),
    )


def _parse_measurements(
    payload: dict[str, Any], expected_meter_id: str
) -> CollectorMeasurements:
    _require_exact_keys(
        payload,
        {
            "schema_version",
            "meter_id",
            "dataset_revision",
            "data_timestamp",
            "last_attempt",
            "last_success",
            "completeness",
            "source_status",
            "values",
            "missing",
            "next_cursor",
        },
    )
    _require_schema(payload)
    meter_id = _require_meter(payload["meter_id"], expected_meter_id)
    revision = _require_text(payload["dataset_revision"], "dataset_revision")
    values_raw = payload["values"]
    missing_raw = payload["missing"]
    if not isinstance(values_raw, list) or len(values_raw) > MAX_COLLECTION_ITEMS:
        raise CollectorProtocolError("invalid_measurement_values")
    if not isinstance(missing_raw, list) or len(missing_raw) > MAX_COLLECTION_ITEMS:
        raise CollectorProtocolError("invalid_missing_intervals")
    values = tuple(_parse_measurement(item, revision) for item in values_raw)
    missing = tuple(_parse_missing_interval(item) for item in missing_raw)
    next_cursor = payload["next_cursor"]
    if next_cursor is not None:
        raise CollectorProtocolError("unexpected_pagination")
    completeness_raw = payload["completeness"]
    completeness = _parse_completeness(completeness_raw, include_range=True)
    if (
        completeness.valid_count
        + completeness.missing_count
        + completeness.invalid_count
        != completeness.expected_count
        or len(values) != completeness.valid_count + completeness.missing_count
        or sum(item.quality == "valid" for item in values)
        != completeness.valid_count
        or sum(item.quality == "missing" for item in values)
        != completeness.missing_count
        or len(missing) != completeness.missing_count
    ):
        raise CollectorProtocolError("contradictory_completeness")
    return CollectorMeasurements(
        meter_id=meter_id,
        dataset_revision=revision,
        data_timestamp=_parse_nullable_utc(payload["data_timestamp"]),
        last_attempt=_parse_nullable_utc(payload["last_attempt"]),
        last_success=_parse_nullable_utc(payload["last_success"]),
        completeness=completeness,
        source_status=_require_text(payload["source_status"], "source_status"),
        requested_start=_parse_utc(completeness_raw["requested_start"]),
        requested_end=_parse_utc(completeness_raw["requested_end"]),
        values=values,
        missing=missing,
    )


def _parse_completeness(value: Any, include_range: bool) -> CollectorCompleteness:
    expected = {
        "state",
        "expected_count",
        "valid_count",
        "missing_count",
        "invalid_count",
    }
    if include_range:
        expected |= {"requested_start", "requested_end"}
    if not isinstance(value, dict):
        raise CollectorProtocolError("invalid_completeness")
    _require_exact_keys(value, expected)
    if include_range:
        _parse_utc(value["requested_start"])
        _parse_utc(value["requested_end"])
    counts = []
    for key in ("expected_count", "valid_count", "missing_count", "invalid_count"):
        count = value[key]
        if (
            isinstance(count, bool)
            or not isinstance(count, int)
            or not 0 <= count <= MAX_COLLECTION_ITEMS
        ):
            raise CollectorProtocolError("invalid_completeness")
        counts.append(count)
    return CollectorCompleteness(
        state=_require_text(value["state"], "completeness_state"),
        expected_count=counts[0],
        valid_count=counts[1],
        missing_count=counts[2],
        invalid_count=counts[3],
    )


def _parse_measurement(value: Any, revision: str) -> CollectorMeasurement:
    if not isinstance(value, dict):
        raise CollectorProtocolError("invalid_measurement")
    _require_exact_keys(
        value,
        {
            "channel",
            "interval_start",
            "interval_end",
            "value_kwh",
            "quality",
            "source_timezone",
            "source_profile",
            "collected_at",
            "revision",
        },
    )
    channel = _require_text(value["channel"], "channel")
    quality = _require_text(value["quality"], "quality")
    if value["revision"] != revision:
        raise CollectorProtocolError("revision_mismatch")
    interval_start = _parse_utc(value["interval_start"])
    interval_end = _parse_utc(value["interval_end"])
    if interval_start >= interval_end:
        raise CollectorProtocolError("invalid_measurement_interval")
    raw_measurement = value["value_kwh"]
    if quality == "missing":
        if raw_measurement is not None:
            raise CollectorProtocolError("missing_measurement_has_value")
        measurement = None
    elif quality == "valid":
        if not isinstance(raw_measurement, str) or not DECIMAL_PATTERN.fullmatch(
            raw_measurement
        ):
            raise CollectorProtocolError("invalid_measurement_value")
        try:
            measurement = Decimal(raw_measurement)
        except InvalidOperation as error:
            raise CollectorProtocolError("invalid_measurement_value") from error
    else:
        raise CollectorProtocolError("invalid_measurement_quality")
    _require_text(value["source_timezone"], "source_timezone")
    _require_text(value["source_profile"], "source_profile")
    _parse_utc(value["collected_at"])
    return CollectorMeasurement(
        channel=channel,
        interval_start=interval_start,
        interval_end=interval_end,
        value_kwh=measurement,
        quality=quality,
        revision=revision,
    )


def _parse_missing_interval(value: Any) -> CollectorMissingInterval:
    if not isinstance(value, dict):
        raise CollectorProtocolError("invalid_missing_interval")
    _require_exact_keys(value, {"channel", "interval_start", "interval_end", "reason"})
    channel = _require_text(value["channel"], "missing_channel")
    start = _parse_utc(value["interval_start"])
    end = _parse_utc(value["interval_end"])
    if start >= end:
        raise CollectorProtocolError("invalid_missing_interval")
    return CollectorMissingInterval(
        channel=channel,
        interval_start=start,
        interval_end=end,
        reason=_require_text(value["reason"], "missing_reason"),
    )


def _require_schema(payload: dict[str, Any]) -> None:
    if payload.get("schema_version") != API_SCHEMA_VERSION:
        raise CollectorProtocolError("unsupported_schema_version")


def _require_exact_keys(value: dict[str, Any], expected: set[str]) -> None:
    if set(value) != expected:
        raise CollectorProtocolError("unexpected_response_fields")


def _require_meter(value: Any, expected: str) -> str:
    if value != expected:
        raise CollectorProtocolError("meter_id_mismatch")
    return expected


def _require_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_TEXT_LENGTH:
        raise CollectorProtocolError(f"invalid_{field}")
    return value


def _parse_nullable_utc(value: Any) -> datetime | None:
    if value is None:
        return None
    return _parse_utc(value)


def _parse_utc(value: Any) -> datetime:
    if not isinstance(value, str) or len(value) > 40 or not value.endswith("Z"):
        raise CollectorProtocolError("invalid_utc_timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise CollectorProtocolError("invalid_utc_timestamp") from error
    if parsed.tzinfo != timezone.utc:
        raise CollectorProtocolError("invalid_utc_timestamp")
    return parsed
