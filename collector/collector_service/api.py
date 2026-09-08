"""Narrow, authenticated, offline Collector API contract."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import base64
import hashlib
import hmac
import json
from pathlib import Path
import re
import secrets
from typing import Mapping
from urllib.parse import parse_qs, urlsplit

from .security_files import read_private_file


API_SCHEMA_VERSION = "1.0"
API_PREFIX = "/api/v1"
MAX_TARGET_LENGTH = 2048
MAX_RANGE = timedelta(days=60)
MAX_LIMIT = 1000
EXPECTED_SCOPES = frozenset({"health:read", "status:read", "measurements:read"})
METER_ID_PATTERN = re.compile(r"^mtr_[a-f0-9]{32}$")
SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43,128}$")
UTC_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$"
)

SYNTHETIC_METER_ID = "mtr_7f93b3e31d514db18cd62c0fcaa19a8e"
SYNTHETIC_START = datetime(2026, 8, 1, 0, 0, tzinfo=timezone.utc)
SYNTHETIC_END = datetime(2026, 8, 1, 0, 30, tzinfo=timezone.utc)
SYNTHETIC_LAST_ATTEMPT = "2026-08-01T01:00:00Z"
SYNTHETIC_DATA_TIMESTAMP = "2026-08-01T00:15:00Z"
SYNTHETIC_REVISION = "synthetic-20260801-0001"
SYNTHETIC_SECOND_PAGE_CURSOR = "c_syn_9a1d408f5d224428b958"


@dataclass(frozen=True)
class ApiResponse:
    """An allowlisted JSON response."""

    status: int
    body: dict[str, object]
    route: str
    request_id: str


@dataclass(frozen=True)
class TokenVerifier:
    """Single-client, single-meter read-only token verifier."""

    token_sha256: str
    meter_id: str
    scopes: frozenset[str]

    @classmethod
    def from_file(cls, path: Path) -> TokenVerifier:
        raw = json.loads(read_private_file(path, maximum_bytes=4096).decode("utf-8"))
        return cls.from_mapping(raw)

    @classmethod
    def from_mapping(cls, raw: object) -> TokenVerifier:
        """Validate a token verifier supplied by a trusted configuration boundary."""

        if not isinstance(raw, dict) or set(raw) != {
            "schema_version",
            "token_sha256",
            "meter_id",
            "scopes",
        }:
            raise ValueError("invalid token verifier schema")
        if raw["schema_version"] != "1":
            raise ValueError("unsupported token verifier schema")
        token_sha256 = raw["token_sha256"]
        meter_id = raw["meter_id"]
        scopes = raw["scopes"]
        if not isinstance(token_sha256, str) or not SHA256_PATTERN.fullmatch(token_sha256):
            raise ValueError("invalid token verifier digest")
        if not isinstance(meter_id, str) or not METER_ID_PATTERN.fullmatch(meter_id):
            raise ValueError("invalid opaque meter id")
        if not isinstance(scopes, list) or set(scopes) != EXPECTED_SCOPES:
            raise ValueError("invalid token scopes")
        return cls(token_sha256, meter_id, frozenset(scopes))

    def authorize(self, authorization: str | None, scope: str) -> bool:
        if scope not in self.scopes or authorization is None:
            return False
        scheme, separator, token = authorization.partition(" ")
        if separator != " " or scheme != "Bearer" or not _valid_token_shape(token):
            return False
        candidate = hashlib.sha256(token.encode("ascii")).hexdigest()
        return hmac.compare_digest(candidate, self.token_sha256)


class CollectorApi:
    """Pure request handler for the initial read-only API."""

    def __init__(self, verifier: TokenVerifier) -> None:
        self._verifier = verifier

    def handle(
        self,
        method: str,
        raw_target: str,
        headers: Mapping[str, str],
    ) -> ApiResponse:
        request_id = secrets.token_hex(8)
        if len(raw_target) > MAX_TARGET_LENGTH:
            return self._error(414, "request_target_too_long", False, request_id, "unknown")

        try:
            split = urlsplit(raw_target)
        except ValueError:
            return self._error(400, "invalid_request_target", False, request_id, "unknown")
        if split.scheme or split.netloc or split.fragment:
            return self._error(400, "invalid_request_target", False, request_id, "unknown")

        route = split.path
        routes = {
            f"{API_PREFIX}/health": "health:read",
            f"{API_PREFIX}/status": "status:read",
            f"{API_PREFIX}/measurements": "measurements:read",
        }
        scope = routes.get(route)
        if scope is None:
            return self._error(404, "not_found", False, request_id, "unknown")

        if not self._verifier.authorize(_header(headers, "Authorization"), scope):
            return self._error(401, "unauthorized", False, request_id, route)
        if method != "GET":
            return self._error(405, "method_not_allowed", False, request_id, route)

        try:
            query = parse_qs(
                split.query,
                keep_blank_values=True,
                strict_parsing=True,
                max_num_fields=6,
            )
        except ValueError:
            return self._error(400, "invalid_query", False, request_id, route)
        if any(len(values) != 1 for values in query.values()):
            return self._error(400, "duplicate_query_parameter", False, request_id, route)

        if route.endswith("/health"):
            if query:
                return self._error(400, "unknown_query_parameter", False, request_id, route)
            return ApiResponse(
                200,
                {
                    "schema_version": API_SCHEMA_VERSION,
                    "service_status": "ok",
                },
                route,
                request_id,
            )
        if route.endswith("/status"):
            return self._status(query, request_id, route)
        return self._measurements(query, request_id, route)

    def _status(
        self, query: dict[str, list[str]], request_id: str, route: str
    ) -> ApiResponse:
        if set(query) != {"meter_id"}:
            return self._error(400, "invalid_query_fields", False, request_id, route)
        if query["meter_id"][0] != self._verifier.meter_id:
            return self._error(404, "meter_not_found", False, request_id, route)
        return ApiResponse(
            200,
            {
                "schema_version": API_SCHEMA_VERSION,
                "meter_id": self._verifier.meter_id,
                "dataset_revision": SYNTHETIC_REVISION,
                "data_timestamp": SYNTHETIC_DATA_TIMESTAMP,
                "last_attempt": SYNTHETIC_LAST_ATTEMPT,
                "last_success": None,
                "completeness": {
                    "state": "partial",
                    "expected_count": 2,
                    "valid_count": 1,
                    "missing_count": 1,
                    "invalid_count": 0,
                },
                "source_status": "synthetic_offline_partial",
            },
            route,
            request_id,
        )

    def _measurements(
        self, query: dict[str, list[str]], request_id: str, route: str
    ) -> ApiResponse:
        required = {"meter_id", "start", "end"}
        allowed = required | {"limit", "cursor"}
        if not required <= set(query) or not set(query) <= allowed:
            return self._error(400, "invalid_query_fields", False, request_id, route)
        if query["meter_id"][0] != self._verifier.meter_id:
            return self._error(404, "meter_not_found", False, request_id, route)
        cursor = query.get("cursor", [""])[0]
        if cursor not in {"", SYNTHETIC_SECOND_PAGE_CURSOR}:
            return self._error(400, "invalid_cursor", False, request_id, route)
        try:
            start = _parse_utc(query["start"][0])
            end = _parse_utc(query["end"][0])
            limit = int(query.get("limit", [str(MAX_LIMIT)])[0])
        except (ValueError, TypeError):
            return self._error(400, "invalid_query_value", False, request_id, route)
        if start >= end or end - start > MAX_RANGE or not 1 <= limit <= MAX_LIMIT:
            return self._error(400, "invalid_query_value", False, request_id, route)
        if start != SYNTHETIC_START or end != SYNTHETIC_END:
            return self._error(400, "unsupported_synthetic_range", False, request_id, route)

        values: list[dict[str, object]] = [
            {
                "channel": "grid_import",
                "interval_start": "2026-08-01T00:00:00Z",
                "interval_end": "2026-08-01T00:15:00Z",
                "value_kwh": "0.125",
                "quality": "valid",
                "source_timezone": "Etc/UTC",
                "source_profile": "synthetic_v1",
                "collected_at": SYNTHETIC_LAST_ATTEMPT,
                "revision": SYNTHETIC_REVISION,
            },
            {
                "channel": "grid_import",
                "interval_start": "2026-08-01T00:15:00Z",
                "interval_end": "2026-08-01T00:30:00Z",
                "value_kwh": None,
                "quality": "missing",
                "source_timezone": "Etc/UTC",
                "source_profile": "synthetic_v1",
                "collected_at": SYNTHETIC_LAST_ATTEMPT,
                "revision": SYNTHETIC_REVISION,
            },
        ]
        offset = 1 if cursor == SYNTHETIC_SECOND_PAGE_CURSOR else 0
        page = values[offset : offset + limit]
        next_cursor = (
            SYNTHETIC_SECOND_PAGE_CURSOR
            if offset == 0 and offset + limit < len(values)
            else None
        )
        return ApiResponse(
            200,
            {
                "schema_version": API_SCHEMA_VERSION,
                "meter_id": self._verifier.meter_id,
                "dataset_revision": SYNTHETIC_REVISION,
                "data_timestamp": SYNTHETIC_DATA_TIMESTAMP,
                "last_attempt": SYNTHETIC_LAST_ATTEMPT,
                "last_success": None,
                "completeness": {
                    "state": "partial",
                    "requested_start": "2026-08-01T00:00:00Z",
                    "requested_end": "2026-08-01T00:30:00Z",
                    "expected_count": 2,
                    "valid_count": 1,
                    "missing_count": 1,
                    "invalid_count": 0,
                },
                "source_status": "synthetic_offline_partial",
                "values": page,
                "missing": [
                    {
                        "channel": "grid_import",
                        "interval_start": "2026-08-01T00:15:00Z",
                        "interval_end": "2026-08-01T00:30:00Z",
                        "reason": "synthetic_missing_interval",
                    }
                ],
                "next_cursor": next_cursor,
            },
            route,
            request_id,
        )

    @staticmethod
    def _error(
        status: int,
        code: str,
        retryable: bool,
        request_id: str,
        route: str,
    ) -> ApiResponse:
        return ApiResponse(
            status,
            {
                "schema_version": API_SCHEMA_VERSION,
                "error": {
                    "code": code,
                    "request_id": request_id,
                    "retryable": retryable,
                },
            },
            route,
            request_id,
        )


def _header(headers: Mapping[str, str], name: str) -> str | None:
    wanted = name.casefold()
    for key, value in headers.items():
        if key.casefold() == wanted:
            return value
    return None


def _valid_token_shape(token: str) -> bool:
    if not token.isascii() or not TOKEN_PATTERN.fullmatch(token):
        return False
    try:
        decoded = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
    except (ValueError, UnicodeEncodeError):
        return False
    return len(decoded) >= 32


def _parse_utc(value: str) -> datetime:
    if not UTC_PATTERN.fullmatch(value):
        raise ValueError("UTC Z suffix required")
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    if parsed.tzinfo != timezone.utc:
        raise ValueError("UTC required")
    return parsed
