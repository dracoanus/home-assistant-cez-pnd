"""Narrow authenticated Collector API backed by normalized SQLite data."""
from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
from pathlib import Path
import re
import secrets
import sqlite3
from typing import Mapping
from urllib.parse import parse_qs, urlsplit

from .dataset_store import NormalizedDatasetStore, StoredMeasurement
from .security_files import read_private_file

API_SCHEMA_VERSION = "1.0"
API_PREFIX = "/api/v1"
MAX_TARGET_LENGTH = 2048
MAX_RANGE = timedelta(days=60)
MAX_LIMIT = 1000
MAX_CURSOR_LENGTH = 512
EXPECTED_SCOPES = frozenset({"health:read", "status:read", "measurements:read"})
METER_ID_PATTERN = re.compile(r"^mtr_[a-f0-9]{32}$")
SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43,128}$")
CURSOR_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,512}$")
REVISION_PATTERN = re.compile(r"^ds_[a-f0-9]{2,77}$")
UTC_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")

# Stable opaque meter fixture retained for verifier/configuration tests only.
SYNTHETIC_METER_ID = "mtr_7f93b3e31d514db18cd62c0fcaa19a8e"


@dataclass(frozen=True)
class ApiResponse:
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
        return cls.from_mapping(json.loads(read_private_file(path, maximum_bytes=4096).decode("utf-8")))

    @classmethod
    def from_mapping(cls, raw: object) -> TokenVerifier:
        if not isinstance(raw, dict) or set(raw) != {"schema_version", "token_sha256", "meter_id", "scopes"}:
            raise ValueError("invalid token verifier schema")
        if raw["schema_version"] != "1":
            raise ValueError("unsupported token verifier schema")
        digest, meter, scopes = raw["token_sha256"], raw["meter_id"], raw["scopes"]
        if not isinstance(digest, str) or not SHA256_PATTERN.fullmatch(digest):
            raise ValueError("invalid token verifier digest")
        if not isinstance(meter, str) or not METER_ID_PATTERN.fullmatch(meter):
            raise ValueError("invalid opaque meter id")
        if not isinstance(scopes, list) or set(scopes) != EXPECTED_SCOPES:
            raise ValueError("invalid token scopes")
        return cls(digest, meter, frozenset(scopes))

    def authorize(self, authorization: str | None, scope: str) -> bool:
        if scope not in self.scopes or authorization is None:
            return False
        scheme, separator, token = authorization.partition(" ")
        if separator != " " or scheme != "Bearer" or not _valid_token_shape(token):
            return False
        return hmac.compare_digest(hashlib.sha256(token.encode("ascii")).hexdigest(), self.token_sha256)


class CollectorApi:
    """Pure read-only request handler over a persistent normalized dataset."""
    def __init__(self, verifier: TokenVerifier, store: NormalizedDatasetStore | None = None) -> None:
        self._verifier = verifier
        self._store = store or NormalizedDatasetStore()

    def handle(self, method: str, raw_target: str, headers: Mapping[str, str]) -> ApiResponse:
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
        routes = {f"{API_PREFIX}/health": "health:read", f"{API_PREFIX}/status": "status:read", f"{API_PREFIX}/measurements": "measurements:read"}
        scope = routes.get(route)
        if scope is None:
            return self._error(404, "not_found", False, request_id, "unknown")
        if not self._verifier.authorize(_header(headers, "Authorization"), scope):
            return self._error(401, "unauthorized", False, request_id, route)
        if method != "GET":
            return self._error(405, "method_not_allowed", False, request_id, route)
        try:
            query = parse_qs(split.query, keep_blank_values=True, strict_parsing=True, max_num_fields=6)
        except ValueError:
            return self._error(400, "invalid_query", False, request_id, route)
        if any(len(values) != 1 for values in query.values()):
            return self._error(400, "duplicate_query_parameter", False, request_id, route)
        if route.endswith("/health"):
            if query:
                return self._error(400, "unknown_query_parameter", False, request_id, route)
            return ApiResponse(200, {"schema_version": API_SCHEMA_VERSION, "service_status": "ok"}, route, request_id)
        return self._status(query, request_id, route) if route.endswith("/status") else self._measurements(query, request_id, route)

    def _status(self, query: dict[str, list[str]], request_id: str, route: str) -> ApiResponse:
        if set(query) != {"meter_id"}:
            return self._error(400, "invalid_query_fields", False, request_id, route)
        if query["meter_id"][0] != self._verifier.meter_id:
            return self._error(404, "meter_not_found", False, request_id, route)
        try:
            status = self._store.read_status()
        except (OSError, sqlite3.Error):
            return self._error(503, "dataset_storage_unavailable", True, request_id, route)
        if status is None:
            return self._error(503, "dataset_unavailable", True, request_id, route)
        return ApiResponse(200, {"schema_version": API_SCHEMA_VERSION, "meter_id": self._verifier.meter_id,
            "dataset_revision": status.revision, "data_timestamp": status.data_timestamp,
            "last_attempt": status.last_attempt, "last_success": status.last_success,
            "completeness": _completeness(status.state, status.expected_count, status.valid_count, status.missing_count, status.invalid_count),
            "source_status": status.source_status}, route, request_id)

    def _measurements(self, query: dict[str, list[str]], request_id: str, route: str) -> ApiResponse:
        required, allowed = {"meter_id", "start", "end"}, {"meter_id", "start", "end", "limit", "cursor"}
        if not required <= set(query) or not set(query) <= allowed:
            return self._error(400, "invalid_query_fields", False, request_id, route)
        if query["meter_id"][0] != self._verifier.meter_id:
            return self._error(404, "meter_not_found", False, request_id, route)
        start_text, end_text = query["start"][0], query["end"][0]
        try:
            start, end = _parse_utc(start_text), _parse_utc(end_text)
            limit = int(query.get("limit", [str(MAX_LIMIT)])[0])
        except (ValueError, TypeError):
            return self._error(400, "invalid_query_value", False, request_id, route)
        if start >= end or end - start > MAX_RANGE or not 1 <= limit <= MAX_LIMIT:
            return self._error(400, "invalid_query_value", False, request_id, route)
        after = None
        cursor_revision = None
        if "cursor" in query:
            try:
                cursor = _decode_cursor(query["cursor"][0])
                if cursor["start"] != start_text or cursor["end"] != end_text:
                    raise ValueError("cursor range mismatch")
                after = (cursor["interval_start"], cursor["channel"])
                cursor_revision = cursor["revision"]
            except (KeyError, TypeError, ValueError):
                return self._error(400, "invalid_cursor", False, request_id, route)
        try:
            page = self._store.read_measurements(start_text, end_text, limit=limit, after=after)
        except ValueError:
            return self._error(400, "invalid_cursor", False, request_id, route)
        except (OSError, sqlite3.Error):
            return self._error(503, "dataset_storage_unavailable", True, request_id, route)
        if page is None:
            return self._error(503, "dataset_unavailable", True, request_id, route)
        if cursor_revision is not None and cursor_revision != page.status.revision:
            return self._error(400, "invalid_cursor", False, request_id, route)
        selected = page.rows[:limit]
        next_cursor = None
        if len(page.rows) > limit and selected:
            last = selected[-1]
            next_cursor = _encode_cursor(page.status.revision, start_text, end_text, last.interval_start, last.channel)
        values = [_measurement(row) for row in selected if row.quality != "invalid"]
        missing = [_missing(row) for row in selected if row.quality == "missing"]
        state = "empty" if page.expected_count == 0 else ("partial" if page.missing_count or page.invalid_count else "complete")
        completeness = _completeness(state, page.expected_count, page.valid_count, page.missing_count, page.invalid_count)
        completeness.update({"requested_start": start_text, "requested_end": end_text})
        return ApiResponse(200, {"schema_version": API_SCHEMA_VERSION, "meter_id": self._verifier.meter_id,
            "dataset_revision": page.status.revision, "data_timestamp": page.status.data_timestamp,
            "last_attempt": page.status.last_attempt, "last_success": page.status.last_success,
            "completeness": completeness, "source_status": page.status.source_status,
            "values": values, "missing": missing, "next_cursor": next_cursor}, route, request_id)

    @staticmethod
    def _error(status: int, code: str, retryable: bool, request_id: str, route: str) -> ApiResponse:
        return ApiResponse(status, {"schema_version": API_SCHEMA_VERSION, "error": {"code": code, "request_id": request_id, "retryable": retryable}}, route, request_id)


def _completeness(state: str, expected: int, valid: int, missing: int, invalid: int) -> dict[str, object]:
    return {"state": state, "expected_count": expected, "valid_count": valid, "missing_count": missing, "invalid_count": invalid}


def _measurement(row: StoredMeasurement) -> dict[str, object]:
    return {"channel": row.channel, "interval_start": row.interval_start, "interval_end": row.interval_end,
        "value_kwh": row.value_kwh, "quality": row.quality, "source_timezone": row.source_timezone,
        "source_profile": row.source_profile, "collected_at": row.collected_at, "revision": row.revision}


def _missing(row: StoredMeasurement) -> dict[str, object]:
    return {"channel": row.channel, "interval_start": row.interval_start, "interval_end": row.interval_end, "reason": "source_missing"}


def _encode_cursor(revision: str, start: str, end: str, interval_start: str, channel: str) -> str:
    payload = {"v": 1, "revision": revision, "start": start, "end": end, "interval_start": interval_start, "channel": channel}
    return base64.urlsafe_b64encode(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")).decode("ascii").rstrip("=")


def _decode_cursor(value: str) -> dict[str, object]:
    if not isinstance(value, str) or len(value) > MAX_CURSOR_LENGTH or not CURSOR_PATTERN.fullmatch(value):
        raise ValueError("invalid cursor")
    raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    payload = json.loads(raw.decode("ascii"))
    if not isinstance(payload, dict) or set(payload) != {"v", "revision", "start", "end", "interval_start", "channel"}:
        raise ValueError("invalid cursor")
    if payload["v"] != 1 or payload["channel"] not in {"grid_import", "grid_export"}:
        raise ValueError("invalid cursor")
    if not isinstance(payload["revision"], str) or not REVISION_PATTERN.fullmatch(payload["revision"]):
        raise ValueError("invalid cursor")
    for key in ("start", "end", "interval_start"):
        if not isinstance(payload[key], str):
            raise ValueError("invalid cursor")
        _parse_utc(payload[key])
    if _encode_cursor(payload["revision"], payload["start"], payload["end"], payload["interval_start"], payload["channel"]) != value:
        raise ValueError("invalid cursor")
    return payload


def _header(headers: Mapping[str, str], name: str) -> str | None:
    wanted = name.casefold()
    return next((value for key, value in headers.items() if key.casefold() == wanted), None)


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
