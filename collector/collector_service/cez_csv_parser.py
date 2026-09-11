"""Bounded CEZ PND CSV parser adapted from HACS_CEZD_PND semantics.

Behavioral reference: igracek/HACS_CEZD_PND parser.py and models.py,
Copyright (c) 2026 igracek, used under the MIT License. See
THIRD_PARTY_NOTICES.md. This Collector implementation is HA-independent and
retains missing values instead of converting them to zero.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from decimal import Decimal, InvalidOperation
from pathlib import Path
import unicodedata
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .cez_csv_models import (
    IntervalQuality,
    IntervalRecord,
    ParsedPndData,
    PndChannel,
)


MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_ROWS = 10_000
MAX_COLUMNS = 50
MAX_CELL_CHARACTERS = 128
INTERVAL = timedelta(minutes=15)
SUPPORTED_ENCODINGS = ("utf-8-sig", "utf-8", "cp1250", "iso-8859-2")
SUPPORTED_DELIMITERS = (";", ",")
DEFAULT_SOURCE_TIMEZONE = "Europe/Prague"

_VALID_STATUSES = frozenset(
    {
        "", "1", "a", "ok", "true", "v", "valid", "validni",
        "platna", "platne", "platny", "platna data", "namerena data ok",
        "namerena data, vypadek napeti",
    }
)
_MISSING_STATUSES = frozenset(
    {
        "missing", "n/a", "n / a", "n.a", "n.a.", "n-a", "na", "neznama hodnota", "neznama",
        "nezname", "nedostupna data", "nedostupna", "unknown", "unavailable",
    }
)
_INVALID_STATUSES = frozenset(
    {
        "0", "false", "invalid", "n", "neplatna", "neplatne", "neplatny",
        "neplatna data", "chyba", "chyba mereni",
    }
)
_PLACEHOLDERS = frozenset({"", "-", "--", "n/a", "na", "none", "null"})

_COMBINED_TIME_HEADERS = frozenset(
    {"datum a cas", "datumcas", "datetime", "timestamp", "casove razitko"}
)
_DATE_HEADERS = frozenset({"date", "datum"})
_TIME_HEADERS = frozenset({"cas", "time"})
_VALUE_HEADERS = frozenset({"hodnota", "mnozstvi", "value"})
_UNIT_HEADERS = frozenset({"jednotka", "unit"})
_STATUS_HEADERS = frozenset({"platnost", "status", "stav", "validita", "validity"})
_PROFILE_HEADERS = frozenset({"profil", "profile", "typ profilu", "typ mereni"})

_CONSUMPTION_HEADER_KEYWORDS = ("+a", "+e", "spotreb", "odber")
_PRODUCTION_HEADER_KEYWORDS = ("-a", "-e", "vyrob", "dodavk")

CSV_PARSE_ERROR_CODES = frozenset(
    {
        "csv_file_invalid",
        "csv_file_too_large",
        "csv_encoding_invalid",
        "csv_delimiter_invalid",
        "csv_schema_invalid",
        "csv_row_limit",
        "csv_column_limit",
        "csv_cell_limit",
        "csv_profile_invalid",
        "csv_timestamp_invalid",
        "csv_timestamp_ambiguous",
        "csv_unit_invalid",
        "csv_value_invalid",
        "csv_status_invalid",
        "csv_duplicate_conflict",
        "csv_day_interval_count_invalid",
    }
)


class PndCsvParseError(ValueError):
    """Fail-closed parser error carrying only a fixed non-secret code."""

    def __init__(self, code: str) -> None:
        if code not in CSV_PARSE_ERROR_CODES:
            raise ValueError("unknown CSV parser error code")
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class _Columns:
    combined_time: int | None
    date: int | None
    time: int | None
    value: int
    unit: int | None
    status: int | None
    profile: int | None
    unit_from_header: str | None


@dataclass(frozen=True)
class _RawInterval:
    local_end: datetime
    source_day: date
    value_kwh: Decimal | None
    quality: IntervalQuality


def parse_pnd_file(
    path: Path,
    *,
    source_timezone: str = DEFAULT_SOURCE_TIMEZONE,
    require_complete_days: bool = True,
) -> ParsedPndData:
    """Parse one Collector-owned raw export selected by its exact filename."""

    if path.name == "range-consumption.csv":
        channel = PndChannel.CONSUMPTION
    elif path.name == "range-production.csv":
        channel = PndChannel.PRODUCTION
    else:
        raise PndCsvParseError("csv_file_invalid")
    try:
        if path.is_symlink() or not path.is_file():
            raise PndCsvParseError("csv_file_invalid")
        size = path.stat(follow_symlinks=False).st_size
        if size > MAX_FILE_BYTES:
            raise PndCsvParseError("csv_file_too_large")
        content = path.read_bytes()
    except PndCsvParseError:
        raise
    except OSError as error:
        raise PndCsvParseError("csv_file_invalid") from error
    return parse_pnd_csv(
        content,
        channel=channel,
        source_timezone=source_timezone,
        require_complete_days=require_complete_days,
    )


def parse_pnd_csv(
    content: bytes,
    *,
    channel: PndChannel,
    source_timezone: str = DEFAULT_SOURCE_TIMEZONE,
    require_complete_days: bool = True,
) -> ParsedPndData:
    """Decode and atomically validate a bounded +A or -A CSV profile."""

    if not isinstance(content, bytes) or not content:
        raise PndCsvParseError("csv_file_invalid")
    if len(content) > MAX_FILE_BYTES:
        raise PndCsvParseError("csv_file_too_large")
    if not isinstance(channel, PndChannel):
        raise PndCsvParseError("csv_profile_invalid")
    text, encoding = _decode(content)
    delimiter, rows, header_index, columns = _read_table(text, channel)
    raw = _parse_rows(rows, header_index, columns, channel)
    intervals = _normalize_intervals(raw, channel, source_timezone)
    if require_complete_days:
        _validate_day_counts(intervals, source_timezone)
    return ParsedPndData(
        channel=channel,
        profile=channel.profile_marker,
        encoding=encoding,
        delimiter=delimiter,
        intervals=intervals,
    )


def _decode(content: bytes) -> tuple[str, str]:
    candidates = SUPPORTED_ENCODINGS if content.startswith(b"\xef\xbb\xbf") else SUPPORTED_ENCODINGS[1:]
    for encoding in candidates:
        try:
            return content.decode(encoding, errors="strict"), encoding
        except UnicodeDecodeError:
            continue
    raise PndCsvParseError("csv_encoding_invalid")


def _read_table(text: str, channel: PndChannel) -> tuple[str, list[list[str]], int, _Columns]:
    best: tuple[int, str, list[list[str]], int, _Columns] | None = None
    for delimiter in SUPPORTED_DELIMITERS:
        try:
            rows = list(csv.reader(text.splitlines(), delimiter=delimiter, strict=True))
        except csv.Error:
            continue
        if len(rows) > MAX_ROWS + 32:
            raise PndCsvParseError("csv_row_limit")
        for index, row in enumerate(rows[:32]):
            try:
                _validate_row_bounds(row)
                columns = _identify_columns(row, channel)
            except PndCsvParseError:
                continue
            candidate = (len(row), delimiter, rows, index, columns)
            if best is None or candidate[0] > best[0]:
                best = candidate
            break
    if best is None:
        raise PndCsvParseError("csv_delimiter_invalid")
    _, delimiter, rows, header_index, columns = best
    return delimiter, rows, header_index, columns


def _identify_columns(header: list[str], channel: PndChannel) -> _Columns:
    normalized = [_normalize(cell) for cell in header]
    combined = _find(normalized, _COMBINED_TIME_HEADERS)
    date_column = _find(normalized, _DATE_HEADERS)
    time_column = _find(normalized, _TIME_HEADERS)
    if combined is None and date_column is not None and time_column is None:
        combined = date_column
        date_column = None
    if combined is None and (date_column is None or time_column is None):
        raise PndCsvParseError("csv_schema_invalid")
    expected_keywords = _channel_header_keywords(channel)
    opposite_keywords = _channel_header_keywords(
        PndChannel.PRODUCTION
        if channel is PndChannel.CONSUMPTION
        else PndChannel.CONSUMPTION
    )
    value_candidates = [
        index
        for index, value in enumerate(normalized)
        if value in _VALUE_HEADERS or _contains_keyword(value, expected_keywords)
    ]
    if len(value_candidates) != 1 or any(
        _contains_keyword(value, opposite_keywords) for value in normalized
    ):
        raise PndCsvParseError("csv_profile_invalid")
    value_column = value_candidates[0]
    unit_from_header = _unit_from_text(header[value_column])
    profile_column = _find(normalized, _PROFILE_HEADERS)
    if not any(_contains_keyword(value, expected_keywords) for value in normalized) and profile_column is None:
        raise PndCsvParseError("csv_profile_invalid")
    return _Columns(
        combined,
        date_column,
        time_column,
        value_column,
        _find(normalized, _UNIT_HEADERS),
        _find(normalized, _STATUS_HEADERS),
        profile_column,
        unit_from_header,
    )


def _parse_rows(
    rows: list[list[str]], header_index: int, columns: _Columns, channel: PndChannel
) -> list[_RawInterval]:
    parsed: list[_RawInterval] = []
    data_rows = rows[header_index + 1 :]
    if len(data_rows) > MAX_ROWS:
        raise PndCsvParseError("csv_row_limit")
    for row in data_rows:
        if not row or all(not cell.strip() for cell in row):
            continue
        _validate_row_bounds(row)
        required_index = max(
            index
            for index in (
                columns.combined_time,
                columns.date,
                columns.time,
                columns.value,
                columns.unit,
                columns.status,
                columns.profile,
            )
            if index is not None
        )
        if len(row) <= required_index:
            raise PndCsvParseError("csv_schema_invalid")
        if columns.profile is not None:
            profile = _normalize(row[columns.profile])
            if not _contains_keyword(profile, _channel_header_keywords(channel)) or _contains_keyword(
                profile,
                _channel_header_keywords(
                    PndChannel.PRODUCTION
                    if channel is PndChannel.CONSUMPTION
                    else PndChannel.CONSUMPTION
                ),
            ):
                raise PndCsvParseError("csv_profile_invalid")
        local_end, source_day = _parse_timestamp(row, columns)
        status = _parse_status(row[columns.status] if columns.status is not None else "")
        raw_value = row[columns.value].strip()
        placeholder = _normalize(raw_value) in _PLACEHOLDERS
        if status is IntervalQuality.INVALID:
            value_kwh = None
            quality = IntervalQuality.INVALID
        elif status is IntervalQuality.MISSING or placeholder:
            value_kwh = None
            quality = IntervalQuality.MISSING
        else:
            unit = row[columns.unit] if columns.unit is not None else columns.unit_from_header
            value_kwh = _parse_energy(raw_value, unit)
            quality = IntervalQuality.VALID
        parsed.append(_RawInterval(local_end, source_day, value_kwh, quality))
    if not parsed:
        raise PndCsvParseError("csv_schema_invalid")
    return parsed


def _parse_timestamp(row: list[str], columns: _Columns) -> tuple[datetime, date]:
    if columns.combined_time is not None:
        text = row[columns.combined_time].strip()
    else:
        assert columns.date is not None and columns.time is not None
        text = f"{row[columns.date].strip()} {row[columns.time].strip()}"
    date_text, separator, time_text = text.rpartition(" ")
    if not separator:
        raise PndCsvParseError("csv_timestamp_invalid")
    parsed_date = _parse_date(date_text)
    components = time_text.split(":")
    if len(components) not in {2, 3} or any(not component.isascii() or not component.isdigit() for component in components):
        raise PndCsvParseError("csv_timestamp_invalid")
    hour, minute = int(components[0]), int(components[1])
    second = int(components[2]) if len(components) == 3 else 0
    if hour == 24:
        if minute != 0 or second != 0:
            raise PndCsvParseError("csv_timestamp_invalid")
        return datetime.combine(parsed_date + timedelta(days=1), time()), parsed_date
    if not 0 <= hour <= 23 or not 0 <= minute <= 59 or second != 0:
        raise PndCsvParseError("csv_timestamp_invalid")
    if minute % 15:
        raise PndCsvParseError("csv_timestamp_invalid")
    return datetime.combine(parsed_date, time(hour, minute)), parsed_date


def _parse_date(value: str) -> date:
    for pattern in ("%d.%m.%Y", "%d.%m.%y", "%Y-%m-%d"):
        try:
            return datetime.strptime(value, pattern).date()
        except ValueError:
            continue
    raise PndCsvParseError("csv_timestamp_invalid")


def _parse_status(value: str) -> IntervalQuality:
    normalized = _normalize(value)
    if normalized in _VALID_STATUSES:
        return IntervalQuality.VALID
    if normalized in _MISSING_STATUSES:
        return IntervalQuality.MISSING
    if normalized in _INVALID_STATUSES:
        return IntervalQuality.INVALID
    raise PndCsvParseError("csv_status_invalid")


def _parse_energy(value: str, unit: str | None) -> Decimal:
    normalized_value = value.strip().replace("\u00a0", "").replace(" ", "")
    if "," in normalized_value and "." in normalized_value:
        raise PndCsvParseError("csv_value_invalid")
    normalized_value = normalized_value.replace(",", ".")
    try:
        parsed = Decimal(normalized_value)
    except InvalidOperation as error:
        raise PndCsvParseError("csv_value_invalid") from error
    if not parsed.is_finite() or parsed < 0:
        raise PndCsvParseError("csv_value_invalid")
    normalized_unit = _normalize_unit(unit)
    if normalized_unit == "kw":
        parsed *= Decimal("0.25")
    elif normalized_unit != "kwh":
        raise PndCsvParseError("csv_unit_invalid")
    return parsed


def _normalize_intervals(
    rows: list[_RawInterval], channel: PndChannel, timezone_name: str
) -> tuple[IntervalRecord, ...]:
    try:
        zone = ZoneInfo(timezone_name)
    except (ZoneInfoNotFoundError, ValueError) as error:
        raise PndCsvParseError("csv_timestamp_invalid") from error
    grouped: dict[datetime, list[_RawInterval]] = {}
    for row in rows:
        grouped.setdefault(row.local_end, []).append(row)
    records: dict[tuple[datetime, datetime], IntervalRecord] = {}
    for local_end, occurrences in grouped.items():
        candidates = _utc_candidates(local_end, zone)
        if not candidates:
            raise PndCsvParseError("csv_timestamp_invalid")
        if len(candidates) == 2:
            if len(occurrences) != 2:
                raise PndCsvParseError("csv_timestamp_ambiguous")
            assigned = zip(occurrences, candidates, strict=True)
        else:
            assigned = ((row, candidates[0]) for row in occurrences)
        for raw, end_utc in assigned:
            record = IntervalRecord(
                channel,
                end_utc - INTERVAL,
                end_utc,
                raw.value_kwh,
                raw.quality,
                raw.source_day,
            )
            key = (record.interval_start, record.interval_end)
            existing = records.get(key)
            if existing is None:
                records[key] = record
            elif existing.value_kwh != record.value_kwh or existing.quality is not record.quality:
                raise PndCsvParseError("csv_duplicate_conflict")
    return tuple(sorted(records.values(), key=lambda item: item.interval_start))


def _utc_candidates(local_value: datetime, zone: ZoneInfo) -> tuple[datetime, ...]:
    candidates: set[datetime] = set()
    for fold in (0, 1):
        aware = local_value.replace(tzinfo=zone, fold=fold)
        utc_value = aware.astimezone(UTC)
        if utc_value.astimezone(zone).replace(tzinfo=None) == local_value:
            candidates.add(utc_value)
    return tuple(sorted(candidates))


def _validate_day_counts(records: tuple[IntervalRecord, ...], timezone_name: str) -> None:
    zone = ZoneInfo(timezone_name)
    by_day: dict[date, int] = {}
    for record in records:
        by_day[record.source_day] = by_day.get(record.source_day, 0) + 1
    for source_day, actual in by_day.items():
        start = datetime.combine(source_day, time(), tzinfo=zone).astimezone(UTC)
        end = datetime.combine(source_day + timedelta(days=1), time(), tzinfo=zone).astimezone(UTC)
        expected = int((end - start) / INTERVAL)
        if expected not in {92, 96, 100} or actual != expected:
            raise PndCsvParseError("csv_day_interval_count_invalid")


def _validate_row_bounds(row: list[str]) -> None:
    if len(row) > MAX_COLUMNS:
        raise PndCsvParseError("csv_column_limit")
    if any(len(cell) > MAX_CELL_CHARACTERS for cell in row):
        raise PndCsvParseError("csv_cell_limit")


def _find(values: list[str], candidates: frozenset[str]) -> int | None:
    matches = [index for index, value in enumerate(values) if value in candidates]
    if len(matches) > 1:
        raise PndCsvParseError("csv_schema_invalid")
    return matches[0] if matches else None


def _channel_header_keywords(channel: PndChannel) -> tuple[str, ...]:
    return (
        _CONSUMPTION_HEADER_KEYWORDS
        if channel is PndChannel.CONSUMPTION
        else _PRODUCTION_HEADER_KEYWORDS
    )


def _contains_keyword(value: str, keywords: tuple[str, ...]) -> bool:
    return any(keyword in value for keyword in keywords)


def _normalize(value: str) -> str:
    decomposed = unicodedata.normalize("NFKD", value.strip().casefold())
    return " ".join(
        "".join(character for character in decomposed if not unicodedata.combining(character)).split()
    )


def _unit_from_text(value: str) -> str | None:
    normalized = value.casefold().replace(" ", "")
    if "kwh" in normalized:
        return "kWh"
    if "kw" in normalized:
        return "kW"
    return None


def _normalize_unit(value: str | None) -> str:
    return "" if value is None else value.strip().casefold().replace(" ", "")
