"""Offline regression tests for the bounded CEZ PND CSV parser."""

from __future__ import annotations

import csv
from datetime import UTC, date, datetime, time, timedelta
from decimal import Decimal
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from zoneinfo import ZoneInfo

from collector_service.cez_csv_models import IntervalQuality, PndChannel
from collector_service import cez_csv_parser
from collector_service.cez_csv_parser import (
    MAX_CELL_CHARACTERS,
    MAX_COLUMNS,
    PndCsvParseError,
    parse_pnd_csv,
    parse_pnd_file,
)


def _csv_bytes(
    rows: list[list[str]], *, delimiter: str = ";", encoding: str = "utf-8"
) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, delimiter=delimiter, lineterminator="\n")
    writer.writerows(rows)
    return stream.getvalue().encode(encoding)


def _single(
    *,
    channel: PndChannel = PndChannel.CONSUMPTION,
    timestamp: str = "01.01.2026 00:15",
    value: str = "1,25",
    unit: str = "kWh",
    status: str = "OK",
    delimiter: str = ";",
) -> bytes:
    return _csv_bytes(
        [
            ["Datum a čas", "Profil", "Hodnota", "Jednotka", "Status"],
            [timestamp, channel.profile_marker, value, unit, status],
        ],
        delimiter=delimiter,
    )


def _complete_day(day: date, channel: PndChannel) -> bytes:
    zone = ZoneInfo("Europe/Prague")
    start = datetime.combine(day, time(), tzinfo=zone).astimezone(UTC)
    finish = datetime.combine(day + timedelta(days=1), time(), tzinfo=zone).astimezone(UTC)
    rows = [["Datum a čas", "Profil", "Hodnota", "Jednotka", "Status"]]
    instant = start + timedelta(minutes=15)
    while instant <= finish:
        local = instant.astimezone(zone)
        if instant == finish:
            timestamp = f"{day.strftime('%d.%m.%Y')} 24:00"
        else:
            timestamp = local.strftime("%d.%m.%Y %H:%M")
        rows.append([timestamp, channel.profile_marker, "1", "kWh", "OK"])
        instant += timedelta(minutes=15)
    return _csv_bytes(rows)


def _complete_day_with_statuses(
    day: date, channel: PndChannel, statuses: tuple[str, ...]
) -> bytes:
    rows = list(csv.reader(io.StringIO(_complete_day(day, channel).decode("utf-8")), delimiter=";"))
    if len(rows) - 1 != len(statuses):
        raise ValueError("status fixture length mismatch")
    for row, status in zip(rows[1:], statuses, strict=True):
        row[-1] = status
    return _csv_bytes(rows)


class CezCsvParserTests(unittest.TestCase):
    def test_real_cez_datum_timestamp_and_profile_headers(self) -> None:
        for channel, header in (
            (PndChannel.CONSUMPTION, "+A/profile [kW]"),
            (PndChannel.PRODUCTION, "-A/profile [kW]"),
        ):
            with self.subTest(channel=channel):
                parsed = parse_pnd_csv(
                    _csv_bytes([
                        ["Datum", header, "Status"],
                        ["10.09.2026 00:15:00", "0,309", "naměřená data OK"],
                    ]),
                    channel=channel,
                    require_complete_days=False,
                )
                self.assertEqual(parsed.intervals[0].value_kwh, Decimal("0.07725"))

    def test_combined_and_split_timestamp_headers_remain_supported(self) -> None:
        combined = parse_pnd_csv(
            _single(timestamp="10.09.2026 00:15:00"),
            channel=PndChannel.CONSUMPTION,
            require_complete_days=False,
        )
        split = parse_pnd_csv(
            _csv_bytes([
                ["Datum", "Čas", "+A [kWh]", "Status"],
                ["10.09.2026", "00:15:00", "1,25", "platná data"],
            ]),
            channel=PndChannel.CONSUMPTION,
            require_complete_days=False,
        )
        self.assertEqual(combined.intervals[0].interval_end, split.intervals[0].interval_end)

    def test_upstream_profile_header_keywords_select_only_expected_channel(self) -> None:
        cases = (
            (PndChannel.CONSUMPTION, "+E [kWh]"),
            (PndChannel.CONSUMPTION, "Spotřeba [kWh]"),
            (PndChannel.CONSUMPTION, "Odběr [kWh]"),
            (PndChannel.PRODUCTION, "-E [kWh]"),
            (PndChannel.PRODUCTION, "Výroba [kWh]"),
            (PndChannel.PRODUCTION, "Dodávka [kWh]"),
        )
        for channel, header in cases:
            with self.subTest(channel=channel, header=header):
                parsed = parse_pnd_csv(
                    _csv_bytes([["Datum", header, "Status"], ["10.09.2026 00:15", "1", "OK"]]),
                    channel=channel,
                    require_complete_days=False,
                )
                self.assertEqual(parsed.channel, channel)

    def test_real_cez_status_semantics_are_distinct_and_unknown_fails(self) -> None:
        cases = {
            IntervalQuality.VALID: (
                "platná", "platna data", "naměřená data OK", "OK", "valid", "platné",
            ),
            IntervalQuality.MISSING: (
                "neznámá hodnota", "neznámá", "neznámé", "nedostupná data",
                "nedostupná", "unknown", "unavailable", "N/A",
            ),
            IntervalQuality.INVALID: (
                "neplatná data", "neplatná", "neplatné", "invalid", "chyba", "chyba měření",
            ),
        }
        for quality, statuses in cases.items():
            for status in statuses:
                with self.subTest(status=status):
                    parsed = parse_pnd_csv(
                        _csv_bytes([["Datum", "+A [kWh]", "Status"], ["10.09.2026 00:15", "1", status]]),
                        channel=PndChannel.CONSUMPTION,
                        require_complete_days=False,
                    )
                    record = parsed.intervals[0]
                    self.assertEqual(record.quality, quality)
                    if quality is not IntervalQuality.VALID:
                        self.assertIsNone(record.value_kwh)
        with self.assertRaises(PndCsvParseError) as raised:
            parse_pnd_csv(
                _csv_bytes([["Datum", "+A [kWh]", "Status"], ["10.09.2026 00:15", "1", "nový stav"]]),
                channel=PndChannel.CONSUMPTION,
                require_complete_days=False,
            )
        self.assertEqual(raised.exception.code, "csv_status_invalid")

    def test_voltage_outage_status_is_valid_and_preserves_numeric_value(self) -> None:
        for status, value, expected in (
            ("naměřená data, výpadek napětí", "1,25", Decimal("1.25")),
            ("namerena data, vypadek napeti", "0", Decimal("0")),
        ):
            with self.subTest(status=status, value=value):
                parsed = parse_pnd_csv(
                    _csv_bytes(
                        [["Datum", "+A [kWh]", "Status"], ["07.10.2025 07:45", value, status]]
                    ),
                    channel=PndChannel.CONSUMPTION,
                    require_complete_days=False,
                )
                record = parsed.intervals[0]
                self.assertEqual(record.quality, IntervalQuality.VALID)
                self.assertEqual(record.value_kwh, expected)

        invalid = parse_pnd_csv(
            _csv_bytes(
                [["Datum", "+A [kWh]", "Status"], ["07.10.2025 08:00", "9", "neplatná data"]]
            ),
            channel=PndChannel.CONSUMPTION,
            require_complete_days=False,
        ).intervals[0]
        self.assertEqual(invalid.quality, IntervalQuality.INVALID)
        self.assertIsNone(invalid.value_kwh)

        with self.assertRaises(PndCsvParseError) as raised:
            parse_pnd_csv(
                _csv_bytes(
                    [["Datum", "+A [kWh]", "Status"], ["07.10.2025 08:15", "1", "libovolný stav"]]
                ),
                channel=PndChannel.CONSUMPTION,
                require_complete_days=False,
            )
        self.assertEqual(raised.exception.code, "csv_status_invalid")

    def test_complete_day_accepts_mixed_official_cez_statuses(self) -> None:
        statuses = (
            *("naměřená data OK" for _ in range(76)),
            *("neplatná data" for _ in range(18)),
            "naměřená data, výpadek napětí",
            "naměřená data, výpadek napětí",
        )
        parsed = parse_pnd_csv(
            _complete_day_with_statuses(
                date(2025, 10, 7), PndChannel.CONSUMPTION, statuses
            ),
            channel=PndChannel.CONSUMPTION,
        )
        self.assertEqual(len(parsed.intervals), 96)
        self.assertEqual(parsed.valid_count, 78)
        self.assertEqual(parsed.invalid_count, 18)
        self.assertEqual(parsed.missing_count, 0)
        self.assertFalse(parsed.complete)

    def test_encoding_and_delimiter_detection(self) -> None:
        rows = [
            ["Datum a čas", "Profil", "Hodnota", "Jednotka", "Stav"],
            ["01.01.2026 00:15", "+A", "1,5", "kWh", "Platná"],
        ]
        cases = (
            ("utf-8-sig", ";", "utf-8-sig"),
            ("utf-8", ";", "utf-8"),
            ("cp1250", ";", "cp1250"),
            # This Czech fixture is byte-compatible with cp1250, which has
            # precedence over iso-8859-2 in the required detection order.
            ("iso-8859-2", ";", "cp1250"),
            ("utf-8", ",", "utf-8"),
        )
        for encoding, delimiter, detected in cases:
            with self.subTest(encoding=encoding, delimiter=delimiter):
                parsed = parse_pnd_csv(
                    _csv_bytes(rows, delimiter=delimiter, encoding=encoding),
                    channel=PndChannel.CONSUMPTION,
                    require_complete_days=False,
                )
                self.assertEqual(parsed.delimiter, delimiter)
                self.assertEqual(parsed.encoding, detected)
                self.assertEqual(parsed.intervals[0].value_kwh, Decimal("1.5"))

    def test_24_hour_timestamp_and_fifteen_minute_interval(self) -> None:
        parsed = parse_pnd_csv(
            _single(timestamp="01.01.2026 24:00"),
            channel=PndChannel.CONSUMPTION,
            require_complete_days=False,
        )
        record = parsed.intervals[0]
        self.assertEqual(record.source_day, date(2026, 1, 1))
        self.assertEqual(record.interval_end.astimezone(ZoneInfo("Europe/Prague")).date(), date(2026, 1, 2))
        self.assertEqual(record.interval_end - record.interval_start, timedelta(minutes=15))

    def test_kw_is_converted_to_quarter_hour_kwh(self) -> None:
        parsed = parse_pnd_csv(
            _single(value="2,4", unit="kW"),
            channel=PndChannel.CONSUMPTION,
            require_complete_days=False,
        )
        self.assertEqual(parsed.intervals[0].value_kwh, Decimal("0.600"))

    def test_placeholders_missing_and_invalid_remain_distinct(self) -> None:
        for value, status, quality in (("N/A", "OK", IntervalQuality.MISSING),
            ("9", "Neplatná", IntervalQuality.INVALID),
            ("", "missing", IntervalQuality.MISSING)):
            with self.subTest(value=value, status=status):
                parsed = parse_pnd_csv(
                    _single(value=value, status=status),
                    channel=PndChannel.CONSUMPTION,
                    require_complete_days=False,
                )
                record = parsed.intervals[0]
                self.assertIsNone(record.value_kwh)
                self.assertEqual(record.quality, quality)
        with self.assertRaises(PndCsvParseError) as raised:
            parse_pnd_csv(
                _single(status="unexpected"),
                channel=PndChannel.CONSUMPTION,
                require_complete_days=False,
            )
        self.assertEqual(raised.exception.code, "csv_status_invalid")

    def test_profiles_are_independent_and_must_match(self) -> None:
        consumption = parse_pnd_csv(
            _single(channel=PndChannel.CONSUMPTION),
            channel=PndChannel.CONSUMPTION,
            require_complete_days=False,
        )
        production = parse_pnd_csv(
            _single(channel=PndChannel.PRODUCTION),
            channel=PndChannel.PRODUCTION,
            require_complete_days=False,
        )
        self.assertEqual(consumption.profile, "+A")
        self.assertEqual(production.profile, "-A")
        with self.assertRaises(PndCsvParseError) as raised:
            parse_pnd_csv(
                _single(channel=PndChannel.PRODUCTION),
                channel=PndChannel.CONSUMPTION,
                require_complete_days=False,
            )
        self.assertEqual(raised.exception.code, "csv_profile_invalid")

    def test_identical_duplicates_are_deduplicated_and_conflicts_rejected(self) -> None:
        header = ["Datum a čas", "Profil", "Hodnota", "Jednotka", "Status"]
        row = ["01.01.2026 00:15", "+A", "1", "kWh", "OK"]
        parsed = parse_pnd_csv(
            _csv_bytes([header, row, row]),
            channel=PndChannel.CONSUMPTION,
            require_complete_days=False,
        )
        self.assertEqual(len(parsed.intervals), 1)
        with self.assertRaises(PndCsvParseError) as raised:
            parse_pnd_csv(
                _csv_bytes([header, row, [*row[:2], "2", *row[3:]]]),
                channel=PndChannel.CONSUMPTION,
                require_complete_days=False,
            )
        self.assertEqual(raised.exception.code, "csv_duplicate_conflict")

    def test_dst_days_accept_92_96_and_100_intervals(self) -> None:
        for day, expected in (
            (date(2026, 3, 29), 92),
            (date(2026, 1, 1), 96),
            (date(2026, 10, 25), 100),
        ):
            with self.subTest(day=day):
                parsed = parse_pnd_csv(
                    _complete_day(day, PndChannel.CONSUMPTION),
                    channel=PndChannel.CONSUMPTION,
                )
                self.assertEqual(len(parsed.intervals), expected)

    def test_incomplete_day_fails_closed(self) -> None:
        with self.assertRaises(PndCsvParseError) as raised:
            parse_pnd_csv(_single(), channel=PndChannel.CONSUMPTION)
        self.assertEqual(raised.exception.code, "csv_day_interval_count_invalid")

    def test_bounds_are_fail_closed(self) -> None:
        header = ["Datum a čas", "Profil", "Hodnota", "Jednotka", "Status"]
        with self.assertRaises(PndCsvParseError) as raised:
            parse_pnd_csv(
                _csv_bytes([header, ["x" * (MAX_CELL_CHARACTERS + 1)]]),
                channel=PndChannel.CONSUMPTION,
                require_complete_days=False,
            )
        self.assertIn(raised.exception.code, {"csv_cell_limit", "csv_delimiter_invalid"})
        too_many_columns = [f"column-{index}" for index in range(MAX_COLUMNS + 1)]
        with self.assertRaises(PndCsvParseError):
            parse_pnd_csv(
                _csv_bytes([too_many_columns]),
                channel=PndChannel.CONSUMPTION,
                require_complete_days=False,
            )
        with mock.patch.object(cez_csv_parser, "MAX_ROWS", 1), self.assertRaises(
            PndCsvParseError
        ) as raised:
            parse_pnd_csv(
                _csv_bytes(
                    [
                        header,
                        ["01.01.2026 00:15", "+A", "1", "kWh", "OK"],
                        ["01.01.2026 00:30", "+A", "1", "kWh", "OK"],
                    ]
                ),
                channel=PndChannel.CONSUMPTION,
                require_complete_days=False,
            )
        self.assertEqual(raised.exception.code, "csv_row_limit")
        with mock.patch.object(cez_csv_parser, "MAX_FILE_BYTES", 8), self.assertRaises(
            PndCsvParseError
        ) as raised:
            parse_pnd_csv(
                _single(),
                channel=PndChannel.CONSUMPTION,
                require_complete_days=False,
            )
        self.assertEqual(raised.exception.code, "csv_file_too_large")

    def test_unknown_unit_and_non_quarter_timestamp_fail_closed(self) -> None:
        for content, expected in (
            (_single(unit="Wh"), "csv_unit_invalid"),
            (_single(timestamp="01.01.2026 00:17"), "csv_timestamp_invalid"),
            (_single(timestamp="01.01.2026 24:15"), "csv_timestamp_invalid"),
        ):
            with self.subTest(expected=expected), self.assertRaises(
                PndCsvParseError
            ) as raised:
                parse_pnd_csv(
                    content,
                    channel=PndChannel.CONSUMPTION,
                    require_complete_days=False,
                )
            self.assertEqual(raised.exception.code, expected)

    def test_actual_collector_filenames_select_channel(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            consumption_path = root / "range-consumption.csv"
            production_path = root / "range-production.csv"
            consumption_path.write_bytes(_single(channel=PndChannel.CONSUMPTION))
            production_path.write_bytes(_single(channel=PndChannel.PRODUCTION))
            self.assertEqual(
                parse_pnd_file(consumption_path, require_complete_days=False).channel,
                PndChannel.CONSUMPTION,
            )
            self.assertEqual(
                parse_pnd_file(production_path, require_complete_days=False).channel,
                PndChannel.PRODUCTION,
            )


if __name__ == "__main__":
    unittest.main()
