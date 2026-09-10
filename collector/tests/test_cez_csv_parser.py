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


class CezCsvParserTests(unittest.TestCase):
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

    def test_placeholders_and_invalid_status_remain_missing(self) -> None:
        for value, status in (("N/A", "OK"), ("9", "Neplatná"), ("", "missing")):
            with self.subTest(value=value, status=status):
                parsed = parse_pnd_csv(
                    _single(value=value, status=status),
                    channel=PndChannel.CONSUMPTION,
                    require_complete_days=False,
                )
                record = parsed.intervals[0]
                self.assertIsNone(record.value_kwh)
                self.assertEqual(record.quality, IntervalQuality.MISSING)
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
