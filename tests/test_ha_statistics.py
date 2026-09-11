"""Focused offline tests for CEZ PND Recorder external statistics."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from enum import Enum
import importlib.util
from pathlib import Path
from types import ModuleType, SimpleNamespace
import sys
import unittest
from unittest.mock import ANY, AsyncMock, Mock


ROOT = Path(__file__).parents[1]
INTEGRATION = ROOT / "custom_components" / "cez_pnd"


def _load_statistics_module():
    package_name = "cez_pnd_statistics_test_package"
    package = ModuleType(package_name)
    package.__path__ = [str(INTEGRATION)]
    sys.modules[package_name] = package

    class MeanType(Enum):
        NONE = "none"

    homeassistant = ModuleType("homeassistant")
    components = ModuleType("homeassistant.components")
    recorder = ModuleType("homeassistant.components.recorder")
    recorder.get_instance = lambda _hass: None
    models = ModuleType("homeassistant.components.recorder.models")
    models.StatisticData = dict
    models.StatisticMetaData = dict
    models.StatisticMeanType = MeanType
    recorder_statistics = ModuleType("homeassistant.components.recorder.statistics")
    recorder_statistics.async_add_external_statistics = lambda *_args: None
    config_entries = ModuleType("homeassistant.config_entries")
    config_entries.ConfigEntry = object
    const = ModuleType("homeassistant.const")
    const.UnitOfEnergy = SimpleNamespace(KILO_WATT_HOUR="kWh")
    core = ModuleType("homeassistant.core")
    core.HomeAssistant = object
    sys.modules.update(
        {
            "homeassistant": homeassistant,
            "homeassistant.components": components,
            "homeassistant.components.recorder": recorder,
            "homeassistant.components.recorder.models": models,
            "homeassistant.components.recorder.statistics": recorder_statistics,
            "homeassistant.config_entries": config_entries,
            "homeassistant.const": const,
            "homeassistant.core": core,
        }
    )

    client = ModuleType(f"{package_name}.client")
    client.MAX_COMBINED_ITEMS = 12_000
    client.CollectorClient = object
    client.CollectorMeasurement = object
    client.CollectorMeasurements = object
    client.CollectorStatus = object
    sys.modules[client.__name__] = client

    name = f"{package_name}.statistics"
    spec = importlib.util.spec_from_file_location(name, INTEGRATION / "statistics.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


statistics = _load_statistics_module()


def _completeness(expected: int):
    return SimpleNamespace(
        expected_count=expected,
        valid_count=expected,
        missing_count=0,
        invalid_count=0,
    )


def _status(revision: str = "ds_revision", expected: int = 0):
    return SimpleNamespace(
        meter_id="mtr_test",
        dataset_revision=revision,
        data_timestamp=datetime(2026, 9, 11, tzinfo=UTC),
        last_success=datetime(2026, 9, 11, 1, tzinfo=UTC),
        source_status="ok",
        completeness=_completeness(expected),
    )


def _measurement(
    start: datetime,
    channel: str = "grid_import",
    value: str | None = "1",
    quality: str = "valid",
):
    return SimpleNamespace(
        channel=channel,
        interval_start=start,
        interval_end=start + timedelta(minutes=15),
        value_kwh=None if value is None else Decimal(value),
        quality=quality,
    )


def _hour(
    start: datetime,
    channel: str = "grid_import",
    value: str = "1",
):
    return tuple(
        _measurement(start + timedelta(minutes=15 * index), channel, value)
        for index in range(4)
    )


def _page(status, expected: int, values=()):
    return SimpleNamespace(
        meter_id=status.meter_id,
        dataset_revision=status.dataset_revision,
        data_timestamp=status.data_timestamp,
        last_success=status.last_success,
        source_status=status.source_status,
        completeness=_completeness(expected),
        values=tuple(values),
    )


class _Client:
    def __init__(self, status, pages=()) -> None:
        self.status = status
        self.pages = list(pages)
        self.ranges: list[tuple[str, str]] = []

    async def async_measurements(self, start: str, end: str):
        self.ranges.append((start, end))
        return self.pages.pop(0)

    async def async_status(self):
        return self.status


class _Entry:
    def __init__(self) -> None:
        self.background_tasks = 0

    def async_create_background_task(self, _hass, coroutine, _name):
        self.background_tasks += 1
        coroutine.close()
        return SimpleNamespace(done=lambda: True)


class StatisticsTests(unittest.IsolatedAsyncioTestCase):
    def test_metadata_and_statistic_ids_are_energy_compatible(self) -> None:
        self.assertEqual(
            statistics.STATISTIC_IDS,
            ("cez_pnd:grid_import_energy", "cez_pnd:grid_export_energy"),
        )
        for statistic_id in statistics.STATISTIC_IDS:
            metadata = statistics.statistic_metadata(statistic_id)
            self.assertTrue(metadata["has_sum"])
            self.assertIs(metadata["mean_type"], statistics.StatisticMeanType.NONE)
            self.assertEqual(metadata["source"], "cez_pnd")
            self.assertEqual(metadata["unit_class"], "energy")
            self.assertEqual(metadata["unit_of_measurement"], "kWh")

    def test_hour_requires_four_valid_intervals_and_preserves_zero(self) -> None:
        start = datetime(2026, 9, 1, tzinfo=UTC)
        complete = statistics.aggregate_hourly(_hour(start, value="0"))
        self.assertEqual(complete["grid_import"][start], Decimal(0))
        self.assertEqual(
            statistics.aggregate_hourly(_hour(start)[:3])["grid_import"], {}
        )
        for quality in ("missing", "invalid"):
            intervals = (
                *_hour(start)[:3],
                _measurement(
                    start + timedelta(minutes=45), value=None, quality=quality
                ),
            )
            with self.subTest(quality=quality):
                self.assertEqual(
                    statistics.aggregate_hourly(intervals)["grid_import"], {}
                )

    def test_import_and_export_are_independent(self) -> None:
        start = datetime(2026, 9, 1, tzinfo=UTC)
        hourly = statistics.aggregate_hourly(
            (*_hour(start, "grid_import", "1"), *_hour(start, "grid_export", "2"))
        )
        self.assertEqual(hourly["grid_import"][start], Decimal(4))
        self.assertEqual(hourly["grid_export"][start], Decimal(8))

    def test_unknown_quality_fails_closed(self) -> None:
        start = datetime(2026, 9, 1, tzinfo=UTC)
        with self.assertRaisesRegex(
            statistics.StatisticsSyncError, "quality_invalid"
        ):
            statistics.aggregate_hourly(
                (_measurement(start, quality="unexpected"),)
            )

    def test_utc_aggregation_produces_dst_day_hour_counts(self) -> None:
        start = datetime(2026, 3, 28, 23, tzinfo=UTC)
        for hours in (23, 25):
            with self.subTest(hours=hours):
                intervals = tuple(
                    _measurement(start + timedelta(minutes=15 * index))
                    for index in range(hours * 4)
                )
                result = statistics.aggregate_hourly(intervals)
                self.assertEqual(len(result["grid_import"]), hours)

    def test_cumulative_sums_are_monotonic_and_corrections_shift_later_sums(
        self,
    ) -> None:
        start = datetime(2026, 9, 1, tzinfo=UTC)
        initial = statistics.cumulative_statistics(
            {start: Decimal("1"), start + timedelta(hours=1): Decimal("2")}
        )
        corrected = statistics.cumulative_statistics(
            {start: Decimal("3"), start + timedelta(hours=1): Decimal("2")}
        )
        self.assertEqual([row["sum"] for row in initial], [1.0, 3.0])
        self.assertEqual([row["sum"] for row in corrected], [3.0, 5.0])
        self.assertTrue(
            all(row["sum"] >= 0 for row in corrected)
            and all(a["sum"] <= b["sum"] for a, b in zip(corrected, corrected[1:]))
        )

    async def test_full_history_uses_nonoverlapping_sixty_day_windows(self) -> None:
        status = _status(expected=30)
        client = _Client(status, [_page(status, 10), _page(status, 20)])
        manager = statistics.CezPndStatisticsManager(
            object(), _Entry(), client, clear_statistics=AsyncMock()
        )
        await manager._async_full_history(status)
        self.assertEqual(len(client.ranges), 2)
        self.assertEqual(client.ranges[0][0], client.ranges[1][1])
        first_start = datetime.fromisoformat(client.ranges[0][0].replace("Z", "+00:00"))
        first_end = datetime.fromisoformat(client.ranges[0][1].replace("Z", "+00:00"))
        self.assertEqual(first_end - first_start, timedelta(days=60))

    async def test_full_history_includes_current_day_future_missing_rows(self) -> None:
        status = _status(expected=8)
        status.data_timestamp = datetime(2026, 9, 11, 12, tzinfo=UTC)
        status.last_success = datetime(2026, 9, 11, 13, tzinfo=UTC)
        valid_hour = _hour(datetime(2026, 9, 11, 11, tzinfo=UTC))
        future_missing = tuple(
            _measurement(
                datetime(2026, 9, 11, 20, tzinfo=UTC)
                + timedelta(minutes=15 * index),
                value=None,
                quality="missing",
            )
            for index in range(4)
        )
        client = _Client(
            status, [_page(status, 8, (*valid_hour, *future_missing))]
        )
        manager = statistics.CezPndStatisticsManager(object(), _Entry(), client)
        hourly = await manager._async_full_history(status)
        self.assertEqual(client.ranges[0][1], "2026-09-11T22:00:00Z")
        self.assertEqual(
            hourly["grid_import"],
            {datetime(2026, 9, 11, 11, tzinfo=UTC): Decimal(4)},
        )

    def test_full_history_upper_bound_uses_prague_dst_midnight(self) -> None:
        cases = (
            (
                datetime(2026, 3, 29, 12, tzinfo=UTC),
                datetime(2026, 3, 29, 22, tzinfo=UTC),
            ),
            (
                datetime(2026, 10, 25, 12, tzinfo=UTC),
                datetime(2026, 10, 25, 23, tzinfo=UTC),
            ),
        )
        for last_success, expected in cases:
            with self.subTest(last_success=last_success):
                status = _status()
                status.data_timestamp = last_success
                status.last_success = last_success
                self.assertEqual(
                    statistics._full_history_upper_bound(status), expected
                )

    async def test_history_stops_exactly_at_global_count_and_rejects_overcount(
        self,
    ) -> None:
        status = _status(expected=10)
        client = _Client(status, [_page(status, 10), _page(status, 1)])
        manager = statistics.CezPndStatisticsManager(object(), _Entry(), client)
        await manager._async_full_history(status)
        self.assertEqual(len(client.ranges), 1)

        client = _Client(status, [_page(status, 11)])
        manager = statistics.CezPndStatisticsManager(object(), _Entry(), client)
        with self.assertRaisesRegex(statistics.StatisticsSyncError, "overcount"):
            await manager._async_full_history(status)

    async def test_revision_race_and_unreconciled_history_fail_closed(self) -> None:
        status = _status(expected=1)
        changed = _status("ds_changed", expected=1)
        client = _Client(changed, [_page(status, 1)])
        manager = statistics.CezPndStatisticsManager(object(), _Entry(), client)
        with self.assertRaisesRegex(statistics.StatisticsSyncError, "revision_changed"):
            await manager._async_full_history(status)

        status = _status(expected=1)
        client = _Client(status, [_page(status, 0)] * statistics.MAX_HISTORY_WINDOWS)
        manager = statistics.CezPndStatisticsManager(object(), _Entry(), client)
        with self.assertRaisesRegex(statistics.StatisticsSyncError, "unreconciled"):
            await manager._async_full_history(status)

    async def test_same_revision_skips_and_expected_growth_forces_full_scan(
        self,
    ) -> None:
        status = _status(expected=0)
        added: list[tuple[object, object]] = []
        clear = AsyncMock()

        def add(_hass, metadata, rows):
            added.append((metadata, rows))

        manager = statistics.CezPndStatisticsManager(
            object(), _Entry(), _Client(status),
            add_statistics=add,
            clear_statistics=clear,
        )
        await manager.async_sync(status)
        await manager.async_sync(status)
        self.assertEqual(len(added), 2)
        clear.assert_awaited_once_with(ANY, list(statistics.STATISTIC_IDS))

        manager._async_full_history = AsyncMock(
            return_value={channel: {} for channel in statistics.CHANNELS}
        )
        manager._async_recent_correction = AsyncMock()
        await manager.async_sync(_status("ds_grown", expected=2))
        manager._async_full_history.assert_awaited_once()
        manager._async_recent_correction.assert_not_awaited()
        self.assertEqual(clear.await_count, 2)

    def test_schedule_is_config_entry_owned_and_deduplicates_revision(self) -> None:
        status = _status()
        entry = _Entry()
        manager = statistics.CezPndStatisticsManager(
            object(), entry, _Client(status)
        )
        manager.schedule(status)
        manager.schedule(status)
        self.assertEqual(entry.background_tasks, 1)

    async def test_revision_change_uses_recent_window_and_removes_stale_hour(
        self,
    ) -> None:
        old = _status("ds_old", expected=4)
        new = _status("ds_new", expected=4)
        start = datetime(2026, 9, 10, tzinfo=UTC)
        missing = tuple(
            _measurement(
                start + timedelta(minutes=15 * index),
                value=None,
                quality="missing",
            )
            for index in range(4)
        )
        client = _Client(new, [_page(new, 4, missing)])
        imported: dict[str, list[dict]] = {}
        clear = AsyncMock()

        def add(_hass, metadata, rows):
            imported[metadata["statistic_id"]] = rows

        manager = statistics.CezPndStatisticsManager(
            object(), _Entry(), client,
            add_statistics=add,
            clear_statistics=clear,
        )
        manager._last_revision = old.dataset_revision
        manager._last_expected_count = 4
        manager._hourly = {
            "grid_import": {start: Decimal("4")},
            "grid_export": {},
        }
        await manager.async_sync(new)
        self.assertNotIn(start, manager._hourly["grid_import"])
        self.assertEqual(imported[statistics.GRID_IMPORT_STATISTIC_ID], [])
        clear.assert_awaited_once_with(
            ANY, [statistics.GRID_IMPORT_STATISTIC_ID]
        )
        self.assertNotIn(statistics.GRID_EXPORT_STATISTIC_ID, imported)

    async def test_historical_correction_rebuilds_later_cumulative_sums(self) -> None:
        old = _status("ds_old", expected=12)
        new = _status("ds_new", expected=12)
        start = datetime(2026, 9, 10, tzinfo=UTC)
        client = _Client(
            new,
            [
                _page(
                    new,
                    12,
                    (
                        *_hour(start, value="1"),
                        *_hour(start + timedelta(hours=1), value="2"),
                        *_hour(start + timedelta(hours=2), value="1"),
                    ),
                )
            ],
        )
        imported: dict[str, list[dict]] = {}
        clear = AsyncMock()

        def add(_hass, metadata, rows):
            imported[metadata["statistic_id"]] = rows

        manager = statistics.CezPndStatisticsManager(
            object(),
            _Entry(),
            client,
            add_statistics=add,
            clear_statistics=clear,
        )
        manager._last_revision = old.dataset_revision
        manager._last_expected_count = 12
        manager._hourly = {
            "grid_import": {
                start: Decimal("4"),
                start + timedelta(hours=1): Decimal("4"),
                start + timedelta(hours=2): Decimal("4"),
            },
            "grid_export": {},
        }
        await manager.async_sync(new)
        rows = imported[statistics.GRID_IMPORT_STATISTIC_ID]
        self.assertEqual([row["state"] for row in rows], [8.0, 4.0])
        self.assertEqual([row["sum"] for row in rows], [12.0, 16.0])
        self.assertEqual(rows[0]["start"], start + timedelta(hours=1))
        clear.assert_not_awaited()

    async def test_new_revision_with_same_hourly_data_writes_nothing(self) -> None:
        old = _status("ds_old", expected=4)
        new = _status("ds_new", expected=4)
        start = datetime(2026, 9, 10, tzinfo=UTC)
        add = Mock()
        clear = AsyncMock()
        manager = statistics.CezPndStatisticsManager(
            object(),
            _Entry(),
            _Client(new, [_page(new, 4, _hour(start))]),
            add_statistics=add,
            clear_statistics=clear,
        )
        manager._last_revision = old.dataset_revision
        manager._last_expected_count = 4
        manager._hourly = {
            "grid_import": {start: Decimal("4")},
            "grid_export": {},
        }
        await manager.async_sync(new)
        add.assert_not_called()
        clear.assert_not_awaited()
        self.assertEqual(manager._last_revision, new.dataset_revision)

    async def test_newly_complete_hour_is_added_without_stream_clear(self) -> None:
        old = _status("ds_old", expected=4)
        new = _status("ds_new", expected=4)
        start = datetime(2026, 9, 10, tzinfo=UTC)
        added: list[tuple[object, list[dict]]] = []
        clear = AsyncMock()

        def add(_hass, metadata, rows):
            added.append((metadata, rows))

        manager = statistics.CezPndStatisticsManager(
            object(),
            _Entry(),
            _Client(new, [_page(new, 4, _hour(start))]),
            add_statistics=add,
            clear_statistics=clear,
        )
        manager._last_revision = old.dataset_revision
        manager._last_expected_count = 4
        manager._hourly = {channel: {} for channel in statistics.CHANNELS}
        await manager.async_sync(new)
        clear.assert_not_awaited()
        self.assertEqual(len(added), 1)
        self.assertEqual(
            added[0][0]["statistic_id"], statistics.GRID_IMPORT_STATISTIC_ID
        )
        self.assertEqual(added[0][1][0]["sum"], 4.0)

    async def test_measurement_metadata_mismatch_fails_closed(self) -> None:
        status = _status(expected=1)
        page = _page(status, 1)
        page.dataset_revision = "ds_other"
        manager = statistics.CezPndStatisticsManager(
            object(), _Entry(), _Client(status, [page])
        )
        with self.assertRaisesRegex(
            statistics.StatisticsSyncError, "metadata_inconsistent"
        ):
            await manager._async_full_history(status)

    async def test_import_failure_is_contained_by_background_runner(self) -> None:
        status = _status(expected=0)

        def fail(*_args):
            raise RuntimeError("private detail")

        manager = statistics.CezPndStatisticsManager(
            object(), _Entry(), _Client(status),
            add_statistics=fail,
            clear_statistics=AsyncMock(),
        )
        manager._pending_status = status
        await manager._async_run_pending()
        self.assertIsNone(manager._last_revision)
        self.assertEqual(manager._last_attempted_revision, status.dataset_revision)

        manager.schedule(status)
        self.assertIsNone(manager._pending_status)


if __name__ == "__main__":
    unittest.main()
