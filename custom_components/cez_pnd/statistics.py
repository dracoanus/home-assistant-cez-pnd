"""Recorder external energy statistics sourced from the local Collector."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Coroutine
from datetime import UTC, datetime, time, timedelta
from decimal import Decimal
from typing import Any
from zoneinfo import ZoneInfo

from homeassistant.components.recorder import get_instance
from homeassistant.components.recorder.models import (
    StatisticData,
    StatisticMeanType,
    StatisticMetaData,
)
from homeassistant.components.recorder.statistics import async_add_external_statistics
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import UnitOfEnergy
from homeassistant.core import HomeAssistant

from .client import (
    MAX_COMBINED_ITEMS,
    CollectorClient,
    CollectorMeasurement,
    CollectorMeasurements,
    CollectorStatus,
)
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

GRID_IMPORT_STATISTIC_ID = f"{DOMAIN}:grid_import_energy"
GRID_EXPORT_STATISTIC_ID = f"{DOMAIN}:grid_export_energy"
STATISTIC_IDS = (GRID_IMPORT_STATISTIC_ID, GRID_EXPORT_STATISTIC_ID)
CHANNELS = ("grid_import", "grid_export")

HISTORY_WINDOW_DAYS = 60
RECENT_CORRECTION_DAYS = 7
MAX_HISTORY_WINDOWS = 128
MAX_HISTORY_EXPECTED_COUNT = MAX_HISTORY_WINDOWS * MAX_COMBINED_ITEMS
CLEAR_TIMEOUT_SECONDS = 30
INTERVAL_DURATION = timedelta(minutes=15)
HOUR_DURATION = timedelta(hours=1)
PRAGUE_TIMEZONE = ZoneInfo("Europe/Prague")


class StatisticsSyncError(RuntimeError):
    """The bounded statistics reconciliation failed closed."""


type HourlyEnergy = dict[str, dict[datetime, Decimal]]
type AddStatistics = Callable[
    [HomeAssistant, StatisticMetaData, list[StatisticData]], None
]
type ClearStatistics = Callable[[HomeAssistant, list[str]], Coroutine[Any, Any, None]]


def statistic_metadata(statistic_id: str) -> StatisticMetaData:
    """Return Energy Dashboard compatible external-statistic metadata."""

    if statistic_id not in STATISTIC_IDS:
        raise StatisticsSyncError("statistics_id_invalid")
    return {
        "has_sum": True,
        "mean_type": StatisticMeanType.NONE,
        "name": (
            "CEZ PND grid import energy"
            if statistic_id == GRID_IMPORT_STATISTIC_ID
            else "CEZ PND grid export energy"
        ),
        "source": DOMAIN,
        "statistic_id": statistic_id,
        "unit_class": "energy",
        "unit_of_measurement": UnitOfEnergy.KILO_WATT_HOUR,
    }


def aggregate_hourly(
    measurements: tuple[CollectorMeasurement, ...],
) -> HourlyEnergy:
    """Aggregate exactly four valid UTC quarter-hours into each hour."""

    buckets: dict[str, dict[datetime, dict[datetime, Decimal]]] = {
        channel: {} for channel in CHANNELS
    }
    for item in measurements:
        if item.channel not in CHANNELS:
            raise StatisticsSyncError("statistics_channel_invalid")
        start = item.interval_start.astimezone(UTC)
        end = item.interval_end.astimezone(UTC)
        if (
            end - start != INTERVAL_DURATION
            or start.second != 0
            or start.microsecond != 0
            or start.minute not in {0, 15, 30, 45}
        ):
            raise StatisticsSyncError("statistics_interval_invalid")
        if item.quality not in {"valid", "missing", "invalid"}:
            raise StatisticsSyncError("statistics_quality_invalid")
        if item.quality != "valid":
            continue
        if item.value_kwh is None or item.value_kwh < 0:
            raise StatisticsSyncError("statistics_value_invalid")
        hour = start.replace(minute=0, second=0, microsecond=0)
        intervals = buckets[item.channel].setdefault(hour, {})
        if start in intervals:
            raise StatisticsSyncError("statistics_interval_duplicate")
        intervals[start] = item.value_kwh

    hourly: HourlyEnergy = {channel: {} for channel in CHANNELS}
    expected_offsets = {0, 15, 30, 45}
    for channel, hours in buckets.items():
        for hour, intervals in hours.items():
            if (
                len(intervals) == 4
                and {instant.minute for instant in intervals} == expected_offsets
            ):
                hourly[channel][hour] = sum(intervals.values(), Decimal(0))
    return hourly


def cumulative_statistics(hourly: dict[datetime, Decimal]) -> list[StatisticData]:
    """Create deterministic non-negative cumulative Recorder rows."""

    total = Decimal(0)
    rows: list[StatisticData] = []
    for start, state in sorted(hourly.items()):
        if state < 0:
            raise StatisticsSyncError("statistics_value_invalid")
        total += state
        rows.append({"start": start, "state": float(state), "sum": float(total)})
    return rows


async def async_clear_external_statistics(
    hass: HomeAssistant, statistic_ids: list[str]
) -> None:
    """Clear complete external streams through the supported Recorder queue."""

    completed = asyncio.Event()

    def on_done() -> None:
        hass.loop.call_soon_threadsafe(completed.set)

    get_instance(hass).async_clear_statistics(statistic_ids, on_done=on_done)
    async with asyncio.timeout(CLEAR_TIMEOUT_SECONDS):
        await completed.wait()


class CezPndStatisticsManager:
    """Revision-driven, ConfigEntry-owned external statistics synchronizer."""

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        client: CollectorClient,
        *,
        add_statistics: AddStatistics = async_add_external_statistics,
        clear_statistics: ClearStatistics = async_clear_external_statistics,
    ) -> None:
        self._hass = hass
        self._entry = entry
        self._client = client
        self._add_statistics = add_statistics
        self._clear_statistics = clear_statistics
        self._lock = asyncio.Lock()
        self._last_revision: str | None = None
        self._last_attempted_revision: str | None = None
        self._last_expected_count: int | None = None
        self._hourly: HourlyEnergy | None = None
        self._pending_status: CollectorStatus | None = None
        self._active_revision: str | None = None
        self._task: asyncio.Task[None] | None = None

    def schedule(self, status: CollectorStatus) -> None:
        """Schedule the newest unseen revision without accumulating tasks."""

        revision = status.dataset_revision
        if revision in {
            self._last_revision,
            self._last_attempted_revision,
            self._active_revision,
            getattr(self._pending_status, "dataset_revision", None),
        }:
            return
        self._pending_status = status
        if self._task is None or self._task.done():
            self._task = self._entry.async_create_background_task(
                self._hass,
                self._async_run_pending(),
                "CEZ PND external statistics",
            )

    async def _async_run_pending(self) -> None:
        while (status := self._pending_status) is not None:
            self._pending_status = None
            self._active_revision = status.dataset_revision
            self._last_attempted_revision = status.dataset_revision
            try:
                await self.async_sync(status)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - isolates entities from Recorder work
                _LOGGER.warning("CEZ PND statistics synchronization failed")
            finally:
                self._active_revision = None

    async def async_sync(self, status: CollectorStatus) -> None:
        """Reconcile one revision while preventing overlapping imports."""

        async with self._lock:
            if status.dataset_revision == self._last_revision:
                return
            if (
                self._hourly is None
                or self._last_expected_count != status.completeness.expected_count
            ):
                hourly = await self._async_full_history(status)
                await self._async_full_rebuild(hourly)
            else:
                previous = self._hourly
                hourly = await self._async_recent_correction(status)
                await self._async_incremental_update(previous, hourly)
            self._hourly = hourly
            self._last_revision = status.dataset_revision
            self._last_expected_count = status.completeness.expected_count

    async def _async_full_history(self, status: CollectorStatus) -> HourlyEnergy:
        if status.data_timestamp is None:
            raise StatisticsSyncError("statistics_dataset_unavailable")
        global_expected = status.completeness.expected_count
        if not 0 <= global_expected <= MAX_HISTORY_EXPECTED_COUNT:
            raise StatisticsSyncError("statistics_history_too_large")
        end = _full_history_upper_bound(status)
        accumulated = 0
        hourly: HourlyEnergy = {channel: {} for channel in CHANNELS}
        for _window in range(MAX_HISTORY_WINDOWS):
            if accumulated == global_expected:
                break
            start = end - timedelta(days=HISTORY_WINDOW_DAYS)
            measurements = await self._client.async_measurements(
                _format_utc(start), _format_utc(end)
            )
            _validate_measurement_metadata(status, measurements)
            accumulated += measurements.completeness.expected_count
            if accumulated > global_expected:
                raise StatisticsSyncError("statistics_history_overcount")
            _merge_disjoint(hourly, aggregate_hourly(measurements.values))
            end = start
        if accumulated != global_expected:
            raise StatisticsSyncError("statistics_history_unreconciled")
        await self._async_confirm_revision(status)
        return hourly

    async def _async_recent_correction(self, status: CollectorStatus) -> HourlyEnergy:
        if status.data_timestamp is None or self._hourly is None:
            raise StatisticsSyncError("statistics_dataset_unavailable")
        end = _ceil_hour(status.data_timestamp)
        start = end - timedelta(days=RECENT_CORRECTION_DAYS)
        measurements = await self._client.async_measurements(
            _format_utc(start), _format_utc(end)
        )
        _validate_measurement_metadata(status, measurements)
        replacement = aggregate_hourly(measurements.values)
        hourly = {
            channel: {
                hour: value
                for hour, value in self._hourly[channel].items()
                if not start <= hour < end
            }
            for channel in CHANNELS
        }
        _merge_disjoint(hourly, replacement)
        await self._async_confirm_revision(status)
        return hourly

    async def _async_confirm_revision(self, expected: CollectorStatus) -> None:
        current = await self._client.async_status()
        if _status_signature(current) != _status_signature(expected):
            raise StatisticsSyncError("statistics_revision_changed")

    async def _async_full_rebuild(self, hourly: HourlyEnergy) -> None:
        await self._clear_statistics(self._hass, list(STATISTIC_IDS))
        for channel, statistic_id in zip(CHANNELS, STATISTIC_IDS, strict=True):
            self._add_statistics(
                self._hass,
                statistic_metadata(statistic_id),
                cumulative_statistics(hourly[channel]),
            )

    async def _async_incremental_update(
        self, previous: HourlyEnergy, current: HourlyEnergy
    ) -> None:
        """Apply only effective per-stream changes for a recent correction."""

        for channel, statistic_id in zip(CHANNELS, STATISTIC_IDS, strict=True):
            old = previous[channel]
            new = current[channel]
            removed = old.keys() - new.keys()
            changed = {hour for hour, value in new.items() if old.get(hour) != value}
            if not removed and not changed:
                continue
            if removed:
                await self._clear_statistics(self._hass, [statistic_id])
                rows = cumulative_statistics(new)
            else:
                earliest_changed = min(changed)
                rows = [
                    row
                    for row in cumulative_statistics(new)
                    if row["start"] >= earliest_changed
                ]
            self._add_statistics(
                self._hass,
                statistic_metadata(statistic_id),
                rows,
            )


def _validate_measurement_metadata(
    status: CollectorStatus, measurements: CollectorMeasurements
) -> None:
    if (
        measurements.meter_id != status.meter_id
        or measurements.dataset_revision != status.dataset_revision
        or measurements.data_timestamp != status.data_timestamp
        or measurements.last_success != status.last_success
        or measurements.source_status != status.source_status
    ):
        raise StatisticsSyncError("statistics_metadata_inconsistent")


def _status_signature(status: CollectorStatus) -> tuple[object, ...]:
    return (
        status.meter_id,
        status.dataset_revision,
        status.data_timestamp,
        status.last_success,
        status.source_status,
        status.completeness.expected_count,
    )


def _merge_disjoint(target: HourlyEnergy, addition: HourlyEnergy) -> None:
    for channel in CHANNELS:
        if target[channel].keys() & addition[channel].keys():
            raise StatisticsSyncError("statistics_history_overlap")
        target[channel].update(addition[channel])


def _ceil_hour(value: datetime) -> datetime:
    utc = value.astimezone(UTC)
    floor = utc.replace(minute=0, second=0, microsecond=0)
    return floor if utc == floor else floor + HOUR_DURATION


def _full_history_upper_bound(status: CollectorStatus) -> datetime:
    """Cover the full Prague day that may contain persisted placeholders."""

    if status.data_timestamp is None or status.last_success is None:
        raise StatisticsSyncError("statistics_dataset_unavailable")
    last_success_day = status.last_success.astimezone(PRAGUE_TIMEZONE).date()
    next_local_midnight = datetime.combine(
        last_success_day + timedelta(days=1), time(), tzinfo=PRAGUE_TIMEZONE
    ).astimezone(UTC)
    return max(_ceil_hour(status.data_timestamp), next_local_midnight)


def _format_utc(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
