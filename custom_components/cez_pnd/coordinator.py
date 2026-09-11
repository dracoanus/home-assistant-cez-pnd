"""Coordinated polling for CEZ PND Collector."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .client import (
    CollectorAuthenticationError,
    CollectorClient,
    CollectorError,
    CollectorMeasurements,
    CollectorProtocolError,
    CollectorStatus,
)
from .const import (
    CONF_POLL_INTERVAL_SECONDS,
    DEFAULT_POLL_INTERVAL_SECONDS,
    DOMAIN,
    validate_poll_interval_seconds,
)

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class CollectorSnapshot:
    """One internally consistent Collector polling result."""

    health: str
    status: CollectorStatus
    measurements: CollectorMeasurements


class CezPndCoordinator(DataUpdateCoordinator[CollectorSnapshot]):
    """Fetch the narrow Collector API once for all entities."""

    def __init__(
        self,
        hass: HomeAssistant,
        config_entry: ConfigEntry,
        client: CollectorClient,
    ) -> None:
        super().__init__(
            hass,
            logger=_LOGGER,
            name=DOMAIN,
            config_entry=config_entry,
            update_interval=timedelta(
                seconds=validate_poll_interval_seconds(
                    getattr(config_entry, "options", {}).get(
                        CONF_POLL_INTERVAL_SECONDS,
                        DEFAULT_POLL_INTERVAL_SECONDS,
                    )
                )
            ),
            always_update=False,
        )
        self._client = client
        self._measurements: CollectorMeasurements | None = None

    async def _async_update_data(self) -> CollectorSnapshot:
        try:
            status = await self._client.async_status()
            if status.data_timestamp is None or status.last_success is None:
                raise UpdateFailed("collector_dataset_unavailable")
            health = await self._client.async_health()
            measurements = self._measurements
            if (
                measurements is not None
                and status.dataset_revision == measurements.dataset_revision
            ):
                _validate_unchanged_revision(status, measurements)
                return CollectorSnapshot(health, status, measurements)

            measurements = await self._fetch_measurements(status)
            if status.dataset_revision != measurements.dataset_revision:
                status = await self._client.async_status()
                _require_usable_dataset(status)
                measurements = await self._fetch_measurements(status)
            _validate_consistent_snapshot(status, measurements)
            self._measurements = measurements
            return CollectorSnapshot(health, status, measurements)
        except CollectorAuthenticationError as error:
            raise ConfigEntryAuthFailed(
                "Collector API credential was rejected"
            ) from error
        except CollectorError as error:
            raise UpdateFailed("Collector API update failed") from error

    async def _fetch_measurements(
        self, status: CollectorStatus
    ) -> CollectorMeasurements:
        range_end = _format_utc(status.data_timestamp)
        range_start = _format_utc(status.data_timestamp - timedelta(hours=24))
        return await self._client.async_measurements(range_start, range_end)


def _format_utc(value: datetime) -> str:
    """Format a validated Collector timestamp for the bounded API range."""

    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _require_usable_dataset(status: CollectorStatus) -> None:
    if status.data_timestamp is None or status.last_success is None:
        raise UpdateFailed("collector_dataset_unavailable")


def _validate_unchanged_revision(
    status: CollectorStatus, measurements: CollectorMeasurements
) -> None:
    if (
        status.meter_id != measurements.meter_id
        or status.data_timestamp != measurements.data_timestamp
        or status.last_success != measurements.last_success
        or status.source_status != measurements.source_status
    ):
        raise CollectorProtocolError("inconsistent_unchanged_revision")


def _validate_consistent_snapshot(
    status: CollectorStatus, measurements: CollectorMeasurements
) -> None:
    if (
        status.meter_id != measurements.meter_id
        or status.dataset_revision != measurements.dataset_revision
        or status.data_timestamp != measurements.data_timestamp
        or status.last_success != measurements.last_success
        or status.source_status != measurements.source_status
    ):
        raise CollectorProtocolError("inconsistent_collector_snapshot")
