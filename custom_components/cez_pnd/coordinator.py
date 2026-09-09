"""Coordinated polling for CEZ PND Collector."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

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
from .const import DOMAIN, POLL_INTERVAL, SYNTHETIC_RANGE_END, SYNTHETIC_RANGE_START

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
            update_interval=POLL_INTERVAL,
            always_update=False,
        )
        self._client = client

    async def _async_update_data(self) -> CollectorSnapshot:
        try:
            health, status, measurements = await asyncio.gather(
                self._client.async_health(),
                self._client.async_status(),
                self._client.async_measurements(
                    SYNTHETIC_RANGE_START, SYNTHETIC_RANGE_END
                ),
            )
            _validate_consistent_snapshot(status, measurements)
            return CollectorSnapshot(health, status, measurements)
        except CollectorAuthenticationError as error:
            raise ConfigEntryAuthFailed(
                "Collector API credential was rejected"
            ) from error
        except CollectorError as error:
            raise UpdateFailed("Collector API update failed") from error


def _validate_consistent_snapshot(
    status: CollectorStatus, measurements: CollectorMeasurements
) -> None:
    if (
        status.meter_id != measurements.meter_id
        or status.dataset_revision != measurements.dataset_revision
        or status.data_timestamp != measurements.data_timestamp
        or status.last_attempt != measurements.last_attempt
        or status.last_success != measurements.last_success
        or status.source_status != measurements.source_status
        or status.completeness != measurements.completeness
    ):
        raise CollectorProtocolError("inconsistent_collector_snapshot")
