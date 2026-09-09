"""Sensors backed by the CEZ PND Collector API."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import UnitOfEnergy
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import CONF_METER_ID, DOMAIN
from .coordinator import CezPndCoordinator, CollectorSnapshot


@dataclass(frozen=True, kw_only=True)
class CezPndSensorDescription(SensorEntityDescription):
    """Describe a Collector sensor value."""

    value_fn: Callable[[CollectorSnapshot], Any]


SENSORS = (
    CezPndSensorDescription(
        key="collector_health",
        translation_key="collector_health",
        value_fn=lambda data: data.health,
    ),
    CezPndSensorDescription(
        key="source_status",
        translation_key="source_status",
        value_fn=lambda data: data.status.source_status,
    ),
    CezPndSensorDescription(
        key="data_timestamp",
        translation_key="data_timestamp",
        device_class=SensorDeviceClass.TIMESTAMP,
        value_fn=lambda data: data.status.data_timestamp,
    ),
    CezPndSensorDescription(
        key="last_attempt",
        translation_key="last_attempt",
        device_class=SensorDeviceClass.TIMESTAMP,
        value_fn=lambda data: data.status.last_attempt,
    ),
    CezPndSensorDescription(
        key="last_success",
        translation_key="last_success",
        device_class=SensorDeviceClass.TIMESTAMP,
        value_fn=lambda data: data.status.last_success,
    ),
    CezPndSensorDescription(
        key="completeness",
        translation_key="completeness",
        value_fn=lambda data: data.status.completeness.state,
    ),
    CezPndSensorDescription(
        key="valid_count",
        translation_key="valid_count",
        native_unit_of_measurement="intervals",
        value_fn=lambda data: data.status.completeness.valid_count,
    ),
    CezPndSensorDescription(
        key="missing_count",
        translation_key="missing_count",
        native_unit_of_measurement="intervals",
        value_fn=lambda data: data.status.completeness.missing_count,
    ),
    CezPndSensorDescription(
        key="dataset_revision",
        translation_key="dataset_revision",
        entity_registry_enabled_default=False,
        value_fn=lambda data: data.status.dataset_revision,
    ),
    CezPndSensorDescription(
        key="grid_import",
        translation_key="grid_import",
        device_class=SensorDeviceClass.ENERGY,
        native_unit_of_measurement=UnitOfEnergy.KILO_WATT_HOUR,
        value_fn=lambda data: (
            measurement.value_kwh
            if (measurement := data.measurements.latest_valid_grid_import)
            else None
        ),
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Collector sensors from the shared coordinator."""

    coordinator: CezPndCoordinator = entry.runtime_data
    async_add_entities(
        CezPndSensor(coordinator, entry, description) for description in SENSORS
    )


class CezPndSensor(CoordinatorEntity[CezPndCoordinator], SensorEntity):
    """A read-only entity backed by one Collector snapshot."""

    entity_description: CezPndSensorDescription
    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: CezPndCoordinator,
        entry: ConfigEntry,
        description: CezPndSensorDescription,
    ) -> None:
        super().__init__(coordinator)
        self.entity_description = description
        self._attr_unique_id = f"{entry.entry_id}_{description.key}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.data[CONF_METER_ID])},
            name="CEZ PND Collector",
            manufacturer="Dracoanus",
            model="Collector API",
        )

    @property
    def native_value(self) -> str | int | Decimal | datetime | None:
        """Return a validated value; missing data remains unknown."""

        return self.entity_description.value_fn(self.coordinator.data)

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        """Expose bounded interval metadata for the synthetic measurement."""

        if self.entity_description.key != "grid_import":
            return None
        measurement = self.coordinator.data.measurements.latest_valid_grid_import
        if measurement is None:
            return {
                "quality": "missing",
                "dataset_revision": self.coordinator.data.measurements.dataset_revision,
            }
        return {
            "interval_start": measurement.interval_start.isoformat(),
            "interval_end": measurement.interval_end.isoformat(),
            "quality": measurement.quality,
            "dataset_revision": measurement.revision,
        }
