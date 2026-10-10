"""Health-only startup and dataset sensor recovery with stable identity."""
from dataclasses import dataclass
import importlib.util
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch


@dataclass(frozen=True, kw_only=True)
class _Description:
    key: str
    translation_key: str
    device_class: str | None = None
    native_unit_of_measurement: str | None = None
    entity_registry_enabled_default: bool = True


class _CoordinatorEntity:
    def __class_getitem__(cls, _item):
        return cls
    def __init__(self, coordinator):
        self.coordinator = coordinator
    @property
    def available(self):
        return self.coordinator.last_update_success


def _load_sensor():
    folder = Path(__file__).parents[1] / "custom_components" / "cez_pnd"
    name = "cez_pnd_sensor_test"
    package = ModuleType(name)
    package.__path__ = [str(folder)]
    sensors = ModuleType("homeassistant.components.sensor")
    sensors.SensorDeviceClass = SimpleNamespace(TIMESTAMP="timestamp", ENERGY="energy")
    sensors.SensorEntity = object
    sensors.SensorEntityDescription = _Description
    entries = ModuleType("homeassistant.config_entries")
    entries.ConfigEntry = object
    core = ModuleType("homeassistant.core")
    core.HomeAssistant = object
    const = ModuleType("homeassistant.const")
    const.UnitOfEnergy = SimpleNamespace(KILO_WATT_HOUR="kWh")
    registry = ModuleType("homeassistant.helpers.device_registry")
    registry.DeviceInfo = dict
    platforms = ModuleType("homeassistant.helpers.entity_platform")
    platforms.AddEntitiesCallback = object
    updates = ModuleType("homeassistant.helpers.update_coordinator")
    updates.CoordinatorEntity = _CoordinatorEntity
    coordinator = ModuleType(name + ".coordinator")
    coordinator.CezPndCoordinator = object
    coordinator.CollectorSnapshot = object
    with patch.dict(sys.modules, {name: package, "homeassistant.components.sensor": sensors,
        "homeassistant.config_entries": entries, "homeassistant.core": core,
        "homeassistant.const": const, "homeassistant.helpers.device_registry": registry,
        "homeassistant.helpers.entity_platform": platforms,
        "homeassistant.helpers.update_coordinator": updates, name + ".coordinator": coordinator}):
        spec = importlib.util.spec_from_file_location(name + ".sensor", folder / "sensor.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
    return module


sensor_module = _load_sensor()


class SensorAvailabilityTests(unittest.TestCase):
    def test_no_dataset_health_available_others_unavailable_and_recover(self):
        coordinator = SimpleNamespace(last_update_success=True,
            data=SimpleNamespace(health="ok", status=None, measurements=None))
        entry = SimpleNamespace(entry_id="stable-entry", data={"meter_id": "mtr_" + "a" * 32})
        entities = [sensor_module.CezPndSensor(coordinator, entry, d) for d in sensor_module.SENSORS]
        for entity in entities:
            if entity.entity_description.key == "collector_health":
                self.assertTrue(entity.available)
                self.assertEqual(entity.native_value, "ok")
            else:
                self.assertFalse(entity.available)
                self.assertIsNone(entity.native_value)
                self.assertIsNone(entity.extra_state_attributes)
            self.assertEqual(entity._attr_unique_id, "stable-entry_" + entity.entity_description.key)
        coordinator.data.status = SimpleNamespace(source_status="complete", data_timestamp=None,
            last_attempt=None, last_success=None, dataset_revision="ds_" + "b" * 32,
            completeness=SimpleNamespace(state="complete", valid_count=192, missing_count=0))
        coordinator.data.measurements = SimpleNamespace(latest_valid_grid_import=None,
            dataset_revision="ds_" + "b" * 32)
        for entity in entities:
            self.assertTrue(entity.available)
        energy = next(e for e in entities if e.entity_description.key == "grid_import")
        self.assertIsNone(energy.native_value)
        self.assertEqual(energy.extra_state_attributes["quality"], "missing")
        coordinator.last_update_success = False
        self.assertTrue(all(not entity.available for entity in entities))


if __name__ == "__main__":
    unittest.main()
