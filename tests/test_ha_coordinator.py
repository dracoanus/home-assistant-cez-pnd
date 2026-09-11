"""Focused tests for the Home Assistant polling coordinator."""

from __future__ import annotations

import importlib.util
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType, SimpleNamespace
import sys
import unittest


ROOT = Path(__file__).parents[1]
INTEGRATION = ROOT / "custom_components" / "cez_pnd"


class _CollectorError(Exception):
    pass


class _CollectorAuthenticationError(_CollectorError):
    pass


class _CollectorProtocolError(_CollectorError):
    pass


class _ConfigEntryAuthFailed(Exception):
    pass


class _UpdateFailed(Exception):
    pass


class _DataUpdateCoordinator:
    def __class_getitem__(cls, _item):
        return cls

    def __init__(self, *_args, **_kwargs) -> None:
        pass


def _load_coordinator_module():
    package_name = "cez_pnd_coordinator_test_package"
    package = ModuleType(package_name)
    package.__path__ = [str(INTEGRATION)]
    sys.modules[package_name] = package

    client = ModuleType(f"{package_name}.client")
    client.CollectorAuthenticationError = _CollectorAuthenticationError
    client.CollectorClient = object
    client.CollectorError = _CollectorError
    client.CollectorMeasurements = object
    client.CollectorProtocolError = _CollectorProtocolError
    client.CollectorStatus = object
    sys.modules[client.__name__] = client

    homeassistant = ModuleType("homeassistant")
    config_entries = ModuleType("homeassistant.config_entries")
    config_entries.ConfigEntry = object
    core = ModuleType("homeassistant.core")
    core.HomeAssistant = object
    exceptions = ModuleType("homeassistant.exceptions")
    exceptions.ConfigEntryAuthFailed = _ConfigEntryAuthFailed
    helpers = ModuleType("homeassistant.helpers")
    update_coordinator = ModuleType("homeassistant.helpers.update_coordinator")
    update_coordinator.DataUpdateCoordinator = _DataUpdateCoordinator
    update_coordinator.UpdateFailed = _UpdateFailed
    sys.modules.update(
        {
            "homeassistant": homeassistant,
            "homeassistant.config_entries": config_entries,
            "homeassistant.core": core,
            "homeassistant.exceptions": exceptions,
            "homeassistant.helpers": helpers,
            "homeassistant.helpers.update_coordinator": update_coordinator,
        }
    )

    name = f"{package_name}.coordinator"
    spec = importlib.util.spec_from_file_location(name, INTEGRATION / "coordinator.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


coordinator_module = _load_coordinator_module()


def _completeness(expected: int, valid: int):
    return SimpleNamespace(
        state="complete" if expected == valid else "partial",
        expected_count=expected,
        valid_count=valid,
        missing_count=expected - valid,
        invalid_count=0,
    )


def _status(**changes):
    values = {
        "meter_id": "mtr_test",
        "dataset_revision": "ds_revision",
        "data_timestamp": datetime(2026, 10, 25, 1, 30, tzinfo=timezone.utc),
        "last_attempt": datetime(2026, 10, 25, 1, 35, tzinfo=timezone.utc),
        "last_success": datetime(2026, 10, 25, 1, 34, tzinfo=timezone.utc),
        "completeness": _completeness(192, 192),
        "source_status": "ok",
    }
    values.update(changes)
    return SimpleNamespace(**values)


def _measurements(status, **changes):
    values = {
        "meter_id": status.meter_id,
        "dataset_revision": status.dataset_revision,
        "data_timestamp": status.data_timestamp,
        "last_attempt": status.last_attempt,
        "last_success": status.last_success,
        "completeness": _completeness(96, 92),
        "source_status": status.source_status,
    }
    values.update(changes)
    return SimpleNamespace(**values)


class _Client:
    def __init__(self, status, measurements=None) -> None:
        self.status = status
        self.measurements = measurements or _measurements(status)
        self.calls = []

    async def async_status(self):
        self.calls.append("status")
        return self.status

    async def async_health(self):
        self.calls.append("health")
        return "ok"

    async def async_measurements(self, start: str, end: str):
        self.calls.append(("measurements", start, end))
        return self.measurements


class CoordinatorTests(unittest.IsolatedAsyncioTestCase):
    async def test_uses_latest_24_hours_in_utc_and_allows_range_completeness(self):
        status = _status()
        client = _Client(status)
        coordinator = coordinator_module.CezPndCoordinator(object(), object(), client)

        snapshot = await coordinator._async_update_data()

        self.assertIs(snapshot.status, status)
        self.assertEqual(
            client.calls,
            [
                "status",
                "health",
                (
                    "measurements",
                    "2026-10-24T01:30:00Z",
                    "2026-10-25T01:30:00Z",
                ),
            ],
        )
        self.assertNotEqual(status.completeness, snapshot.measurements.completeness)

    async def test_revision_mismatch_fails(self):
        status = _status()
        client = _Client(
            status,
            _measurements(status, dataset_revision="ds_other_revision"),
        )
        coordinator = coordinator_module.CezPndCoordinator(object(), object(), client)

        with self.assertRaises(_UpdateFailed):
            await coordinator._async_update_data()

    async def test_snapshot_metadata_mismatch_fails(self):
        status = _status()
        for field, value in (
            ("meter_id", "mtr_other"),
            ("data_timestamp", datetime(2026, 10, 25, 1, 15, tzinfo=timezone.utc)),
            ("last_attempt", datetime(2026, 10, 25, 1, 36, tzinfo=timezone.utc)),
            ("last_success", datetime(2026, 10, 25, 1, 33, tzinfo=timezone.utc)),
            ("source_status", "partial"),
        ):
            with self.subTest(field=field):
                client = _Client(status, _measurements(status, **{field: value}))
                coordinator = coordinator_module.CezPndCoordinator(
                    object(), object(), client
                )
                with self.assertRaises(_UpdateFailed):
                    await coordinator._async_update_data()

    async def test_missing_committed_dataset_fails_before_other_requests(self):
        for field in ("data_timestamp", "last_success"):
            with self.subTest(field=field):
                client = _Client(_status(**{field: None}))
                coordinator = coordinator_module.CezPndCoordinator(
                    object(), object(), client
                )
                with self.assertRaisesRegex(
                    _UpdateFailed, "^collector_dataset_unavailable$"
                ):
                    await coordinator._async_update_data()
                self.assertEqual(client.calls, ["status"])

    def test_synthetic_ranges_are_removed(self):
        source = "\n".join(
            (INTEGRATION / name).read_text(encoding="utf-8")
            for name in ("const.py", "coordinator.py")
        )
        self.assertNotIn("SYNTHETIC_RANGE_START", source)
        self.assertNotIn("SYNTHETIC_RANGE_END", source)


if __name__ == "__main__":
    unittest.main()
