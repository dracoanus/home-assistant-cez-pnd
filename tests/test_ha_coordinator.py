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

    def __init__(self, *_args, **kwargs) -> None:
        self.update_interval = kwargs.get("update_interval")


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
        self.statuses = status if isinstance(status, list) else [status]
        default_status = self.statuses[0]
        supplied = measurements or _measurements(default_status)
        self.measurements = supplied if isinstance(supplied, list) else [supplied]
        self.calls = []

    async def async_status(self):
        self.calls.append("status")
        return self.statuses.pop(0) if len(self.statuses) > 1 else self.statuses[0]

    async def async_health(self):
        self.calls.append("health")
        return "ok"

    async def async_measurements(self, start: str, end: str):
        self.calls.append(("measurements", start, end))
        return (
            self.measurements.pop(0)
            if len(self.measurements) > 1
            else self.measurements[0]
        )


def _entry(interval=None):
    options = {} if interval is None else {"poll_interval_seconds": interval}
    return SimpleNamespace(options=options)


class CoordinatorTests(unittest.IsolatedAsyncioTestCase):
    async def test_uses_latest_24_hours_in_utc_and_allows_range_completeness(self):
        status = _status()
        client = _Client(status)
        coordinator = coordinator_module.CezPndCoordinator(object(), _entry(), client)

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
        coordinator = coordinator_module.CezPndCoordinator(object(), _entry(), client)

        with self.assertRaises(_UpdateFailed):
            await coordinator._async_update_data()

    async def test_snapshot_metadata_mismatch_fails(self):
        status = _status()
        for field, value in (
            ("meter_id", "mtr_other"),
            ("data_timestamp", datetime(2026, 10, 25, 1, 15, tzinfo=timezone.utc)),
            ("last_success", datetime(2026, 10, 25, 1, 33, tzinfo=timezone.utc)),
            ("source_status", "partial"),
        ):
            with self.subTest(field=field):
                client = _Client(status, _measurements(status, **{field: value}))
                coordinator = coordinator_module.CezPndCoordinator(
                    object(), _entry(), client
                )
                with self.assertRaises(_UpdateFailed):
                    await coordinator._async_update_data()

    async def test_missing_committed_dataset_fails_before_other_requests(self):
        for field in ("data_timestamp", "last_success"):
            with self.subTest(field=field):
                client = _Client(_status(**{field: None}))
                coordinator = coordinator_module.CezPndCoordinator(
                    object(), _entry(), client
                )
                with self.assertRaisesRegex(
                    _UpdateFailed, "^collector_dataset_unavailable$"
                ):
                    await coordinator._async_update_data()
                self.assertEqual(client.calls, ["status"])

    async def test_unchanged_revision_reuses_measurements_and_updates_attempt(self):
        initial = _status()
        later = _status(
            last_attempt=datetime(2026, 10, 25, 1, 50, tzinfo=timezone.utc)
        )
        measurements = _measurements(initial)
        client = _Client([initial, later], measurements)
        coordinator = coordinator_module.CezPndCoordinator(object(), _entry(), client)

        first = await coordinator._async_update_data()
        second = await coordinator._async_update_data()

        self.assertIs(first.measurements, second.measurements)
        self.assertEqual(second.status.last_attempt, later.last_attempt)
        self.assertEqual(
            sum(isinstance(call, tuple) and call[0] == "measurements" for call in client.calls),
            1,
        )

    async def test_unchanged_revision_metadata_changes_fail_closed(self):
        cases = (
            ("data_timestamp", datetime(2026, 10, 25, 1, 45, tzinfo=timezone.utc)),
            ("last_success", datetime(2026, 10, 25, 1, 45, tzinfo=timezone.utc)),
            ("source_status", "partial"),
        )
        for field, changed in cases:
            with self.subTest(field=field):
                initial = _status()
                client = _Client([initial, _status(**{field: changed})])
                coordinator = coordinator_module.CezPndCoordinator(
                    object(), _entry(), client
                )
                await coordinator._async_update_data()
                with self.assertRaises(_UpdateFailed):
                    await coordinator._async_update_data()

    async def test_changed_revision_fetches_range_from_new_timestamp(self):
        initial = _status()
        changed = _status(
            dataset_revision="ds_changed",
            data_timestamp=datetime(2026, 10, 26, 2, 0, tzinfo=timezone.utc),
            last_success=datetime(2026, 10, 26, 2, 5, tzinfo=timezone.utc),
        )
        client = _Client(
            [initial, changed],
            [_measurements(initial), _measurements(changed)],
        )
        coordinator = coordinator_module.CezPndCoordinator(object(), _entry(), client)

        await coordinator._async_update_data()
        snapshot = await coordinator._async_update_data()

        self.assertEqual(snapshot.measurements.dataset_revision, "ds_changed")
        self.assertEqual(
            client.calls[-1],
            (
                "measurements",
                "2026-10-25T02:00:00Z",
                "2026-10-26T02:00:00Z",
            ),
        )

    async def test_revision_race_retries_once_and_succeeds(self):
        status_a = _status(dataset_revision="ds_a")
        status_b = _status(
            dataset_revision="ds_b",
            data_timestamp=datetime(2026, 10, 26, 2, tzinfo=timezone.utc),
            last_success=datetime(2026, 10, 26, 2, 5, tzinfo=timezone.utc),
        )
        measurements_b = _measurements(status_b)
        client = _Client([status_a, status_b], [measurements_b, measurements_b])
        coordinator = coordinator_module.CezPndCoordinator(object(), _entry(), client)

        snapshot = await coordinator._async_update_data()

        self.assertEqual(snapshot.status.dataset_revision, "ds_b")
        self.assertEqual(client.calls.count("status"), 2)
        self.assertEqual(
            sum(isinstance(call, tuple) and call[0] == "measurements" for call in client.calls),
            2,
        )

    async def test_second_revision_inconsistency_fails_without_more_retries(self):
        status_a = _status(dataset_revision="ds_a")
        status_b = _status(dataset_revision="ds_b")
        measurements_b = _measurements(status_b)
        measurements_c = _measurements(status_b, dataset_revision="ds_c")
        client = _Client(
            [status_a, status_b], [measurements_b, measurements_c]
        )
        coordinator = coordinator_module.CezPndCoordinator(object(), _entry(), client)

        with self.assertRaises(_UpdateFailed):
            await coordinator._async_update_data()
        self.assertEqual(client.calls.count("status"), 2)
        self.assertEqual(
            sum(isinstance(call, tuple) and call[0] == "measurements" for call in client.calls),
            2,
        )

    def test_coordinator_uses_default_and_configured_intervals(self):
        client = _Client(_status())
        default = coordinator_module.CezPndCoordinator(object(), _entry(), client)
        configured = coordinator_module.CezPndCoordinator(
            object(), _entry(30), client
        )
        self.assertEqual(default.update_interval.total_seconds(), 60)
        self.assertEqual(configured.update_interval.total_seconds(), 30)

    def test_synthetic_ranges_are_removed(self):
        source = "\n".join(
            (INTEGRATION / name).read_text(encoding="utf-8")
            for name in ("const.py", "coordinator.py")
        )
        self.assertNotIn("SYNTHETIC_RANGE_START", source)
        self.assertNotIn("SYNTHETIC_RANGE_END", source)


if __name__ == "__main__":
    unittest.main()
