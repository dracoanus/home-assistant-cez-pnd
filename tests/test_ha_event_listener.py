"""Deterministic event lifecycle tests; no Home Assistant or external network."""
import asyncio
import importlib.util
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

import test_ha_collector_client as client_tests
import test_ha_coordinator as coordinator_tests

ROOT = Path(__file__).parents[1]
INTEGRATION = ROOT / "custom_components" / "cez_pnd"
client_module = client_tests.client_module


def _load_listener():
    name = "cez_pnd_listener_test"
    package = ModuleType(name)
    package.__path__ = [str(INTEGRATION)]
    exceptions = ModuleType("homeassistant.exceptions")
    exceptions.ConfigEntryAuthFailed = coordinator_tests._ConfigEntryAuthFailed
    updates = ModuleType("homeassistant.helpers.update_coordinator")
    updates.UpdateFailed = coordinator_tests._UpdateFailed
    with patch.dict(sys.modules, {name: package, name + ".client": client_module,
        "homeassistant.exceptions": exceptions,
        "homeassistant.helpers.update_coordinator": updates}):
        spec = importlib.util.spec_from_file_location(name + ".event_listener", INTEGRATION / "event_listener.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    return module


listener_module = _load_listener()
CURSOR = "ev1_" + "a" * 32 + "_0"


class _Entry:
    entry_id = "synthetic-entry"
    def __init__(self):
        self.tasks, self.unloads = [], []
        self.async_start_reauth = Mock()
    def async_create_background_task(self, hass, coroutine, name, **kwargs):
        task = asyncio.create_task(coroutine, name=name)
        self.tasks.append(task)
        return task
    def async_on_unload(self, callback):
        self.unloads.append(callback)


class ListenerTests(unittest.IsolatedAsyncioTestCase):
    def make(self, client=None, coordinator=None, **kwargs):
        entry = _Entry()
        hass = SimpleNamespace(config_entries=SimpleNamespace(async_schedule_reload=Mock()))
        coordinator = coordinator or SimpleNamespace(async_request_refresh=AsyncMock())
        client = client or SimpleNamespace(async_events=AsyncMock())
        listener = listener_module.CollectorEventListener(
            hass, entry, client, coordinator, CURSOR, **kwargs)
        return listener, entry, hass

    async def test_204_keeps_cursor_events_update_before_refresh(self):
        calls, cursors = [], []
        events = [None, client_module.CollectorEvent("state_reset", CURSOR[:-1] + "1"),
            client_module.CollectorEvent("sync_finished", CURSOR[:-1] + "2", "current_day", "failed", None)]
        async def poll(cursor):
            calls.append(cursor)
            if not events:
                raise asyncio.CancelledError
            return events.pop(0)
        listener, entry, hass = self.make(SimpleNamespace(async_events=poll))
        async def refresh():
            cursors.append(listener._cursor)
        listener._coordinator.async_request_refresh = refresh
        with self.assertRaises(asyncio.CancelledError):
            await listener._listen()
        self.assertEqual(calls, [CURSOR, CURSOR, CURSOR[:-1] + "1", CURSOR[:-1] + "2"])
        self.assertEqual(cursors, [CURSOR[:-1] + "1", CURSOR[:-1] + "2"])
        self.assertEqual(entry.tasks, [])
        self.assertFalse(entry.async_start_reauth.called)

    async def test_event_only_triggers_authoritative_revision_refresh(self):
        initial = coordinator_tests._status()
        changed = coordinator_tests._status(dataset_revision="ds_changed")
        later = coordinator_tests._status(dataset_revision="ds_changed",
            last_attempt=coordinator_tests.datetime(2026, 10, 25, 2, tzinfo=coordinator_tests.timezone.utc))
        api = coordinator_tests._Client([initial, changed, later],
            [coordinator_tests._measurements(initial), coordinator_tests._measurements(changed)])
        coordinator = coordinator_tests.coordinator_module.CezPndCoordinator(object(), SimpleNamespace(options={}), api)
        coordinator.data = await coordinator._async_update_data()
        async def refresh():
            coordinator.data = await coordinator._async_update_data()
        coordinator.async_request_refresh = refresh
        notifications = [client_module.CollectorEvent("sync_finished", CURSOR[:-1] + str(i),
            "current_day", result, "ds_" + "f" * 32)
            for i, result in ((1, "succeeded"), (2, "failed"))]
        async def poll(_cursor):
            if not notifications:
                raise asyncio.CancelledError
            return notifications.pop(0)
        listener, _, _ = self.make(SimpleNamespace(async_events=poll), coordinator)
        with self.assertRaises(asyncio.CancelledError):
            await listener._listen()
        self.assertEqual(coordinator.data.status.dataset_revision, "ds_changed")
        self.assertEqual(coordinator.data.status.last_attempt, later.last_attempt)
        self.assertEqual(api.calls.count("health"), 3)
        self.assertEqual(api.calls.count("status"), 3)
        self.assertEqual(sum(isinstance(c, tuple) for c in api.calls), 2)

    async def test_reconnect_sequence_is_bounded_and_204_resets_it(self):
        delays = []
        calls = 0
        async def poll(_cursor):
            nonlocal calls
            calls += 1
            if calls == 9:
                return None
            if calls == 11:
                raise asyncio.CancelledError
            raise client_module.CollectorConnectionError("fixed")
        async def sleep(delay):
            delays.append(delay)
        listener, _, _ = self.make(SimpleNamespace(async_events=poll), sleep=sleep, jitter=lambda: 0.25)
        with self.assertRaises(asyncio.CancelledError):
            await listener._listen()
        self.assertEqual(delays, [1.25, 2.25, 5.25, 10.25, 30.25, 60.25, 60.25, 60.25, 1.25])

    async def test_successful_event_resets_backoff(self):
        count, delays = 0, []
        async def poll(_cursor):
            nonlocal count
            count += 1
            if count == 3:
                return client_module.CollectorEvent("state_reset", CURSOR)
            if count == 5:
                raise asyncio.CancelledError
            raise client_module.CollectorConnectionError("fixed")
        async def sleep(delay):
            delays.append(delay)
        listener, _, _ = self.make(SimpleNamespace(async_events=poll), sleep=sleep, jitter=lambda: 10)
        with self.assertRaises(asyncio.CancelledError):
            await listener._listen()
        self.assertEqual(delays, [1.5, 2.5, 1.5])

    async def test_first_dataset_event_recovers_health_only_state_and_schedules_statistics(self):
        status = coordinator_tests._status()
        api = coordinator_tests._Client(status)
        api.statuses = [coordinator_tests._CollectorDatasetUnavailable("dataset_unavailable"), status]
        coordinator = coordinator_tests.coordinator_module.CezPndCoordinator(object(), SimpleNamespace(options={}), api)
        coordinator.data = await coordinator._async_update_data()
        self.assertIsNone(coordinator.data.status)
        scheduled = []
        async def refresh():
            coordinator.data = await coordinator._async_update_data()
            if coordinator.data.status is not None:
                scheduled.append(coordinator.data.status)
        coordinator.async_request_refresh = refresh
        count = 0
        async def poll(_cursor):
            nonlocal count
            count += 1
            if count > 1:
                raise asyncio.CancelledError
            return client_module.CollectorEvent("sync_finished", CURSOR, "current_day", "succeeded", None)
        listener, _, _ = self.make(SimpleNamespace(async_events=poll), coordinator)
        with self.assertRaises(asyncio.CancelledError):
            await listener._listen()
        self.assertIs(coordinator.data.status, status)
        self.assertIsNotNone(coordinator.data.measurements)
        self.assertEqual(scheduled, [status])

    async def test_auth_and_downgrade_stop_watchdog_and_do_not_retry(self):
        for error in (client_module.CollectorAuthenticationError("fixed"),
                      client_module.CollectorUpdateRequired("collector_update_required")):
            with self.subTest(error=type(error)):
                client = SimpleNamespace(async_events=AsyncMock(side_effect=error))
                listener, entry, hass = self.make(client)
                listener.start()
                await entry.tasks[0]
                self.assertTrue(listener._terminal)
                self.assertEqual(client.async_events.await_count, 1)
                if isinstance(error, client_module.CollectorAuthenticationError):
                    listener._reauth()
                    entry.async_start_reauth.assert_called_once_with(hass)
                    hass.config_entries.async_schedule_reload.assert_not_called()
                else:
                    hass.config_entries.async_schedule_reload.assert_called_once_with(entry.entry_id)
                    entry.async_start_reauth.assert_not_called()
                await listener.async_stop()
                self.assertTrue(all(task.done() for task in entry.tasks))

    async def test_unload_cancels_active_long_poll_and_watchdog_without_closing_session(self):
        entered = asyncio.Event()
        async def poll(_cursor):
            entered.set()
            await asyncio.Event().wait()
        client = SimpleNamespace(async_events=poll, close=Mock())
        listener, entry, _ = self.make(client)
        listener.start()
        with self.assertRaisesRegex(RuntimeError, "already_started"):
            listener.start()
        await asyncio.wait_for(entered.wait(), 1)
        self.assertEqual(len(entry.tasks), 2)
        entry.unloads[0]()
        await listener.async_stop()
        self.assertTrue(all(task.done() for task in entry.tasks))
        client.close.assert_not_called()

    async def test_unload_interrupts_backoff(self):
        entered = asyncio.Event()
        async def sleep(_delay):
            entered.set()
            await asyncio.Event().wait()
        client = SimpleNamespace(async_events=AsyncMock(side_effect=client_module.CollectorConnectionError("fixed")))
        listener, _, _ = self.make(client, sleep=sleep)
        task = asyncio.create_task(listener._listen())
        await asyncio.wait_for(entered.wait(), 1)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task

    async def test_watchdog_is_fixed_300_seconds_and_requests_public_refresh(self):
        delays = []
        async def sleep(delay):
            delays.append(delay)
            if len(delays) > 1:
                raise asyncio.CancelledError
        listener, _, _ = self.make(sleep=sleep)
        with self.assertRaises(asyncio.CancelledError):
            await listener._watchdog()
        self.assertEqual(delays, [300, 300])
        listener._coordinator.async_request_refresh.assert_awaited_once()

    async def test_many_events_are_sequential_without_task_backlog(self):
        active, maximum, calls = 0, 0, 0
        async def poll(_cursor):
            nonlocal calls
            calls += 1
            if calls > 40:
                raise asyncio.CancelledError
            return client_module.CollectorEvent("sync_finished", CURSOR, "current_day", "succeeded", None)
        async def refresh():
            nonlocal active, maximum
            active += 1
            maximum = max(maximum, active)
            await asyncio.sleep(0)
            active -= 1
        listener, entry, _ = self.make(SimpleNamespace(async_events=poll),
            SimpleNamespace(async_request_refresh=refresh))
        with self.assertRaises(asyncio.CancelledError):
            await listener._listen()
        self.assertEqual(maximum, 1)
        self.assertEqual(entry.tasks, [])

    async def test_errors_with_secret_text_are_not_logged(self):
        async def sleep(_delay):
            raise asyncio.CancelledError
        listener, _, _ = self.make(SimpleNamespace(async_events=AsyncMock(
            side_effect=client_module.CollectorConnectionError("synthetic-private-token https://private.invalid"))), sleep=sleep)
        with patch("logging.Logger._log") as log:
            with self.assertRaises(asyncio.CancelledError):
                await listener._listen()
        log.assert_not_called()


if __name__ == "__main__":
    unittest.main()
