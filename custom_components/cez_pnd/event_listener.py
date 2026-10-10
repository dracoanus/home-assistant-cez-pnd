"""ConfigEntry-owned event trigger and bounded reconciliation recovery."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
import random

from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import UpdateFailed

from .client import CollectorAuthenticationError, CollectorError, CollectorUpdateRequired

RECONCILIATION_SECONDS = 300
RECONNECT_SECONDS = (1, 2, 5, 10, 30, 60)


class CollectorEventListener:
    """One sequential long poll; notifications never supply entity state."""

    def __init__(
        self, hass, entry, client, coordinator, cursor: str, *,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        jitter: Callable[[], float] = lambda: random.uniform(0, 0.5),
    ) -> None:
        self._hass, self._entry = hass, entry
        self._client, self._coordinator = client, coordinator
        self._cursor = cursor
        self._sleep, self._jitter = sleep, jitter
        self._tasks: list[asyncio.Task] = []
        self._terminal = False

    def start(self) -> None:
        if self._tasks:
            raise RuntimeError("event_listener_already_started")
        self._tasks = [
            self._entry.async_create_background_task(
                self._hass, self._listen(), "cez_pnd_event_listener", eager_start=False
            ),
            self._entry.async_create_background_task(
                self._hass, self._watchdog(), "cez_pnd_reconciliation_watchdog", eager_start=False
            ),
        ]
        self._entry.async_on_unload(self.cancel)

    def cancel(self) -> None:
        self._terminal = True
        for task in self._tasks:
            task.cancel()

    async def async_stop(self) -> None:
        self.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)

    def _stop_watchdog(self) -> None:
        self._terminal = True
        if len(self._tasks) > 1:
            self._tasks[1].cancel()

    def _reauth(self) -> None:
        if self._terminal:
            return
        self._stop_watchdog()
        self._entry.async_start_reauth(self._hass)

    async def _listen(self) -> None:
        failures = 0
        while not self._terminal:
            try:
                event = await self._client.async_events(self._cursor)
                failures = 0
                if event is not None:
                    self._cursor = event.cursor
                    await self._coordinator.async_request_refresh()
            except (CollectorAuthenticationError, ConfigEntryAuthFailed):
                self._reauth()
                return
            except CollectorUpdateRequired:
                self._stop_watchdog()
                self._hass.config_entries.async_schedule_reload(self._entry.entry_id)
                return
            except (CollectorError, UpdateFailed):
                base = RECONNECT_SECONDS[min(failures, len(RECONNECT_SECONDS) - 1)]
                failures += 1
                await self._sleep(base + min(max(self._jitter(), 0), 0.5))

    async def _watchdog(self) -> None:
        while not self._terminal:
            await self._sleep(RECONCILIATION_SECONDS)
            if self._terminal:
                return
            try:
                await self._coordinator.async_request_refresh()
            except ConfigEntryAuthFailed:
                self._reauth()
                if self._tasks:
                    self._tasks[0].cancel()
                return
            except (CollectorError, UpdateFailed):
                # The coordinator retains its normal unavailable-state handling.
                continue
