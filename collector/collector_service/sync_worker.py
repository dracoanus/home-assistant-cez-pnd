"""Bounded background synchronization for the latest completed CEZ day."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
import threading
from typing import Callable
from zoneinfo import ZoneInfo

from .cez_data_probe import run_data_probe
from .cez_http_auth import (
    AuthStatus,
    DataProbeDatasetCommittedObservation,
    SAFE_ERROR_CODES,
    SafeHttpAuthEvent,
    emit_json_event as emit_http_auth_event,
)
from .dataset_store import NormalizedDatasetStore
from .requests_preauth import RequestsSessionTransport
from .runtime_config import SyncConfiguration
from .structured_logging import structured_event_json


PRAGUE_TIMEZONE = ZoneInfo("Europe/Prague")
SYNC_INTERVAL_SECONDS = 6 * 60 * 60
INITIAL_SYNC_DELAY_SECONDS = 0.0
WORKER_STOP_TIMEOUT_SECONDS = 65.0
SYNC_EVENTS = frozenset(
    {
        "sync_worker_started",
        "sync_cycle_started",
        "sync_cycle_succeeded",
        "sync_cycle_failed",
        "sync_worker_stopped",
    }
)
SYNC_FAILURE_CODES = SAFE_ERROR_CODES | frozenset(
    {
        "auth_success_condition_needs_live_verification",
        "sync_cycle_internal_failed",
        "sync_cycle_commit_evidence_missing",
    }
)


@dataclass(frozen=True)
class SyncCycleOutcome:
    """Non-secret outcome returned by one synchronous collection cycle."""

    succeeded: bool
    code: str | None = None
    committed: DataProbeDatasetCommittedObservation | None = None

    def __post_init__(self) -> None:
        if self.succeeded:
            if self.code is not None or self.committed is None:
                raise ValueError("invalid successful sync outcome")
        elif self.code not in SYNC_FAILURE_CODES or self.committed is not None:
            raise ValueError("invalid failed sync outcome")


@dataclass(frozen=True)
class SafeSyncEvent:
    """Allowlisted production synchronization event."""

    event: str
    code: str | None = None
    committed: DataProbeDatasetCommittedObservation | None = None

    def __post_init__(self) -> None:
        if self.event not in SYNC_EVENTS:
            raise ValueError("unsafe sync event")
        if self.event == "sync_cycle_failed":
            if self.code not in SYNC_FAILURE_CODES or self.committed is not None:
                raise ValueError("invalid failed sync event")
        elif self.event == "sync_cycle_succeeded":
            if self.code is not None or self.committed is None:
                raise ValueError("invalid successful sync event")
        elif self.code is not None or self.committed is not None:
            raise ValueError("unexpected sync event fields")

    def as_dict(self) -> dict[str, object]:
        fields: dict[str, object] = {"event": self.event}
        if self.code is not None:
            fields["code"] = self.code
        if self.committed is not None:
            fields.update(
                {
                    "consumption_intervals": self.committed.consumption_intervals,
                    "production_intervals": self.committed.production_intervals,
                    "dataset_state": self.committed.dataset_state,
                }
            )
        return fields


def emit_sync_event(event: SafeSyncEvent) -> None:
    print(structured_event_json(event.as_dict()), flush=True)


def run_sync_cycle(
    configuration: SyncConfiguration,
    target_day: date,
    *,
    store: NormalizedDatasetStore,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
    transport_factory: Callable[[], RequestsSessionTransport] = RequestsSessionTransport,
    emit_auth: Callable[[SafeHttpAuthEvent], None] = emit_http_auth_event,
) -> SyncCycleOutcome:
    """Reuse the proven collection path without persisting raw CEZ responses."""

    committed: DataProbeDatasetCommittedObservation | None = None

    def capture(event: SafeHttpAuthEvent) -> None:
        nonlocal committed
        emit_auth(event)
        if event.event == "data_probe_dataset_committed":
            committed = event.dataset_committed_observation

    transport = transport_factory()
    result = run_data_probe(
        configuration.for_date(target_day),
        transport,
        resolver=transport.resolve,
        dataset_store=store,
        persist_raw_outputs=False,
        now=now,
        emit=capture,
    )
    if result.status is not AuthStatus.AUTHENTICATED:
        return SyncCycleOutcome(False, code=result.code)
    if committed is None:
        return SyncCycleOutcome(False, code="sync_cycle_commit_evidence_missing")
    return SyncCycleOutcome(True, committed=committed)


class SyncWorker:
    """One explicitly stopped worker with no overlapping synchronization runs."""

    def __init__(
        self,
        configuration: SyncConfiguration,
        *,
        store: NormalizedDatasetStore,
        cycle: Callable[[SyncConfiguration, date], SyncCycleOutcome] | None = None,
        emit: Callable[[SafeSyncEvent], None] = emit_sync_event,
        now_local: Callable[[], datetime] = lambda: datetime.now(PRAGUE_TIMEZONE),
        interval_seconds: float = SYNC_INTERVAL_SECONDS,
        initial_delay_seconds: float = INITIAL_SYNC_DELAY_SECONDS,
    ) -> None:
        self._configuration = configuration
        self._store = store
        self._cycle = cycle or self._default_cycle
        self._emit = emit
        self._now_local = now_local
        self._interval_seconds = interval_seconds
        self._initial_delay_seconds = initial_delay_seconds
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None:
            raise RuntimeError("sync worker already started")
        self._thread = threading.Thread(
            target=self._run,
            name="cez-pnd-sync",
            daemon=True,
        )
        self._thread.start()

    def stop(self, timeout: float = WORKER_STOP_TIMEOUT_SECONDS) -> bool:
        self._stop_event.set()
        thread = self._thread
        if thread is None:
            return True
        thread.join(timeout)
        return not thread.is_alive()

    def _default_cycle(
        self, configuration: SyncConfiguration, target_day: date
    ) -> SyncCycleOutcome:
        return run_sync_cycle(configuration, target_day, store=self._store)

    def _run(self) -> None:
        self._emit(SafeSyncEvent("sync_worker_started"))
        try:
            if self._stop_event.wait(self._initial_delay_seconds):
                return
            while not self._stop_event.is_set():
                target_day = (
                    self._now_local().astimezone(PRAGUE_TIMEZONE).date()
                    - timedelta(days=1)
                )
                self._emit(SafeSyncEvent("sync_cycle_started"))
                try:
                    outcome = self._cycle(self._configuration, target_day)
                except Exception:
                    outcome = SyncCycleOutcome(
                        False, code="sync_cycle_internal_failed"
                    )
                if outcome.succeeded:
                    self._emit(
                        SafeSyncEvent(
                            "sync_cycle_succeeded", committed=outcome.committed
                        )
                    )
                else:
                    self._emit(SafeSyncEvent("sync_cycle_failed", code=outcome.code))
                if self._stop_event.wait(self._interval_seconds):
                    break
        finally:
            self._emit(SafeSyncEvent("sync_worker_stopped"))
