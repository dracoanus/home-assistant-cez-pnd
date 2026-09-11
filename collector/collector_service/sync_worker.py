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
BACKFILL_CHUNK_DAYS = 31
BACKFILL_MAX_CHUNKS_PER_CYCLE = 2
CORRECTION_OVERLAP_DAYS = 3
INITIAL_SYNC_DELAY_SECONDS = 0.0
WORKER_STOP_TIMEOUT_SECONDS = 65.0
SYNC_EVENTS = frozenset(
    {
        "sync_worker_started",
        "sync_cycle_started",
        "sync_cycle_succeeded",
        "sync_cycle_failed",
        "sync_worker_stopped",
        "backfill_started",
        "backfill_chunk_started",
        "backfill_chunk_succeeded",
        "backfill_chunk_failed",
        "backfill_complete",
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
    start_day: date | None = None
    end_day: date | None = None

    def __post_init__(self) -> None:
        if self.event not in SYNC_EVENTS:
            raise ValueError("unsafe sync event")
        if any(
            value is not None and type(value) is not date
            for value in (self.start_day, self.end_day)
        ):
            raise ValueError("unsafe sync event date")
        if self.start_day is not None and self.end_day is not None and (
            self.start_day >= self.end_day
            or self.end_day - self.start_day > timedelta(days=BACKFILL_CHUNK_DAYS)
        ):
            raise ValueError("unsafe sync event range")
        if self.event == "sync_cycle_failed":
            if (
                self.code not in SYNC_FAILURE_CODES
                or self.committed is not None
                or self.start_day is not None
                or self.end_day is not None
            ):
                raise ValueError("invalid failed sync event")
        elif self.event == "sync_cycle_succeeded":
            if (
                self.code is not None
                or self.committed is None
                or self.start_day is not None
                or self.end_day is not None
            ):
                raise ValueError("invalid successful sync event")
        elif self.event == "backfill_started":
            if (
                self.start_day is None
                or self.end_day is not None
                or self.code is not None
                or self.committed is not None
            ):
                raise ValueError("invalid backfill started event")
        elif self.event in {"backfill_chunk_started", "backfill_chunk_succeeded", "backfill_chunk_failed"}:
            if self.start_day is None or self.end_day is None:
                raise ValueError("missing backfill chunk range")
            if self.event == "backfill_chunk_started" and (
                self.code is not None or self.committed is not None
            ):
                raise ValueError("invalid backfill chunk started event")
            if self.event == "backfill_chunk_succeeded" and (
                self.code is not None or self.committed is None
            ):
                raise ValueError("invalid backfill chunk succeeded event")
            if self.event == "backfill_chunk_failed" and (
                self.code not in SYNC_FAILURE_CODES or self.committed is not None
            ):
                raise ValueError("invalid backfill chunk failed event")
        elif self.event == "backfill_complete":
            if (
                self.code is not None
                or self.committed is not None
                or self.start_day is not None
                or self.end_day is not None
            ):
                raise ValueError("invalid backfill complete event")
        elif (
            self.code is not None
            or self.committed is not None
            or self.start_day is not None
            or self.end_day is not None
        ):
            raise ValueError("unexpected sync event fields")

    def as_dict(self) -> dict[str, object]:
        fields: dict[str, object] = {"event": self.event}
        if self.code is not None:
            fields["code"] = self.code
        if self.start_day is not None:
            fields["start_day"] = self.start_day.isoformat()
        if self.end_day is not None:
            fields["end_day"] = self.end_day.isoformat()
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
    start_day: date,
    end_day: date,
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
        configuration.for_date(start_day),
        transport,
        resolver=transport.resolve,
        dataset_store=store,
        persist_raw_outputs=False,
        start_day=start_day,
        end_day=end_day,
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
        cycle: Callable[[SyncConfiguration, date, date], SyncCycleOutcome] | None = None,
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
        self, configuration: SyncConfiguration, start_day: date, end_day: date
    ) -> SyncCycleOutcome:
        return run_sync_cycle(
            configuration, start_day, end_day, store=self._store
        )

    def _scheduled_cycle(self, latest_completed_day: date) -> SyncCycleOutcome:
        history_start = self._configuration.history_start
        if history_start is None:
            return self._cycle(
                self._configuration,
                latest_completed_day,
                latest_completed_day + timedelta(days=1),
            )

        state = self._store.prepare_sync_state(
            history_start, latest_completed_day
        )
        if state.backfill_complete:
            overlap_start = max(
                state.requested_history_start,
                latest_completed_day - timedelta(days=CORRECTION_OVERLAP_DAYS - 1),
            )
            if overlap_start > latest_completed_day:
                overlap_start = latest_completed_day
            return self._cycle(
                self._configuration,
                overlap_start,
                latest_completed_day + timedelta(days=1),
            )

        self._emit(
            SafeSyncEvent("backfill_started", start_day=state.backfill_next_day)
        )
        last_outcome: SyncCycleOutcome | None = None
        for _chunk in range(BACKFILL_MAX_CHUNKS_PER_CYCLE):
            start_day = state.backfill_next_day
            end_day = min(
                start_day + timedelta(days=BACKFILL_CHUNK_DAYS),
                latest_completed_day + timedelta(days=1),
            )
            self._emit(
                SafeSyncEvent(
                    "backfill_chunk_started",
                    start_day=start_day,
                    end_day=end_day,
                )
            )
            try:
                outcome = self._cycle(self._configuration, start_day, end_day)
            except Exception:
                outcome = SyncCycleOutcome(False, code="sync_cycle_internal_failed")
            if not outcome.succeeded:
                self._emit(
                    SafeSyncEvent(
                        "backfill_chunk_failed",
                        code=outcome.code,
                        start_day=start_day,
                        end_day=end_day,
                    )
                )
                return outcome
            try:
                state = self._store.advance_sync_state(
                    start_day, end_day, latest_completed_day
                )
            except Exception:
                failed = SyncCycleOutcome(False, code="data_probe_storage_failed")
                self._emit(
                    SafeSyncEvent(
                        "backfill_chunk_failed",
                        code=failed.code,
                        start_day=start_day,
                        end_day=end_day,
                    )
                )
                return failed
            self._emit(
                SafeSyncEvent(
                    "backfill_chunk_succeeded",
                    committed=outcome.committed,
                    start_day=start_day,
                    end_day=end_day,
                )
            )
            last_outcome = outcome
            if state.backfill_complete:
                self._emit(SafeSyncEvent("backfill_complete"))
                break
        if last_outcome is None:
            return SyncCycleOutcome(False, code="sync_cycle_internal_failed")
        return last_outcome

    def _run(self) -> None:
        self._emit(SafeSyncEvent("sync_worker_started"))
        try:
            if self._stop_event.wait(self._initial_delay_seconds):
                return
            while not self._stop_event.is_set():
                latest_completed_day = (
                    self._now_local().astimezone(PRAGUE_TIMEZONE).date()
                    - timedelta(days=1)
                )
                self._emit(SafeSyncEvent("sync_cycle_started"))
                try:
                    outcome = self._scheduled_cycle(latest_completed_day)
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
