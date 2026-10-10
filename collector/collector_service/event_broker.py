"""Bounded, in-memory notifications; deliberately not a durable event log."""

from __future__ import annotations

from dataclasses import dataclass
import re
import secrets
import threading

from .dataset_revision import REVISION_PATTERN


MAX_EVENT_WAITERS = 2
MAX_EVENT_WAIT_SECONDS = 25.0
MAX_EVENT_RESPONSE_BYTES = 4096
MAX_SEQUENCE = (1 << 63) - 1
CURSOR_PATTERN = re.compile(r"ev1_[a-f0-9]{32}_(?:0|[1-9][0-9]{0,18})", re.ASCII)
SYNC_KINDS = frozenset({"current_day", "historical_backfill", "historical_correction"})
SYNC_RESULTS = frozenset({"succeeded", "failed"})


class EventBrokerError(ValueError):
    """A fixed code only, never a cursor or caller-supplied value."""

    def __init__(self, code: str):
        if code not in {"invalid_event_cursor", "event_waiter_limit", "event_broker_stopping"}:
            raise ValueError("invalid broker error")
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class SyncEvent:
    sync_kind: str
    sync_result: str
    dataset_revision: str | None

    def __post_init__(self) -> None:
        if self.sync_kind not in SYNC_KINDS or self.sync_result not in SYNC_RESULTS:
            raise ValueError("invalid sync event")
        if self.dataset_revision is not None and (
            not isinstance(self.dataset_revision, str)
            or not REVISION_PATTERN.fullmatch(self.dataset_revision)
        ):
            raise ValueError("invalid event revision")


@dataclass(frozen=True)
class EventSnapshot:
    cursor: str
    event: SyncEvent | None = None

    def as_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": 1,
            "event": "state_reset" if self.event is None else "sync_finished",
            "cursor": self.cursor,
        }
        if self.event is not None:
            result.update(sync_kind=self.event.sync_kind, sync_result=self.event.sync_result,
                          dataset_revision=self.event.dataset_revision)
        return result


def parse_event_cursor(cursor: str) -> tuple[str, int]:
    if not isinstance(cursor, str) or len(cursor) > 56 or not CURSOR_PATTERN.fullmatch(cursor):
        raise EventBrokerError("invalid_event_cursor")
    _, generation, raw_sequence = cursor.split("_")
    sequence = int(raw_sequence)
    if sequence > MAX_SEQUENCE:
        raise EventBrokerError("invalid_event_cursor")
    return generation, sequence


class EventBroker:
    """Retain one immutable event, coalescing missed publications atomically."""

    def __init__(self) -> None:
        self._condition = threading.Condition()
        self._generation = secrets.token_hex(16)
        self._sequence = 0
        self._latest: SyncEvent | None = None
        self._closed = False
        self._waiters = 0

    def _cursor(self) -> str:
        return f"ev1_{self._generation}_{self._sequence}"

    def publish(self, event: SyncEvent) -> None:
        if type(event) is not SyncEvent:
            raise ValueError("invalid sync event")
        with self._condition:
            if self._closed:
                raise EventBrokerError("event_broker_stopping")
            if self._sequence == MAX_SEQUENCE:
                raise ValueError("event sequence exhausted")
            self._sequence += 1
            self._latest = event
            self._condition.notify_all()

    def wait(self, cursor: str | None, *, timeout: float = MAX_EVENT_WAIT_SECONDS) -> EventSnapshot | None:
        if isinstance(timeout, bool) or not 0 <= timeout <= MAX_EVENT_WAIT_SECONDS:
            raise ValueError("invalid event timeout")
        parsed = parse_event_cursor(cursor) if cursor is not None else None
        with self._condition:
            if self._closed:
                raise EventBrokerError("event_broker_stopping")
            if parsed is None or parsed[0] != self._generation or parsed[1] > self._sequence:
                return EventSnapshot(self._cursor())
            if parsed[1] < self._sequence:
                return EventSnapshot(self._cursor(), self._latest)
            if self._waiters >= MAX_EVENT_WAITERS:
                raise EventBrokerError("event_waiter_limit")
            self._waiters += 1
            try:
                self._condition.wait_for(
                    lambda: self._closed or self._sequence != parsed[1], timeout=timeout
                )
                if self._closed:
                    raise EventBrokerError("event_broker_stopping")
                if self._sequence != parsed[1]:
                    return EventSnapshot(self._cursor(), self._latest)
                return None
            finally:
                self._waiters -= 1

    def close(self) -> None:
        with self._condition:
            self._closed = True
            self._condition.notify_all()
