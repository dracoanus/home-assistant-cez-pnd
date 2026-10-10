"""Small shared serializer for timestamped structured Collector events."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import sys
import threading
from typing import TextIO
from typing import Mapping


_WRITE_LOCK = threading.Lock()


def write_json_line(line: str, *, file: TextIO | None = None, flush: bool = False) -> None:
    """Write a complete previously validated JSON line under one shared lock."""

    stream = file if file is not None else sys.stdout
    with _WRITE_LOCK:
        stream.write(line + "\n")
        if flush:
            stream.flush()


def utc_timestamp(now: datetime | None = None) -> str:
    """Return an aware UTC instant at ISO 8601 second precision."""

    current = now if now is not None else datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")
    return current.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def structured_event_json(
    fields: Mapping[str, object], *, now: datetime | None = None
) -> str:
    """Serialize an existing safe event with timestamp as its first field."""

    return json.dumps(
        {"timestamp": utc_timestamp(now), **fields}, separators=(",", ":")
    )
