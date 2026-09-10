"""HA-independent normalized model for bounded CEZ PND interval exports."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal
from enum import Enum


class PndChannel(str, Enum):
    CONSUMPTION = "consumption"
    PRODUCTION = "production"

    @property
    def profile_marker(self) -> str:
        return "+A" if self is PndChannel.CONSUMPTION else "-A"


class IntervalQuality(str, Enum):
    VALID = "valid"
    MISSING = "missing"


@dataclass(frozen=True)
class IntervalRecord:
    """One half-open 15-minute UTC interval from one CEZ profile."""

    channel: PndChannel
    interval_start: datetime
    interval_end: datetime
    value_kwh: Decimal | None
    quality: IntervalQuality
    source_day: date

    def __post_init__(self) -> None:
        if self.interval_start.tzinfo is None or self.interval_end.tzinfo is None:
            raise ValueError("interval must be timezone-aware")
        if (self.interval_end - self.interval_start).total_seconds() != 15 * 60:
            raise ValueError("interval must be 15 minutes")
        if self.quality is IntervalQuality.VALID:
            if self.value_kwh is None or not self.value_kwh.is_finite() or self.value_kwh < 0:
                raise ValueError("valid interval requires non-negative finite energy")
        elif self.value_kwh is not None:
            raise ValueError("missing interval cannot carry a value")

    @property
    def timestamp(self) -> datetime:
        """Compatibility timestamp: CEZ profile timestamps denote interval end."""

        return self.interval_end

    @property
    def valid(self) -> bool:
        return self.quality is IntervalQuality.VALID


@dataclass(frozen=True)
class ParsedPndData:
    """One independently validated consumption or production profile."""

    channel: PndChannel
    profile: str
    encoding: str
    delimiter: str
    intervals: tuple[IntervalRecord, ...]

    @property
    def valid_count(self) -> int:
        return sum(record.valid for record in self.intervals)

    @property
    def missing_count(self) -> int:
        return len(self.intervals) - self.valid_count

    @property
    def complete(self) -> bool:
        return bool(self.intervals) and self.missing_count == 0
