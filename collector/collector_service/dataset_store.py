"""Transactional SQLite storage for normalized CEZ PND measurements."""

from __future__ import annotations

from dataclasses import dataclass
from contextlib import closing
from datetime import UTC, datetime
from decimal import Decimal
import os
from pathlib import Path
import secrets
import sqlite3
import stat

from .cez_csv_models import IntervalQuality, ParsedPndData, PndChannel


DATASET_PATH = Path("/data/cez-pnd-dataset/cez-pnd.sqlite3")
SOURCE_TIMEZONE = "Europe/Prague"
BUSY_TIMEOUT_SECONDS = 5.0
CHANNEL_MAP = {
    PndChannel.CONSUMPTION: "grid_import",
    PndChannel.PRODUCTION: "grid_export",
}


@dataclass(frozen=True)
class DatasetStatus:
    revision: str
    data_timestamp: str | None
    last_attempt: str | None
    last_success: str
    source_status: str
    expected_count: int
    valid_count: int
    missing_count: int
    invalid_count: int

    @property
    def state(self) -> str:
        if self.expected_count == 0:
            return "empty"
        if self.missing_count or self.invalid_count:
            return "partial"
        return "complete"


@dataclass(frozen=True)
class StoredMeasurement:
    channel: str
    interval_start: str
    interval_end: str
    value_kwh: str | None
    quality: str
    source_timezone: str
    source_profile: str
    source_day: str
    collected_at: str
    revision: str


@dataclass(frozen=True)
class MeasurementPage:
    status: DatasetStatus
    expected_count: int
    valid_count: int
    missing_count: int
    invalid_count: int
    rows: tuple[StoredMeasurement, ...]


class NormalizedDatasetStore:
    """One-meter store that publishes both channels in one transaction."""

    def __init__(
        self,
        path: Path = DATASET_PATH,
        *,
        required_uid: int | None = 2000,
        revision_factory=lambda: f"ds_{secrets.token_hex(16)}",
    ) -> None:
        self.path = path
        self._required_uid = required_uid
        self._revision_factory = revision_factory

    def record_attempt(self, attempted_at: datetime) -> None:
        attempted = _utc_text(attempted_at)
        with closing(self._connect()) as connection:
            self._initialize(connection)
            connection.execute(
                "INSERT INTO collector_state(id,last_attempt) VALUES(1,?) "
                "ON CONFLICT(id) DO UPDATE SET last_attempt=excluded.last_attempt",
                (attempted,),
            )
            connection.commit()

    def commit_dataset(
        self,
        consumption: ParsedPndData,
        production: ParsedPndData,
        *,
        collected_at: datetime,
    ) -> DatasetStatus:
        if consumption.channel is not PndChannel.CONSUMPTION:
            raise ValueError("invalid consumption dataset")
        if production.channel is not PndChannel.PRODUCTION:
            raise ValueError("invalid production dataset")
        collected = _utc_text(collected_at)
        revision = self._revision_factory()
        if not isinstance(revision, str) or not revision.startswith("ds_") or not 3 < len(revision) <= 80:
            raise ValueError("invalid dataset revision")
        all_records = (*consumption.intervals, *production.intervals)
        expected = len(all_records)
        valid = sum(record.quality is IntervalQuality.VALID for record in all_records)
        missing = sum(record.quality is IntervalQuality.MISSING for record in all_records)
        invalid = sum(record.quality is IntervalQuality.INVALID for record in all_records)
        if valid + missing + invalid != expected or expected == 0:
            raise ValueError("invalid dataset completeness")
        source_status = "ok" if missing == 0 and invalid == 0 else "partial"
        with closing(self._connect()) as connection:
            self._initialize(connection)
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.execute("UPDATE measurements SET revision=?", (revision,))
                for record in all_records:
                    connection.execute(
                        """
                        INSERT INTO measurements(
                          channel,interval_start,interval_end,value_kwh,quality,
                          source_timezone,source_profile,source_day,collected_at,revision
                        ) VALUES(?,?,?,?,?,?,?,?,?,?)
                        ON CONFLICT(channel,interval_start) DO UPDATE SET
                          interval_end=excluded.interval_end,
                          value_kwh=excluded.value_kwh,
                          quality=excluded.quality,
                          source_timezone=excluded.source_timezone,
                          source_profile=excluded.source_profile,
                          source_day=excluded.source_day,
                          collected_at=excluded.collected_at,
                          revision=excluded.revision
                        """,
                        (
                            CHANNEL_MAP[record.channel],
                            _utc_text(record.interval_start),
                            _utc_text(record.interval_end),
                            _decimal_text(record.value_kwh),
                            record.quality.value,
                            SOURCE_TIMEZONE,
                            record.channel.profile_marker,
                            record.source_day.isoformat(),
                            collected,
                            revision,
                        ),
                    )
                totals = connection.execute(
                    "SELECT COUNT(*),"
                    "SUM(quality='valid'),SUM(quality='missing'),SUM(quality='invalid'),"
                    "MAX(CASE WHEN quality='valid' THEN interval_end END) FROM measurements"
                ).fetchone()
                total_expected, total_valid, total_missing, total_invalid, data_timestamp = totals
                connection.execute(
                    """
                    INSERT INTO dataset_metadata(
                      id,dataset_revision,data_timestamp,last_success,source_status,
                      expected_count,valid_count,missing_count,invalid_count
                    ) VALUES(1,?,?,?,?,?,?,?,?)
                    ON CONFLICT(id) DO UPDATE SET
                      dataset_revision=excluded.dataset_revision,
                      data_timestamp=excluded.data_timestamp,
                      last_success=excluded.last_success,
                      source_status=excluded.source_status,
                      expected_count=excluded.expected_count,
                      valid_count=excluded.valid_count,
                      missing_count=excluded.missing_count,
                      invalid_count=excluded.invalid_count
                    """,
                    (
                        revision,
                        data_timestamp,
                        collected,
                        "ok" if total_missing == 0 and total_invalid == 0 else "partial",
                        total_expected,
                        total_valid,
                        total_missing,
                        total_invalid,
                    ),
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise
        status = self.read_status()
        if status is None:
            raise RuntimeError("dataset commit was not visible")
        return status

    def read_status(self) -> DatasetStatus | None:
        with closing(self._connect()) as connection:
            self._initialize(connection)
            row = connection.execute(
                """
                SELECT m.dataset_revision,m.data_timestamp,s.last_attempt,m.last_success,
                       m.source_status,m.expected_count,m.valid_count,m.missing_count,m.invalid_count
                FROM dataset_metadata m LEFT JOIN collector_state s ON s.id=1 WHERE m.id=1
                """
            ).fetchone()
        return None if row is None else DatasetStatus(*row)

    def read_measurements(
        self,
        start: str,
        end: str,
        *,
        limit: int,
        after: tuple[str, str] | None = None,
    ) -> MeasurementPage | None:
        with closing(self._connect()) as connection:
            self._initialize(connection)
            connection.execute("BEGIN")
            metadata = connection.execute(
                """
                SELECT m.dataset_revision,m.data_timestamp,s.last_attempt,m.last_success,
                       m.source_status,m.expected_count,m.valid_count,m.missing_count,m.invalid_count
                FROM dataset_metadata m LEFT JOIN collector_state s ON s.id=1 WHERE m.id=1
                """
            ).fetchone()
            if metadata is None:
                connection.rollback()
                return None
            counts = connection.execute(
                "SELECT COUNT(*),SUM(quality='valid'),SUM(quality='missing'),SUM(quality='invalid') "
                "FROM measurements WHERE interval_start>=? AND interval_start<?",
                (start, end),
            ).fetchone()
            parameters: list[object] = [start, end]
            after_sql = ""
            if after is not None:
                position = connection.execute(
                    "SELECT 1 FROM measurements WHERE interval_start=? AND channel=? "
                    "AND revision=? AND interval_start>=? AND interval_start<?",
                    (after[0], after[1], metadata[0], start, end),
                ).fetchone()
                if position is None:
                    connection.rollback()
                    raise ValueError("invalid cursor position")
                after_sql = " AND (interval_start>? OR (interval_start=? AND channel>?))"
                parameters.extend((after[0], after[0], after[1]))
            parameters.append(limit + 1)
            rows = connection.execute(
                "SELECT channel,interval_start,interval_end,value_kwh,quality,source_timezone,"
                "source_profile,source_day,collected_at,revision FROM measurements "
                "WHERE interval_start>=? AND interval_start<?" + after_sql +
                " ORDER BY interval_start ASC,channel ASC LIMIT ?",
                parameters,
            ).fetchall()
            connection.commit()
        expected, valid, missing, invalid = (int(value or 0) for value in counts)
        return MeasurementPage(
            DatasetStatus(*metadata),
            expected,
            valid,
            missing,
            invalid,
            tuple(StoredMeasurement(*row) for row in rows),
        )

    def _connect(self) -> sqlite3.Connection:
        self._prepare_file()
        connection = sqlite3.connect(self.path, timeout=BUSY_TIMEOUT_SECONDS)
        connection.execute("PRAGMA busy_timeout=5000")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def _prepare_file(self) -> None:
        if self.path.is_symlink():
            raise OSError("unsafe dataset path")
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        parent_metadata = self.path.parent.stat(follow_symlinks=False)
        if (
            not stat.S_ISDIR(parent_metadata.st_mode)
            or self.path.parent.is_symlink()
            or (os.name == "posix" and parent_metadata.st_mode & stat.S_IWOTH)
        ):
            raise OSError("unsafe dataset directory")
        if (
            self._required_uid is not None
            and hasattr(parent_metadata, "st_uid")
            and parent_metadata.st_uid != self._required_uid
        ):
            raise OSError("unsafe dataset directory owner")
        if not self.path.exists():
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            flags |= getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(self.path, flags, 0o600)
            os.close(descriptor)
        metadata = self.path.stat(follow_symlinks=False)
        if not stat.S_ISREG(metadata.st_mode):
            raise OSError("unsafe dataset path")
        if self._required_uid is not None and hasattr(metadata, "st_uid") and metadata.st_uid != self._required_uid:
            raise OSError("unsafe dataset owner")
        os.chmod(self.path, 0o600)

    @staticmethod
    def _initialize(connection: sqlite3.Connection) -> None:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS collector_state(
              id INTEGER PRIMARY KEY CHECK(id=1), last_attempt TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS dataset_metadata(
              id INTEGER PRIMARY KEY CHECK(id=1),
              dataset_revision TEXT NOT NULL,
              data_timestamp TEXT,
              last_success TEXT NOT NULL,
              source_status TEXT NOT NULL CHECK(source_status IN ('ok','partial','no_data')),
              expected_count INTEGER NOT NULL CHECK(expected_count>=0),
              valid_count INTEGER NOT NULL CHECK(valid_count>=0),
              missing_count INTEGER NOT NULL CHECK(missing_count>=0),
              invalid_count INTEGER NOT NULL CHECK(invalid_count>=0),
              CHECK(valid_count+missing_count+invalid_count=expected_count)
            );
            CREATE TABLE IF NOT EXISTS measurements(
              channel TEXT NOT NULL CHECK(channel IN ('grid_import','grid_export')),
              interval_start TEXT NOT NULL,
              interval_end TEXT NOT NULL,
              value_kwh TEXT,
              quality TEXT NOT NULL CHECK(quality IN ('valid','missing','invalid')),
              source_timezone TEXT NOT NULL CHECK(source_timezone='Europe/Prague'),
              source_profile TEXT NOT NULL CHECK(source_profile IN ('+A','-A')),
              source_day TEXT NOT NULL,
              collected_at TEXT NOT NULL,
              revision TEXT NOT NULL,
              PRIMARY KEY(channel,interval_start),
              CHECK((quality='valid' AND value_kwh IS NOT NULL) OR
                    (quality IN ('missing','invalid') AND value_kwh IS NULL))
            );
            CREATE INDEX IF NOT EXISTS measurements_range
              ON measurements(interval_start,channel);
            """
        )


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("UTC timestamp required")
    utc = value.astimezone(UTC)
    return utc.isoformat(timespec="seconds").replace("+00:00", "Z")


def _decimal_text(value: Decimal | None) -> str | None:
    if value is None:
        return None
    rendered = format(value, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return rendered or "0"
