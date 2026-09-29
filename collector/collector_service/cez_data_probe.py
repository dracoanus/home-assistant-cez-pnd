"""One-shot authenticated CEZ PND metadata and raw CSV probe."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
import json
import os
from pathlib import Path
import sqlite3
import stat
import tempfile
from typing import Callable
import unicodedata
from urllib.parse import urlencode

from .cez_http_auth import (
    AuthResult,
    AuthState,
    AuthStatus,
    CEZ_PND_DASHBOARD_DATA_URL,
    CEZ_PND_START_URL,
    CezHttpAuthClient,
    DashboardMetadataObservation,
    DataProbeCsvParseFailureObservation,
    DataProbeExportObservation,
    DataProbeDatasetCommittedObservation,
    DataProbeMeterLookupUnavailableObservation,
    DataProbeMeterSelectionObservation,
    DataProbeParsedObservation,
    DataProbeShadowComparisonObservation,
    HttpResponse,
    HttpTransport,
    MAX_RESPONSE_BODY_BYTES,
    Resolver,
    SafeHttpAuthEvent,
    _AuthFailure,
    _default_resolver,
    _single_header,
)
from .cez_csv_models import IntervalQuality, ParsedPndData, PndChannel
from .cez_csv_parser import PndCsvParseError, parse_pnd_csv
from .dataset_store import NormalizedDatasetStore
from .runtime_config import DataProbeConfiguration


CEZ_PND_EXPORT_URL = (
    "https://pnd.cezdistribuce.cz/cezpnd2/external/data/export"
)
CEZ_PND_METERS_URL = (
    "https://pnd.cezdistribuce.cz/cezpnd2/api/v1/consumption/meters"
)
PROBE_DIRECTORY = Path("/data/cez-pnd-probe")
METADATA_SUMMARY_NAME = "metadata-summary.json"
CONSUMPTION_NAME = "range-consumption.csv"
PRODUCTION_NAME = "range-production.csv"
CSV_CONTENT_TYPES = frozenset(
    {
        "text/csv",
        "application/csv",
        "application/vnd.ms-excel",
        "application/octet-stream",
        "binary/octet-stream",
        "text/plain",
    }
)
MAX_COLLECTION_RANGE_DAYS = 31
MAX_SHADOW_ID_DEVICE_SET = (1 << 63) - 1


@dataclass(frozen=True)
class _ShadowMetadataRow:
    assembly_id: int | None
    electrometer_id: str | None = field(repr=False)
    id_device_set: int | None = field(repr=False)
    id_device_set_valid: bool = False


@dataclass(frozen=True)
class _Metadata:
    id_device_set: str | None
    meter_collection_present: bool
    usable: bool
    meter_records: tuple[tuple[str | None, str | None], ...]
    shadow_array: bool = False
    shadow_rows: tuple[_ShadowMetadataRow, ...] = field(default=(), repr=False)


@dataclass(frozen=True)
class _VerifiedMeter:
    electrometer_id: str = field(repr=False)
    selection_mode: str

    def __post_init__(self) -> None:
        if self.selection_mode not in {
            "metadata",
            "meter_api",
            "configured_elm_fallback",
        }:
            raise ValueError("invalid meter selection source")


class CezDataProbe:
    """Collect exactly two bounded raw profile exports in one authenticated session."""

    def __init__(
        self,
        configuration: DataProbeConfiguration,
        *,
        output_directory: Path = PROBE_DIRECTORY,
        dataset_store: NormalizedDatasetStore | None = None,
        persist_raw_outputs: bool = True,
        start_day: date | None = None,
        end_day: date | None = None,
        collected_at: datetime | None = None,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
        emit: Callable[[SafeHttpAuthEvent], None] | None = None,
        current_day_shadow: bool = False,
    ) -> None:
        self._configuration = configuration
        self._output_directory = output_directory
        self._dataset_store = dataset_store
        self._persist_raw_outputs = persist_raw_outputs
        self._start_day = start_day or configuration.probe_date
        self._end_day = end_day or (self._start_day + timedelta(days=1))
        if (
            self._start_day >= self._end_day
            or self._end_day - self._start_day
            > timedelta(days=MAX_COLLECTION_RANGE_DAYS)
        ):
            raise ValueError("invalid collection range")
        self._collected_at = collected_at
        self._now = now
        self._emit = emit or (lambda _event: None)
        self._current_day_shadow = current_day_shadow

    def collect(self, client: CezHttpAuthClient) -> None:
        """Run after authentication and before its mandatory session cleanup."""

        deadline = client.new_operation_deadline()
        metadata_response = self._request(
            client,
            CEZ_PND_DASHBOARD_DATA_URL,
            AuthState.DATA_PROBE_METADATA,
            deadline,
            "data_probe_metadata_failed",
            headers={"Accept": "*/*"},
        )
        metadata, observation = self._validate_metadata(metadata_response)
        if metadata.usable:
            self._emit(SafeHttpAuthEvent("dashboard_metadata_verified"))
        verified_meter = self._verified_electrometer_id(client, metadata, deadline)

        interval_from = f"{self._start_day.strftime('%d.%m.%Y')} 00:00"
        interval_to = f"{self._end_day.strftime('%d.%m.%Y')} 00:00"

        consumption = self._export(
            client,
            metadata,
            interval_from,
            interval_to,
            "-1001",
            "consumption",
            deadline,
            "data_probe_consumption_export_failed",
            verified_meter,
        )
        self._emit(SafeHttpAuthEvent("consumption_export_received"))
        production = self._export(
            client,
            metadata,
            interval_from,
            interval_to,
            "-1002",
            "production",
            deadline,
            "data_probe_production_export_failed",
            verified_meter,
        )
        self._emit(SafeHttpAuthEvent("production_export_received"))

        if self._persist_raw_outputs:
            summary_fields = observation.as_dict()
            summary_fields.update(
                {
                    "schema_version": "1",
                    "dashboard_json_object": metadata.usable,
                    "meter_collection_present": metadata.meter_collection_present,
                    "consumption_bytes": len(consumption),
                    "production_bytes": len(production),
                }
            )
            try:
                self._store(
                    _encode_summary(summary_fields), consumption, production
                )
            except (OSError, ValueError) as error:
                raise _AuthFailure("data_probe_storage_failed") from error

        if self._dataset_store is not None:
            parsed_consumption = self._parse(
                consumption, PndChannel.CONSUMPTION,
                "data_probe_consumption_parse_failed",
            )
            parsed_production = self._parse(
                production, PndChannel.PRODUCTION,
                "data_probe_production_parse_failed",
            )
            try:
                status = self._dataset_store.commit_dataset(
                    parsed_consumption,
                    parsed_production,
                    collected_at=self._collected_at or self._now(),
                )
            except (OSError, ValueError, RuntimeError, sqlite3.Error) as error:
                raise _AuthFailure("data_probe_storage_failed") from error
            self._emit(SafeHttpAuthEvent(
                "data_probe_dataset_committed",
                dataset_committed_observation=DataProbeDatasetCommittedObservation(
                    len(parsed_consumption.intervals), parsed_consumption.valid_count,
                    parsed_consumption.missing_count, parsed_consumption.invalid_count,
                    len(parsed_production.intervals), parsed_production.valid_count,
                    parsed_production.missing_count, parsed_production.invalid_count,
                    status.state,
                ),
            ))
            if self._current_day_shadow:
                self._run_shadow_comparison(
                    client,
                    metadata,
                    verified_meter,
                    interval_from,
                    interval_to,
                    "-1001",
                    PndChannel.CONSUMPTION,
                    parsed_consumption,
                    deadline,
                )
                self._run_shadow_comparison(
                    client,
                    metadata,
                    verified_meter,
                    interval_from,
                    interval_to,
                    "-1002",
                    PndChannel.PRODUCTION,
                    parsed_production,
                    deadline,
                )
        self._emit(SafeHttpAuthEvent("data_probe_complete"))

    def _parse(
        self, content: bytes, channel: PndChannel, failure_code: str
    ) -> ParsedPndData:
        try:
            parsed = parse_pnd_csv(
                content,
                channel=channel,
                source_timezone="Europe/Prague",
            )
        except PndCsvParseError as error:
            self._emit(SafeHttpAuthEvent(
                "data_probe_csv_parse_failed",
                csv_parse_failure_observation=DataProbeCsvParseFailureObservation(
                    channel.value, error.code
                ),
            ))
            raise _AuthFailure(failure_code) from error
        first_valid, last_valid = _valid_interval_bounds(parsed)
        self._emit(SafeHttpAuthEvent(
            f"data_probe_{channel.value}_parsed",
            parsed_observation=DataProbeParsedObservation(
                channel.value, len(parsed.intervals), parsed.valid_count,
                parsed.missing_count, parsed.invalid_count, parsed.complete,
                first_valid,
                last_valid,
            ),
        ))
        return parsed

    def _run_shadow_comparison(
        self,
        client: CezHttpAuthClient,
        metadata: _Metadata,
        verified_meter: _VerifiedMeter,
        interval_from: str,
        interval_to: str,
        assembly_id: str,
        channel: PndChannel,
        normal: ParsedPndData,
        deadline: float,
    ) -> None:
        selection_result, id_device_set = _select_shadow_id_device_set(
            metadata, verified_meter, assembly_id
        )
        if id_device_set is None:
            self._emit_shadow_observation(
                channel, normal, False, selection_result
            )
            return
        parameters = [
            ("format", "csv"),
            ("idAssembly", assembly_id),
            ("idDeviceSet", str(id_device_set)),
            ("intervalFrom", interval_from),
            ("intervalTo", interval_to),
            ("electrometerId", verified_meter.electrometer_id),
        ]
        try:
            response = client.request_data_probe(
                f"{CEZ_PND_EXPORT_URL}?{urlencode(parameters)}",
                AuthState.DATA_PROBE_EXPORT,
                deadline,
                extra_headers={"Accept": "*/*", "Referer": CEZ_PND_START_URL},
            )
            observation = _export_observation(
                channel.value,
                response,
                start_day=self._start_day,
                end_day=self._end_day,
                id_assembly=assembly_id,
                id_device_set_present=True,
                selection_mode=verified_meter.selection_mode,
            )
            if (
                response.status != 200
                or not response.body
                or len(response.body) > MAX_RESPONSE_BODY_BYTES
                or observation.looks_like_html
                or observation.looks_like_login
                or observation.content_type_base not in CSV_CONTENT_TYPES
            ):
                raise _AuthFailure("data_probe_shadow_request_failed")
        except Exception:
            self._emit_shadow_observation(
                channel, normal, True, "shadow_request_failed"
            )
            return
        try:
            shadow = parse_pnd_csv(
                response.body,
                channel=channel,
                source_timezone="Europe/Prague",
            )
        except Exception:
            self._emit_shadow_observation(
                channel, normal, True, "shadow_parse_failed"
            )
            return
        self._emit_shadow_observation(
            channel, normal, True, "matched", shadow
        )

    def _emit_shadow_observation(
        self,
        channel: PndChannel,
        normal: ParsedPndData,
        shadow_executed: bool,
        selection_result: str,
        shadow: ParsedPndData | None = None,
    ) -> None:
        normal_first, normal_last = _valid_interval_bounds(normal)
        shadow_first, shadow_last = (
            _valid_interval_bounds(shadow) if shadow is not None else (None, None)
        )
        same_result = None
        shadow_has_newer_data = None
        if shadow is not None:
            same_result = (
                normal.valid_count,
                normal.missing_count,
                normal.invalid_count,
                normal_first,
                normal_last,
            ) == (
                shadow.valid_count,
                shadow.missing_count,
                shadow.invalid_count,
                shadow_first,
                shadow_last,
            )
            shadow_has_newer_data = shadow_last is not None and (
                normal_last is None or shadow_last > normal_last
            )
        self._emit(
            SafeHttpAuthEvent(
                "data_probe_shadow_comparison",
                shadow_comparison_observation=DataProbeShadowComparisonObservation(
                    channel=channel.value,
                    shadow_executed=shadow_executed,
                    selection_result=selection_result,
                    normal_valid_count=normal.valid_count,
                    normal_missing_count=normal.missing_count,
                    normal_invalid_count=normal.invalid_count,
                    normal_first_valid_interval_end=normal_first,
                    normal_last_valid_interval_end=normal_last,
                    shadow_valid_count=(shadow.valid_count if shadow else None),
                    shadow_missing_count=(shadow.missing_count if shadow else None),
                    shadow_invalid_count=(shadow.invalid_count if shadow else None),
                    shadow_first_valid_interval_end=shadow_first,
                    shadow_last_valid_interval_end=shadow_last,
                    same_result=same_result,
                    shadow_has_newer_data=shadow_has_newer_data,
                ),
            )
        )

    def _request(
        self,
        client: CezHttpAuthClient,
        url: str,
        state: AuthState,
        deadline: float,
        failure_code: str,
        *,
        headers: dict[str, str],
    ) -> HttpResponse:
        try:
            return client.request_data_probe(
                url, state, deadline, extra_headers=headers
            )
        except _AuthFailure as error:
            raise _AuthFailure(failure_code) from error

    def _validate_metadata(
        self, response: HttpResponse
    ) -> tuple[_Metadata, DashboardMetadataObservation]:
        if response.status != 200:
            raise _AuthFailure("data_probe_metadata_failed")

        content_type = _safe_observed_content_type(response)
        text: str | None
        payload: object | None
        try:
            text = response.body.decode("utf-8", errors="strict")
        except UnicodeError:
            text = None
        if text is None:
            payload = None
            json_parseable = False
            root_type = "unknown"
        else:
            try:
                payload = json.loads(text)
            except (json.JSONDecodeError, RecursionError):
                payload = None
                json_parseable = False
                root_type = "unknown"
            else:
                json_parseable = True
                root_type = _json_type(payload)

        observation = _metadata_observation(
            response,
            content_type,
            payload,
            json_parseable=json_parseable,
            root_type=root_type,
        )
        self._emit(
            SafeHttpAuthEvent(
                "dashboard_metadata_response_observed",
                metadata_observation=observation,
            )
        )
        if self._persist_raw_outputs:
            try:
                self._store_metadata_summary(observation)
            except (OSError, ValueError) as error:
                raise _AuthFailure("data_probe_storage_failed") from error

        if content_type != "application/json":
            raise _AuthFailure("data_probe_metadata_content_type_invalid")
        if text is None:
            raise _AuthFailure("data_probe_metadata_utf8_invalid")
        if not json_parseable:
            raise _AuthFailure("data_probe_metadata_json_invalid")
        if not isinstance(payload, dict):
            self._emit(
                SafeHttpAuthEvent(
                    "dashboard_metadata_unusable", json_root_type=root_type
                )
            )
            return _Metadata(
                None,
                False,
                False,
                (),
                shadow_array=isinstance(payload, list),
                shadow_rows=_shadow_metadata_rows(payload),
            ), observation

        raw_id = payload.get("idDeviceSet")
        id_device_set = None
        if raw_id not in (None, ""):
            if isinstance(raw_id, bool) or not isinstance(raw_id, (str, int)):
                raise _AuthFailure("data_probe_metadata_id_device_set_invalid")
            id_device_set = str(raw_id)
            if len(id_device_set.encode("utf-8")) > 128 or any(
                ord(character) < 32 for character in id_device_set
            ):
                raise _AuthFailure("data_probe_metadata_id_device_set_invalid")

        collections: list[list[object]] = []
        for key in ("meters", "devices", "electrometers"):
            if key not in payload:
                continue
            value = payload[key]
            if not isinstance(value, list):
                raise _AuthFailure("data_probe_metadata_meter_collection_invalid")
            collections.append(value)
        meter_collection_present = bool(collections)
        records = _meter_records(
            [item for collection in collections for item in collection]
        )
        return _Metadata(
            id_device_set,
            meter_collection_present,
            True,
            records,
        ), observation

    def _verified_electrometer_id(
        self, client: CezHttpAuthClient, metadata: _Metadata, deadline: float
    ) -> _VerifiedMeter:
        if (
            self._configuration.ean is None
            and self._configuration.electrometer_id is None
        ):
            raise _AuthFailure("data_probe_meter_identity_required")

        selected, _, _, _, error = _select_meter(
            self._configuration, list(metadata.meter_records)
        )
        if selected is not None:
            return _VerifiedMeter(selected, "metadata")

        try:
            response = client.request_data_probe(
                CEZ_PND_METERS_URL,
                AuthState.DATA_PROBE_METERS,
                deadline,
                extra_headers={"Accept": "*/*"},
            )
        except _AuthFailure as error:
            return self._meter_lookup_unavailable(
                "request_failed", failure_code=error.code
            )
        if response.status != 200:
            return self._meter_lookup_unavailable("status", response.status)
        try:
            content_type = _content_type(response)
        except _AuthFailure:
            return self._meter_lookup_unavailable("content_type", response.status)
        if content_type != "application/json":
            return self._meter_lookup_unavailable("content_type", response.status)
        try:
            text = response.body.decode("utf-8", errors="strict")
        except UnicodeError:
            return self._meter_lookup_unavailable("utf8", response.status)
        try:
            payload = json.loads(text)
        except (json.JSONDecodeError, RecursionError):
            return self._meter_lookup_unavailable("json", response.status)
        root_type = _json_type(payload)
        if not isinstance(payload, list):
            return self._meter_lookup_unavailable("root_type", response.status)
        records = _meter_records(payload)
        if not payload or not records:
            return self._meter_lookup_unavailable("empty", response.status)
        selected, ean_matches, elm_matches, mode, error_code = _select_meter(
            self._configuration, list(records)
        )
        self._emit_meter_selection(
            response.status,
            root_type,
            len(payload),
            ean_matches,
            elm_matches,
            mode,
        )
        if error_code is not None:
            raise _AuthFailure(error_code)
        if selected is None:
            raise _AuthFailure("data_probe_meter_not_found")
        return _VerifiedMeter(selected, "meter_api")

    def _meter_lookup_unavailable(
        self,
        reason: str,
        status: int | None = None,
        failure_code: str | None = None,
    ) -> _VerifiedMeter:
        self._emit(
            SafeHttpAuthEvent(
                "data_probe_meter_lookup_unavailable",
                meter_lookup_unavailable_observation=(
                    DataProbeMeterLookupUnavailableObservation(
                        reason, status, failure_code
                    )
                ),
            )
        )
        configured_elm = self._configuration.electrometer_id
        if configured_elm is None:
            raise _AuthFailure("data_probe_meter_lookup_failed")
        return _VerifiedMeter(configured_elm, "configured_elm_fallback")

    def _emit_meter_selection(
        self,
        status: int,
        root_type: str,
        meter_count: int,
        ean_matches: int,
        elm_matches: int,
        mode: str,
    ) -> None:
        self._emit(
            SafeHttpAuthEvent(
                "data_probe_meter_selection_observed",
                meter_selection_observation=DataProbeMeterSelectionObservation(
                    meter_response_status=status,
                    json_root_type=root_type,
                    meter_count=meter_count,
                    matches_by_ean=ean_matches,
                    matches_by_elm=elm_matches,
                    selection_mode=mode,
                ),
            )
        )

    def _export(
        self,
        client: CezHttpAuthClient,
        metadata: _Metadata,
        interval_from: str,
        interval_to: str,
        assembly_id: str,
        channel: str,
        deadline: float,
        failure_code: str,
        verified_meter: _VerifiedMeter,
    ) -> bytes:
        parameters = [
            ("format", "csv"),
            ("idAssembly", assembly_id),
        ]
        if metadata.id_device_set is not None:
            parameters.append(("idDeviceSet", metadata.id_device_set))
        parameters.extend(
            (("intervalFrom", interval_from), ("intervalTo", interval_to))
        )
        parameters.append(("electrometerId", verified_meter.electrometer_id))
        url = f"{CEZ_PND_EXPORT_URL}?{urlencode(parameters)}"
        response = self._request(
            client,
            url,
            AuthState.DATA_PROBE_EXPORT,
            deadline,
            failure_code,
            headers={"Accept": "*/*", "Referer": CEZ_PND_START_URL},
        )
        observation = _export_observation(
            channel,
            response,
            start_day=self._start_day,
            end_day=self._end_day,
            id_assembly=assembly_id,
            id_device_set_present=metadata.id_device_set is not None,
            selection_mode=verified_meter.selection_mode,
        )
        self._emit(
            SafeHttpAuthEvent(
                "data_probe_export_response_observed",
                export_observation=observation,
            )
        )
        prefix = f"data_probe_{channel}_export"
        if response.status != 200:
            raise _AuthFailure(f"{prefix}_status_failed")
        if not response.body:
            raise _AuthFailure(f"{prefix}_empty")
        if len(response.body) > MAX_RESPONSE_BODY_BYTES:
            raise _AuthFailure(f"{prefix}_too_large")
        if observation.looks_like_html or observation.looks_like_login:
            raise _AuthFailure(f"{prefix}_html_rejected")
        if observation.content_type_base not in CSV_CONTENT_TYPES:
            raise _AuthFailure(f"{prefix}_content_type_invalid")
        return response.body

    def _store(self, summary: bytes, consumption: bytes, production: bytes) -> None:
        directory = self._prepare_output_directory()
        for name, content in (
            (METADATA_SUMMARY_NAME, summary),
            (CONSUMPTION_NAME, consumption),
            (PRODUCTION_NAME, production),
        ):
            _atomic_write(directory / name, content)

    def _store_metadata_summary(
        self, observation: DashboardMetadataObservation
    ) -> None:
        directory = self._prepare_output_directory()
        fields = {"schema_version": "1", **observation.as_dict()}
        _atomic_write(
            directory / METADATA_SUMMARY_NAME,
            _encode_summary(fields),
        )

    def _prepare_output_directory(self) -> Path:
        directory = self._output_directory
        if directory.is_symlink():
            raise OSError("unsafe probe directory")
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not directory.is_dir() or directory.is_symlink():
            raise OSError("unsafe probe directory")
        os.chmod(directory, 0o700)
        return directory


def run_data_probe(
    configuration: DataProbeConfiguration,
    transport: HttpTransport,
    *,
    resolver: Resolver = _default_resolver,
    output_directory: Path = PROBE_DIRECTORY,
    dataset_store: NormalizedDatasetStore | None = None,
    persist_raw_outputs: bool = True,
    start_day: date | None = None,
    end_day: date | None = None,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
    emit: Callable[[SafeHttpAuthEvent], None] | None = None,
    current_day_shadow: bool = False,
) -> AuthResult:
    """Authenticate and probe through the same transport/session, then clean up."""

    safe_emit = emit or (lambda _event: None)
    safe_emit(SafeHttpAuthEvent("data_probe_started"))
    attempt_at = now()
    store = dataset_store or NormalizedDatasetStore()
    try:
        store.record_attempt(attempt_at)
    except (OSError, ValueError, RuntimeError, sqlite3.Error):
        return AuthResult(AuthStatus.FAILED, "data_probe_storage_failed")
    probe = CezDataProbe(
        configuration, output_directory=output_directory, dataset_store=store,
        persist_raw_outputs=persist_raw_outputs, start_day=start_day,
        end_day=end_day, now=now, emit=safe_emit,
        current_day_shadow=current_day_shadow,
    )
    result = CezHttpAuthClient(
        configuration,
        transport,
        resolver=resolver,
        emit=safe_emit,
    ).authenticate(on_authenticated=probe.collect)
    if result.status is AuthStatus.FAILED and not result.code.startswith("data_probe_"):
        return AuthResult(AuthStatus.FAILED, "data_probe_auth_failed")
    return result


def _content_type(response: HttpResponse) -> str | None:
    value = _single_header(response.headers, "content-type")
    return None if value is None else value.split(";", 1)[0].strip().lower()


def _safe_observed_content_type(response: HttpResponse) -> str:
    try:
        value = _content_type(response)
    except _AuthFailure:
        return "unknown"
    if value is None or len(value) > 127:
        return "unknown"
    allowed = "abcdefghijklmnopqrstuvwxyz0123456789!#$&^_.+-/"
    if value.count("/") != 1 or any(character not in allowed for character in value):
        return "unknown"
    return value


def _json_type(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, list):
        return "array"
    if isinstance(value, str):
        return "string"
    if isinstance(value, (int, float)):
        return "number"
    return "unknown"


def _meter_records(
    entries: list[object],
) -> tuple[tuple[str | None, str | None], ...]:
    """Extract only validated EAN/ELM pairs without retaining other meter data."""

    records: list[tuple[str | None, str | None]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        ean_value = entry.get("ean")
        elm_value = entry.get("elm")
        ean = ean_value if _is_valid_ean(ean_value) else None
        elm = elm_value if _is_valid_elm(elm_value) else None
        if ean is not None or elm is not None:
            records.append((ean, elm))
    return tuple(records)


def _select_meter(
    configuration: DataProbeConfiguration,
    records: list[tuple[str | None, str | None]],
) -> tuple[str | None, int, int, str, str | None]:
    configured_ean = configuration.ean
    configured_elm = configuration.electrometer_id
    ean_matches = sum(1 for ean, _ in records if configured_ean is not None and ean == configured_ean)
    elm_matches = sum(1 for _, elm in records if configured_elm is not None and elm == configured_elm)

    if configured_ean is not None and configured_elm is not None:
        exact = [
            elm
            for ean, elm in records
            if ean == configured_ean and elm == configured_elm
        ]
        if len(exact) == 1:
            return exact[0], ean_matches, elm_matches, "both", None
        if len(exact) > 1:
            return None, ean_matches, elm_matches, "ambiguous", "data_probe_meter_selection_ambiguous"
        if ean_matches and elm_matches:
            return None, ean_matches, elm_matches, "mismatch", "data_probe_meter_identity_mismatch"
        return None, ean_matches, elm_matches, "none", "data_probe_meter_not_found"

    if configured_ean is not None:
        exact = [elm for ean, elm in records if ean == configured_ean and elm is not None]
        if len(exact) == 1 and ean_matches == 1:
            return exact[0], ean_matches, 0, "ean_only", None
        if ean_matches > 1:
            return None, ean_matches, 0, "ambiguous", "data_probe_meter_selection_ambiguous"
        return None, ean_matches, 0, "none", "data_probe_meter_not_found"

    if configured_elm is not None:
        if elm_matches == 1:
            return configured_elm, 0, elm_matches, "elm_only", None
        if elm_matches > 1:
            return None, 0, elm_matches, "ambiguous", "data_probe_meter_selection_ambiguous"
        return None, 0, elm_matches, "none", "data_probe_meter_not_found"

    return None, 0, 0, "none", "data_probe_meter_identity_required"


def _is_valid_ean(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 18
        and value.isascii()
        and value.isdigit()
    )


def _is_valid_elm(value: object) -> bool:
    if not isinstance(value, str) or not value or value != value.strip():
        return False
    try:
        encoded = value.encode("utf-8")
    except UnicodeError:
        return False
    return len(encoded) <= 128 and not any(
        unicodedata.category(character).startswith("C") for character in value
    )


def _shadow_metadata_rows(payload: object) -> tuple[_ShadowMetadataRow, ...]:
    if not isinstance(payload, list) or len(payload) > MAX_RESPONSE_BODY_BYTES:
        return ()
    rows: list[_ShadowMetadataRow] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        raw_assembly = item.get("idAssembly")
        assembly_id = None
        if type(raw_assembly) is int and raw_assembly in {-1001, -1002}:
            assembly_id = raw_assembly
        elif isinstance(raw_assembly, str) and raw_assembly in {"-1001", "-1002"}:
            assembly_id = int(raw_assembly)
        raw_electrometer = item.get("electrometerId")
        electrometer_id = raw_electrometer if _is_valid_elm(raw_electrometer) else None
        raw_id_device_set = item.get("idDeviceSet")
        id_device_set_valid = (
            type(raw_id_device_set) is int
            and 1 <= raw_id_device_set <= MAX_SHADOW_ID_DEVICE_SET
        )
        rows.append(
            _ShadowMetadataRow(
                assembly_id=assembly_id,
                electrometer_id=electrometer_id,
                id_device_set=(raw_id_device_set if id_device_set_valid else None),
                id_device_set_valid=id_device_set_valid,
            )
        )
    return tuple(rows)


def _select_shadow_id_device_set(
    metadata: _Metadata,
    verified_meter: _VerifiedMeter,
    assembly_id: str,
) -> tuple[str, int | None]:
    if not metadata.shadow_array:
        return "metadata_not_array", None
    if verified_meter.selection_mode != "configured_elm_fallback":
        return "normal_selection_not_configured_fallback", None
    expected_assembly = int(assembly_id)
    matching = [
        row
        for row in metadata.shadow_rows
        if row.assembly_id == expected_assembly
        and row.electrometer_id == verified_meter.electrometer_id
    ]
    if not matching:
        return "no_matching_row", None
    if len(matching) != 1:
        return "ambiguous_matching_rows", None
    selected = matching[0]
    if not selected.id_device_set_valid or selected.id_device_set is None:
        return "invalid_id_device_set", None
    return "matched", selected.id_device_set


def _valid_interval_bounds(
    parsed: ParsedPndData,
) -> tuple[str | None, str | None]:
    valid_ends = [
        interval.interval_end
        for interval in parsed.intervals
        if interval.quality is IntervalQuality.VALID
    ]
    if not valid_ends:
        return None, None
    return _utc_timestamp(min(valid_ends)), _utc_timestamp(max(valid_ends))


def _metadata_observation(
    response: HttpResponse,
    content_type: str,
    payload: object | None,
    *,
    json_parseable: bool,
    root_type: str,
) -> DashboardMetadataObservation:
    keys: tuple[str, ...] = ()
    key_count: int | None = None
    collection_types: tuple[tuple[str, str], ...] = ()
    id_present = False
    id_type: str | None = None
    array_length: int | None = None
    array_object_count: int | None = None
    array_keys: set[str] = set()
    collection_present = {
        "meters": False,
        "devices": False,
        "electrometers": False,
    }
    collection_counts = {name: 0 for name in collection_present}
    collection_counts_valid = {name: True for name in collection_present}
    id_types: set[str] = set()

    def inspect_mapping(item: dict[object, object], *, collect_keys: bool) -> None:
        nonlocal id_present
        if collect_keys:
            for raw_key in item:
                key = raw_key if _safe_top_level_key(raw_key) else "[redacted-key]"
                if len(array_keys) < 50 or key in array_keys:
                    array_keys.add(key)
        if "idDeviceSet" in item:
            id_present = True
            id_types.add(_json_type(item["idDeviceSet"]))
        for name in collection_present:
            if name not in item:
                continue
            collection_present[name] = True
            value = item[name]
            if isinstance(value, list):
                collection_counts[name] += len(value)
            else:
                collection_counts_valid[name] = False

    if isinstance(payload, dict):
        key_count = len(payload)
        keys = tuple(
            sorted(
                {
                    key if _safe_top_level_key(key) else "[redacted-key]"
                    for key in list(payload)[:50]
                }
            )
        )
        collection_types = tuple(
            sorted(
                (key, _json_type(payload[key]))
                for key in ("meters", "devices", "electrometers")
                if key in payload
            )
        )
        inspect_mapping(payload, collect_keys=False)
    elif isinstance(payload, list):
        array_length = len(payload)
        objects = [item for item in payload if isinstance(item, dict)]
        array_object_count = len(objects)
        for item in objects:
            inspect_mapping(item, collect_keys=True)
    if len(id_types) == 1:
        id_type = next(iter(id_types))
    return DashboardMetadataObservation(
        status=response.status,
        body_bytes=len(response.body),
        content_type_base=content_type,
        json_parseable=json_parseable,
        json_root_type=root_type,
        top_level_key_count=key_count,
        top_level_keys=keys,
        collection_types=collection_types,
        id_device_set_present=id_present,
        id_device_set_type=id_type,
        array_length=array_length,
        array_object_count=array_object_count,
        array_object_keys=tuple(sorted(array_keys)),
        array_meter_collection_present=collection_present["meters"],
        array_meter_collection_count=(
            collection_counts["meters"]
            if collection_present["meters"] and collection_counts_valid["meters"]
            else None
        ),
        array_device_collection_present=collection_present["devices"],
        array_device_collection_count=(
            collection_counts["devices"]
            if collection_present["devices"] and collection_counts_valid["devices"]
            else None
        ),
        array_electrometer_collection_present=collection_present["electrometers"],
        array_electrometer_collection_count=(
            collection_counts["electrometers"]
            if collection_present["electrometers"]
            and collection_counts_valid["electrometers"]
            else None
        ),
    )


def _safe_top_level_key(key: object) -> bool:
    if not isinstance(key, str) or not 1 <= len(key) <= 64:
        return False
    return all(
        character.isascii()
        and (character.isalnum() or character in "_.-")
        for character in key
    )


def _encode_summary(fields: dict[str, object]) -> bytes:
    return json.dumps(
        fields,
        ensure_ascii=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _looks_like_html(body: bytes) -> bool:
    sample = body[:8192].lstrip().lower()
    return any(marker in sample for marker in (b"<!doctype html", b"<html"))


def _looks_like_login(body: bytes) -> bool:
    sample = body[:8192].lstrip().lower()
    return any(
        marker in sample
        for marker in (b"<form", b"type=\"password\"", b"type='password'", b"g-recaptcha")
    )


def _looks_like_json(body: bytes) -> bool:
    try:
        json.loads(body.decode("utf-8", errors="strict"))
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        return False
    return True


def _header_present(response: HttpResponse, name: str) -> bool:
    expected = name.lower()
    return any(header_name.lower() == expected for header_name, _ in response.headers)


def _export_observation(
    channel: str,
    response: HttpResponse,
    *,
    start_day: date,
    end_day: date,
    id_assembly: str,
    id_device_set_present: bool,
    selection_mode: str,
) -> DataProbeExportObservation:
    body_bytes = len(response.body)
    return DataProbeExportObservation(
        channel=channel,
        status=response.status,
        body_bytes=body_bytes,
        content_type_base=_safe_observed_content_type(response),
        body_empty=body_bytes == 0,
        body_limit_exceeded=body_bytes > MAX_RESPONSE_BODY_BYTES,
        looks_like_html=_looks_like_html(response.body),
        looks_like_login=_looks_like_login(response.body),
        looks_like_json=_looks_like_json(response.body),
        content_disposition_present=_header_present(
            response, "content-disposition"
        ),
        content_encoding_present=_header_present(response, "content-encoding"),
        start_day=start_day.isoformat(),
        end_day=end_day.isoformat(),
        id_assembly=id_assembly,
        id_device_set_present=id_device_set_present,
        electrometer_id_present=True,
        selection_mode=selection_mode,
    )


def _utc_timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("UTC timestamp required")
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _atomic_write(path: Path, content: bytes) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary_path = Path(temporary_name)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
        else:
            os.chmod(temporary_path, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = -1
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, path)
        os.chmod(path, 0o600)
        if not stat.S_ISREG(path.stat(follow_symlinks=False).st_mode):
            raise OSError("probe output is not a regular file")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass
