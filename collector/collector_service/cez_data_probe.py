"""One-shot authenticated CEZ PND metadata and raw CSV probe."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
import json
import os
from pathlib import Path
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
    DataProbeExportObservation,
    DataProbeMeterLookupUnavailableObservation,
    DataProbeMeterSelectionObservation,
    HttpResponse,
    HttpTransport,
    MAX_RESPONSE_BODY_BYTES,
    Resolver,
    SafeHttpAuthEvent,
    _AuthFailure,
    _default_resolver,
    _single_header,
)
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


@dataclass(frozen=True)
class _Metadata:
    id_device_set: str | None
    meter_collection_present: bool
    usable: bool
    meter_records: tuple[tuple[str | None, str | None], ...]


class CezDataProbe:
    """Collect exactly two bounded raw profile exports in one authenticated session."""

    def __init__(
        self,
        configuration: DataProbeConfiguration,
        *,
        output_directory: Path = PROBE_DIRECTORY,
        emit: Callable[[SafeHttpAuthEvent], None] | None = None,
    ) -> None:
        self._configuration = configuration
        self._output_directory = output_directory
        self._emit = emit or (lambda _event: None)

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
        verified_elm = self._verified_electrometer_id(client, metadata, deadline)

        day = self._configuration.probe_date
        interval_from = f"{day.strftime('%d.%m.%Y')} 00:00"
        interval_to = (
            f"{(day + timedelta(days=1)).strftime('%d.%m.%Y')} 00:00"
        )

        consumption = self._export(
            client,
            metadata,
            interval_from,
            interval_to,
            "-1001",
            "consumption",
            deadline,
            "data_probe_consumption_export_failed",
            verified_elm,
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
            verified_elm,
        )
        self._emit(SafeHttpAuthEvent("production_export_received"))

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
        summary = _encode_summary(summary_fields)
        try:
            self._store(summary, consumption, production)
        except (OSError, ValueError) as error:
            raise _AuthFailure("data_probe_storage_failed") from error
        self._emit(SafeHttpAuthEvent("data_probe_complete"))

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
            return _Metadata(None, False, False, ()), observation

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
    ) -> str:
        if (
            self._configuration.ean is None
            and self._configuration.electrometer_id is None
        ):
            raise _AuthFailure("data_probe_meter_identity_required")

        selected, _, _, _, error = _select_meter(
            self._configuration, list(metadata.meter_records)
        )
        if selected is not None:
            return selected

        try:
            response = client.request_data_probe(
                CEZ_PND_METERS_URL,
                AuthState.DATA_PROBE_METERS,
                deadline,
                extra_headers={"Accept": "*/*"},
            )
        except _AuthFailure:
            return self._meter_lookup_unavailable("request_failed")
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
        return selected

    def _meter_lookup_unavailable(
        self, reason: str, status: int | None = None
    ) -> str:
        self._emit(
            SafeHttpAuthEvent(
                "data_probe_meter_lookup_unavailable",
                meter_lookup_unavailable_observation=(
                    DataProbeMeterLookupUnavailableObservation(reason, status)
                ),
            )
        )
        configured_elm = self._configuration.electrometer_id
        if configured_elm is None:
            raise _AuthFailure("data_probe_meter_lookup_failed")
        return configured_elm

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
        verified_elm: str,
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
        parameters.append(("electrometerId", verified_elm))
        url = f"{CEZ_PND_EXPORT_URL}?{urlencode(parameters)}"
        response = self._request(
            client,
            url,
            AuthState.DATA_PROBE_EXPORT,
            deadline,
            failure_code,
            headers={"Accept": "*/*", "Referer": CEZ_PND_START_URL},
        )
        observation = _export_observation(channel, response)
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
    emit: Callable[[SafeHttpAuthEvent], None] | None = None,
) -> AuthResult:
    """Authenticate and probe through the same transport/session, then clean up."""

    safe_emit = emit or (lambda _event: None)
    safe_emit(SafeHttpAuthEvent("data_probe_started"))
    probe = CezDataProbe(
        configuration, output_directory=output_directory, emit=safe_emit
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
        id_present = "idDeviceSet" in payload
        if id_present:
            id_type = _json_type(payload["idDeviceSet"])
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
    channel: str, response: HttpResponse
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
    )


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
