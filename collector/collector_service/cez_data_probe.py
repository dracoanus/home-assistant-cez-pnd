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
from urllib.parse import urlencode

from .cez_http_auth import (
    AuthResult,
    AuthState,
    AuthStatus,
    CEZ_PND_DASHBOARD_DATA_URL,
    CEZ_PND_START_URL,
    CezHttpAuthClient,
    DashboardMetadataObservation,
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
        self._emit(SafeHttpAuthEvent("dashboard_metadata_verified"))

        day = self._configuration.probe_date
        interval_from = f"{day.strftime('%d.%m.%Y')} 00:00"
        interval_to = (
            f"{(day + timedelta(days=1)).strftime('%d.%m.%Y')} 00:00"
        )

        consumption = self._export(
            client, metadata, interval_from, interval_to, "-1001", deadline,
            "data_probe_consumption_export_failed",
        )
        self._emit(SafeHttpAuthEvent("consumption_export_received"))
        production = self._export(
            client, metadata, interval_from, interval_to, "-1002", deadline,
            "data_probe_production_export_failed",
        )
        self._emit(SafeHttpAuthEvent("production_export_received"))

        summary_fields = observation.as_dict()
        summary_fields.update(
            {
                "schema_version": "1",
                "dashboard_json_object": True,
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
            raise _AuthFailure("data_probe_metadata_root_invalid")

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
        configured_elm = self._configuration.electrometer_id
        if configured_elm is not None:
            values = {
                str(item.get(key))
                for collection in collections
                for item in collection
                if isinstance(item, dict)
                for key in ("elm", "electrometerId", "id")
                if item.get(key) not in (None, "")
            }
            if configured_elm not in values:
                raise _AuthFailure("data_probe_metadata_configured_elm_not_found")
        return _Metadata(id_device_set, meter_collection_present), observation

    def _export(
        self,
        client: CezHttpAuthClient,
        metadata: _Metadata,
        interval_from: str,
        interval_to: str,
        assembly_id: str,
        deadline: float,
        failure_code: str,
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
        if self._configuration.electrometer_id is not None:
            parameters.append(
                ("electrometerId", self._configuration.electrometer_id)
            )
        url = f"{CEZ_PND_EXPORT_URL}?{urlencode(parameters)}"
        response = self._request(
            client,
            url,
            AuthState.DATA_PROBE_EXPORT,
            deadline,
            failure_code,
            headers={"Accept": "*/*", "Referer": CEZ_PND_START_URL},
        )
        if (
            response.status != 200
            or not response.body
            or len(response.body) > MAX_RESPONSE_BODY_BYTES
            or _content_type(response) not in CSV_CONTENT_TYPES
            or _looks_like_html_or_login(response.body)
        ):
            raise _AuthFailure(failure_code)
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


def _looks_like_html_or_login(body: bytes) -> bool:
    sample = body[:8192].lstrip().lower()
    return any(
        marker in sample
        for marker in (
            b"<!doctype html",
            b"<html",
            b"<form",
            b"type=\"password\"",
            b"type='password'",
            b"g-recaptcha",
        )
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
