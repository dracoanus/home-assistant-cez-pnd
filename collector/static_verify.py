"""Static fail-closed checks for the Collector service skeleton."""

from __future__ import annotations

import ast
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parent
REPOSITORY_ROOT = ROOT.parent
DOCKERFILE = (ROOT / "Dockerfile").read_text(encoding="utf-8")
SOURCE_FILES = sorted((ROOT / "collector_service").glob("*.py"))
SOURCE = "\n".join(path.read_text(encoding="utf-8") for path in SOURCE_FILES)
HTTP_AUTH_SOURCE = (ROOT / "collector_service" / "cez_http_auth.py").read_text(
    encoding="utf-8"
)
STRICT_TRANSPORT_SOURCE = (
    ROOT / "collector_service" / "strict_http_transport.py"
).read_text(encoding="utf-8")
REQUESTS_PREAUTH_SOURCE = (
    ROOT / "collector_service" / "requests_preauth.py"
).read_text(encoding="utf-8")
DATA_PROBE_SOURCE = (ROOT / "collector_service" / "cez_data_probe.py").read_text(
    encoding="utf-8"
)
CSV_PARSER_SOURCE = (ROOT / "collector_service" / "cez_csv_parser.py").read_text(
    encoding="utf-8"
)
CSV_MODELS_SOURCE = (ROOT / "collector_service" / "cez_csv_models.py").read_text(
    encoding="utf-8"
)
API_SOURCE = (ROOT / "collector_service" / "api.py").read_text(encoding="utf-8")
DATASET_STORE_SOURCE = (ROOT / "collector_service" / "dataset_store.py").read_text(encoding="utf-8")
THIRD_PARTY_NOTICES = (REPOSITORY_ROOT / "THIRD_PARTY_NOTICES.md").read_text(
    encoding="utf-8"
)
ENTRYPOINT_SOURCE = (ROOT / "collector_entrypoint.py").read_text(encoding="utf-8")
REQUESTS_COMPATIBILITY_REQUIREMENTS = (
    ROOT / "requirements-requests-compatibility.txt"
).read_text(encoding="utf-8")
STRUCTURED_LOGGING_SOURCE = (
    ROOT / "collector_service" / "structured_logging.py"
).read_text(encoding="utf-8")
SYNC_WORKER_SOURCE = (ROOT / "collector_service" / "sync_worker.py").read_text(
    encoding="utf-8"
)
NON_HTTP_AUTH_SOURCE = "\n".join(
    path.read_text(encoding="utf-8")
    for path in SOURCE_FILES
    if path.name not in {
        "cez_http_auth.py",
        "requests_preauth.py",
        "cez_data_probe.py",
    }
)
RUNTIME_CONFIG_SOURCE = (ROOT / "collector_service" / "runtime_config.py").read_text(
    encoding="utf-8"
)
SERVER_SOURCE = (ROOT / "collector_service" / "server.py").read_text(encoding="utf-8")
DISCOVERY_SOURCE = (ROOT / "collector_service" / "cez_discovery.py").read_text(
    encoding="utf-8"
)
RESTRICTED_PROXY_SOURCE = (
    ROOT / "collector_service" / "restricted_proxy.py"
).read_text(encoding="utf-8")
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
WORKFLOW = (
    REPOSITORY_ROOT / ".github" / "workflows" / "publish-collector-service.yaml"
).read_text(encoding="utf-8")
VALIDATION_WORKFLOW = (
    REPOSITORY_ROOT / ".github" / "workflows" / "validate-collector-service.yaml"
).read_text(encoding="utf-8")
SMOKE_COMPOSE = (ROOT / "smoke" / "compose.yaml").read_text(encoding="utf-8")
SMOKE_CLIENT = (ROOT / "smoke" / "smoke_client.py").read_text(encoding="utf-8")
SMOKE_PREPARE = (ROOT / "smoke" / "prepare_material.sh").read_text(encoding="utf-8")
SMOKE_RUN = (ROOT / "smoke" / "run_smoke.sh").read_text(encoding="utf-8")
DOCKERIGNORE = (ROOT / ".dockerignore").read_text(encoding="utf-8")
SMOKE_GITIGNORE = (ROOT / "smoke" / ".gitignore").read_text(encoding="utf-8")
PHASE2B_EVIDENCE = (
    REPOSITORY_ROOT / "docs" / "phase2b-collector-service-validation.md"
).read_text(encoding="utf-8")
APP_DIRECTORY = REPOSITORY_ROOT / "cez_pnd_collector"
APP_MANIFEST = (APP_DIRECTORY / "config.yaml").read_text(encoding="utf-8")
APP_DOCUMENTATION = (APP_DIRECTORY / "DOCS.md").read_text(encoding="utf-8")
HA_APP_VALIDATION = (
    REPOSITORY_ROOT / "docs" / "phase2b-collector-ha-app.md"
).read_text(encoding="utf-8")

EXPECTED_BASE = (
    "FROM ghcr.io/dracoanus/home-assistant-cez-pnd-collector-runtime:0.1.0"
    "@sha256:e0fefbfa049a1843ab4ef6711665168445789776bb25ff03c2e318b933f033fc"
)
assert EXPECTED_BASE in DOCKERFILE
assert VERSION == "0.3.32"
assert f'__version__ = "{VERSION}"' in SOURCE
assert 'datetime.now(timezone.utc)' in STRUCTURED_LOGGING_SOURCE
assert 'strftime("%Y-%m-%dT%H:%M:%SZ")' in STRUCTURED_LOGGING_SOURCE
assert '{"timestamp": utc_timestamp(now), **fields}' in STRUCTURED_LOGGING_SOURCE
assert SOURCE.count("from .structured_logging import structured_event_json") == 4
assert (
    "COPY --chown=0:0 --chmod=0555 collector_service "
    "/opt/collector-service/collector_service"
) in DOCKERFILE
assert (
    "COPY --chown=0:0 --chmod=0555 collector_entrypoint.py "
    "/opt/collector-service/collector_entrypoint.py"
) in DOCKERFILE
assert DOCKERFILE.count("USER root") == 1
assert DOCKERFILE.count("RUN ") == 1
assert "pip install --disable-pip-version-check --no-cache-dir --no-deps --only-binary=:all:" in DOCKERFILE
assert "USER 2000:2000" not in DOCKERFILE
assert (
    'ENTRYPOINT ["/opt/collector-venv/bin/python", '
    '"/opt/collector-service/collector_entrypoint.py"]'
) in DOCKERFILE
assert 'PROBE_DIRECTORY_NAME = "cez-pnd-probe"' in ENTRYPOINT_SOURCE
assert 'DATA_DIRECTORY = Path("/data")' in ENTRYPOINT_SOURCE
assert "probe_directory.mkdir(mode=0o700, exist_ok=True)" in ENTRYPOINT_SOURCE
assert "RUNTIME_UID = 2000" in ENTRYPOINT_SOURCE
assert "RUNTIME_GID = 2000" in ENTRYPOINT_SOURCE
assert "os.setgroups([])" in ENTRYPOINT_SOURCE
assert "os.setgid(RUNTIME_GID)" in ENTRYPOINT_SOURCE
assert "os.setuid(RUNTIME_UID)" in ENTRYPOINT_SOURCE
assert "os.execv(SERVER_ARGV[0], list(SERVER_ARGV))" in ENTRYPOINT_SOURCE
assert "recursive" not in ENTRYPOINT_SOURCE.lower()
assert "chmod 777" not in ENTRYPOINT_SOURCE
assert "0o777" not in ENTRYPOINT_SOURCE
for installer in ("apt-get", "apt ", "apk add", "curl ", "wget "):
    assert installer not in DOCKERFILE
assert REQUESTS_COMPATIBILITY_REQUIREMENTS.splitlines() == [
    "requests==2.32.5",
    "charset-normalizer==3.4.3",
]

for forbidden in (
    "--no-sandbox",
    "--disable-setuid-sandbox",
    "--disable-gpu-sandbox",
    "SYS_ADMIN",
    "NET_ADMIN",
    "privileged",
    "full_access",
    "host_network",
    "/var/run/docker.sock",
):
    assert forbidden not in DOCKERFILE

for forbidden in (
    "pnd.cezdistribuce.cz",
    "mepas.cez.cz",
    "dip.cezdistribuce.cz",
):
    assert forbidden not in NON_HTTP_AUTH_SOURCE

for forbidden in (
    "subprocess",
    "os.system",
    "shell=True",
):
    assert forbidden not in SOURCE

routes = set(re.findall(r'f"\{API_PREFIX\}(/[^"}]*)"', SOURCE))
assert routes == {"/health", "/status", "/measurements"}
assert "hmac.compare_digest" in SOURCE
assert "Cache-Control" in SOURCE and "no-store" in SOURCE
assert "Access-Control-Allow-Origin" not in SOURCE
assert '"value_kwh": row.value_kwh' in API_SOURCE
assert "value_kwh\": 0" not in SOURCE
assert "BIND_ADDRESS = \"0.0.0.0\"" in SOURCE
assert "BIND_PORT = 8443" in SOURCE
assert "ssl.PROTOCOL_TLS_SERVER" in SOURCE
assert 'context.set_alpn_protocols(["http/1.1"])' in STRICT_TRANSPORT_SOURCE
assert "os.O_NOFOLLOW" in SOURCE
assert "os.fstat" in SOURCE
assert "signal.SIGTERM" in SOURCE
assert 'DATASET_DIRECTORY_NAME = "cez-pnd-dataset"' in ENTRYPOINT_SOURCE
assert 'DATASET_FILE_NAME = "cez-pnd.sqlite3"' in ENTRYPOINT_SOURCE
assert "prepare_dataset_storage()" in ENTRYPOINT_SOURCE
assert "mode_setter(dataset_directory, 0o700" in ENTRYPOINT_SOURCE
assert "owner_setter(dataset_directory, RUNTIME_UID, RUNTIME_GID" in ENTRYPOINT_SOURCE
assert "mode_setter(dataset, 0o600" in ENTRYPOINT_SOURCE
assert "owner_setter(dataset, RUNTIME_UID, RUNTIME_GID" in ENTRYPOINT_SOURCE
assert '"event": "service_stopped"' in SERVER_SOURCE
assert (
    'SUPERVISOR_SELF_INFO_URL = "http://supervisor/addons/self/info"'
    in RUNTIME_CONFIG_SOURCE
)
assert '"http://supervisor/apps/self/info"' not in RUNTIME_CONFIG_SOURCE
assert '"http://supervisor/v2/apps/self/info"' not in RUNTIME_CONFIG_SOURCE
assert "class PrivateConfigurationError(ValueError)" in RUNTIME_CONFIG_SOURCE
assert "PRIVATE_CONFIGURATION_ERROR_CODES = frozenset" in RUNTIME_CONFIG_SOURCE
for required_code in (
    "private_config_supervisor_request_failed",
    "private_config_supervisor_response_invalid",
    "private_config_invalid_token_verifier",
    "private_config_missing_tls_certificate",
    "private_config_missing_tls_private_key",
    "private_config_invalid_certificate_encoding",
    "private_config_invalid_private_key_encoding",
    "private_config_key_mismatch",
    "private_config_ssl_context_load_failed",
):
    assert required_code in RUNTIME_CONFIG_SOURCE
assert "HTTPRedirectHandler" in SOURCE
assert "MAX_SUPERVISOR_RESPONSE_BYTES = 256 * 1024" in RUNTIME_CONFIG_SOURCE
assert "base64.b64decode(encoded, validate=True)" in SOURCE
assert "api_token_sha256" in SOURCE
assert "tls_private_key_b64" in SOURCE
assert 'source="supervisor_self_info"' in SOURCE
assert "tempfile.mkstemp" in SOURCE and "os.fchmod(descriptor, 0o600)" in SOURCE
assert "os.unlink(path)" in SOURCE
assert "from selenium import webdriver" in DISCOVERY_SOURCE
assert 'binary_location = "/usr/bin/chromium"' in DISCOVERY_SOURCE
assert 'executable_path="/usr/bin/chromedriver"' in DISCOVERY_SOURCE
assert "--headless=new" in DISCOVERY_SOURCE
assert "--proxy-server=http://127.0.0.1:" in DISCOVERY_SOURCE
assert "--host-resolver-rules=MAP * ~NOTFOUND" in DISCOVERY_SOURCE
assert 'super().__init__(("127.0.0.1", 0)' in RESTRICTED_PROXY_SOURCE
assert 'port_text != "443"' in RESTRICTED_PROXY_SOURCE
assert "ipaddress.ip_address(address[0]).is_global" in RESTRICTED_PROXY_SOURCE
assert '"Browser.setDownloadBehavior", {"behavior": "deny"}' in DISCOVERY_SOURCE
assert "driver.delete_all_cookies()" in DISCOVERY_SOURCE
assert "shutil.rmtree(runtime_directory)" in DISCOVERY_SOURCE
assert "log_output=os.devnull" in DISCOVERY_SOURCE
assert "driver.get(configuration.start_url)" in DISCOVERY_SOURCE
assert "configuration.username" in DISCOVERY_SOURCE
assert "configuration.password" in DISCOVERY_SOURCE
for forbidden_argument in (
    "--no-sandbox",
    "--disable-setuid-sandbox",
    "--disable-gpu-sandbox",
    "--disable-seccomp-filter-sandbox",
):
    assert f'"{forbidden_argument}"' in DISCOVERY_SOURCE
assert "cez_username" not in (ROOT / "collector_service" / "api.py").read_text(
    encoding="utf-8"
)
assert "cez_password" not in (ROOT / "collector_service" / "api.py").read_text(
    encoding="utf-8"
)
assert "os.environ.get(\"CEZ_" not in SOURCE
assert (
    '"https://pnd.cezdistribuce.cz/cezpnd2/external/dashboard/view"'
    in HTTP_AUTH_SOURCE
)
for required_host in (
    "pnd.cezdistribuce.cz",
    "mepas.cez.cz",
    "dip.cezdistribuce.cz",
):
    assert required_host in HTTP_AUTH_SOURCE
assert "trust_environment" in HTTP_AUTH_SOURCE
assert "follows_redirects" in HTTP_AUTH_SOURCE
assert "MAX_REDIRECTS = 8" in HTTP_AUTH_SOURCE
assert "MAX_RESPONSE_BODY_BYTES = 512 * 1024" in HTTP_AUTH_SOURCE
assert "MAX_HTML_BYTES = 256 * 1024" in HTTP_AUTH_SOURCE
assert "MAX_FORM_CONTROLS = 64" in HTTP_AUTH_SOURCE
assert "MAX_FORM_VALUE_BYTES = 32 * 1024" in HTTP_AUTH_SOURCE
for form_limit_code in (
    "auth_form_document_too_large",
    "auth_form_control_limit",
    "auth_form_name_too_large",
    "auth_form_value_too_large",
):
    assert form_limit_code in HTTP_AUTH_SOURCE
assert "MAX_COOKIE_COUNT = 32" in HTTP_AUTH_SOURCE
assert 'REVIEWED_COOKIE_DOMAINS = frozenset({"cez.cz", "cezdistribuce.cz"})' in HTTP_AUTH_SOURCE
assert 'domain == boundary or domain.endswith("." + boundary)' in HTTP_AUTH_SOURCE
assert "not _is_reviewed_cookie_domain(domain)" in HTTP_AUTH_SOURCE
for cookie_error_code in (
    "auth_cookie_invalid_syntax",
    "auth_cookie_invalid_name",
    "auth_cookie_invalid_domain",
    "auth_cookie_domain_mismatch",
    "auth_cookie_domain_not_allowed",
):
    assert cookie_error_code in HTTP_AUTH_SOURCE
assert '"auth_cookie_invalid"' not in HTTP_AUTH_SOURCE
assert (
    "if not host_only and not _domain_matches(hostname, domain):\n"
    "                continue"
) in HTTP_AUTH_SOURCE
assert "AuthStatus.NEEDS_LIVE_VERIFICATION" in HTTP_AUTH_SOURCE
for transport_diagnostic_code in (
    "auth_transport_invariant_failed",
    "auth_connect_failed",
    "auth_request_write_failed",
    "auth_response_protocol_failed",
    "auth_response_header_limit",
    "auth_response_body_limit",
):
    assert transport_diagnostic_code in HTTP_AUTH_SOURCE
    assert transport_diagnostic_code in STRICT_TRANSPORT_SOURCE
assert "header_size > 64 * 1024" in STRICT_TRANSPORT_SOURCE
assert "length > maximum_body_bytes" in STRICT_TRANSPORT_SOURCE
assert '"http_auth_result"' in HTTP_AUTH_SOURCE
assert "SafeHttpAuthEvent.from_result(result)" in SERVER_SOURCE
assert "auth_success_condition_needs_live_verification" in HTTP_AUTH_SOURCE
assert "requests" not in HTTP_AUTH_SOURCE
assert "requests.Session()" in REQUESTS_PREAUTH_SOURCE
assert "session.trust_env = False" in REQUESTS_PREAUTH_SOURCE
assert "allow_redirects=False" in REQUESTS_PREAUTH_SOURCE
assert "verify=True" in REQUESTS_PREAUTH_SOURCE
assert "validate_destination(url, state, \"GET\", transport.resolve)" in REQUESTS_PREAUTH_SOURCE
assert "class RequestsSessionTransport" in REQUESTS_PREAUTH_SOURCE
assert "manages_cookies = True" in REQUESTS_PREAUTH_SOURCE
assert "from .requests_preauth import RequestsSessionTransport" in SERVER_SOURCE
assert "StrictHttpsTransport" not in SERVER_SOURCE
assert "BeautifulSoup" not in HTTP_AUTH_SOURCE
assert re.search(
    r"^\s*(?:import logging|from logging import)", HTTP_AUTH_SOURCE, re.MULTILINE
) is None
assert "CezHttpAuthClient" not in (
    ROOT / "collector_service" / "api.py"
).read_text(encoding="utf-8")
for forbidden_tls in (
    "ssl._create_unverified_context",
    "ssl.CERT_NONE",
    "check_hostname = False",
):
    assert forbidden_tls not in STRICT_TRANSPORT_SOURCE
assert "ssl.create_default_context" in STRICT_TRANSPORT_SOURCE
assert "ssl.CERT_REQUIRED" in STRICT_TRANSPORT_SOURCE
assert "ssl.TLSVersion.TLSv1_2" in STRICT_TRANSPORT_SOURCE
assert "server_hostname=destination.hostname" in STRICT_TRANSPORT_SOURCE
assert 'connection.putheader("Host", destination.hostname)' in STRICT_TRANSPORT_SOURCE
assert "raw_socket.connect(endpoint)" in STRICT_TRANSPORT_SOURCE
assert "connection.sock = tls_socket" in STRICT_TRANSPORT_SOURCE
assert "socket.getaddrinfo" in STRICT_TRANSPORT_SOURCE
assert "trust_environment = False" in STRICT_TRANSPORT_SOURCE
assert "follows_redirects = False" in STRICT_TRANSPORT_SOURCE
assert "ProxyHandler" not in STRICT_TRANSPORT_SOURCE
assert "HTTPSConnection" not in STRICT_TRANSPORT_SOURCE
assert "MAX_ADDRESS_ATTEMPTS = 4" in STRICT_TRANSPORT_SOURCE
assert 'options.get("cez_http_auth_discovery_mode", False)' in RUNTIME_CONFIG_SOURCE
assert 'options.get("cez_requests_preauth_compatibility_mode", False)' in RUNTIME_CONFIG_SOURCE
assert 'options.get("cez_data_probe_mode", False)' in RUNTIME_CONFIG_SOURCE
assert 'options.get("cez_sync_enabled", False)' in RUNTIME_CONFIG_SOURCE
assert "discovery_config_conflicting_modes" in RUNTIME_CONFIG_SOURCE
assert "sync_config_conflicting_modes" in RUNTIME_CONFIG_SOURCE
assert 'CEZ_PND_EXPORT_URL = (' in DATA_PROBE_SOURCE
assert '"https://pnd.cezdistribuce.cz/cezpnd2/external/data/export"' in DATA_PROBE_SOURCE
assert 'PROBE_DIRECTORY = Path("/data/cez-pnd-probe")' in DATA_PROBE_SOURCE
assert 'METADATA_SUMMARY_NAME = "metadata-summary.json"' in DATA_PROBE_SOURCE
assert 'CONSUMPTION_NAME = "range-consumption.csv"' in DATA_PROBE_SOURCE
assert 'PRODUCTION_NAME = "range-production.csv"' in DATA_PROBE_SOURCE
assert 'os.chmod(directory, 0o700)' in DATA_PROBE_SOURCE
assert 'os.chmod(path, 0o600)' in DATA_PROBE_SOURCE
assert "tempfile.mkstemp" in DATA_PROBE_SOURCE
assert "os.replace" in DATA_PROBE_SOURCE
assert '"idAssembly", "-1001"' not in DATA_PROBE_SOURCE
assert '"idAssembly", assembly_id' in DATA_PROBE_SOURCE
assert "run_data_probe(" in SERVER_SOURCE
assert "SyncWorker(sync_configuration, store=dataset_store)" in SERVER_SOURCE
assert "CURRENT_DAY_SYNC_INTERVAL_SECONDS = 60 * 60" in SYNC_WORKER_SOURCE
assert "HISTORICAL_SYNC_INTERVAL_SECONDS = 6 * 60 * 60" in SYNC_WORKER_SOURCE
assert "BACKFILL_CHUNK_DAYS = 31" in SYNC_WORKER_SOURCE
assert "BACKFILL_MAX_CHUNKS_PER_CYCLE = 2" in SYNC_WORKER_SOURCE
assert "CORRECTION_OVERLAP_DAYS = 3" in SYNC_WORKER_SOURCE
assert 'ZoneInfo("Europe/Prague")' in SYNC_WORKER_SOURCE
assert "persist_raw_outputs=False" in SYNC_WORKER_SOURCE
assert "require_complete_days=False" not in SYNC_WORKER_SOURCE
for current_day_event in (
    "current_day_sync_started",
    "current_day_sync_succeeded",
    "current_day_sync_failed",
):
    assert current_day_event in SYNC_WORKER_SOURCE
assert '"sync_cycle_internal_failed"' in SYNC_WORKER_SOURCE
assert "except Exception:" in SYNC_WORKER_SOURCE
assert '"dashboard_metadata_response_observed"' in HTTP_AUTH_SOURCE
assert '"dashboard_metadata_unusable"' in HTTP_AUTH_SOURCE
for metadata_diagnostic_code in (
    "data_probe_metadata_content_type_invalid",
    "data_probe_metadata_utf8_invalid",
    "data_probe_metadata_json_invalid",
    "data_probe_metadata_id_device_set_invalid",
    "data_probe_metadata_meter_collection_invalid",
):
    assert metadata_diagnostic_code in HTTP_AUTH_SOURCE
    assert metadata_diagnostic_code in DATA_PROBE_SOURCE
assert '"data_probe_metadata_configured_elm_not_found"' in HTTP_AUTH_SOURCE
assert "class DashboardMetadataObservation" in HTTP_AUTH_SOURCE
assert 'key != "[redacted-key]"' in HTTP_AUTH_SOURCE
assert "len(self.top_level_keys) > 50" in HTTP_AUTH_SOURCE
assert "metadata_observation=observation" in DATA_PROBE_SOURCE
assert "_store_metadata_summary(observation)" in DATA_PROBE_SOURCE
assert 'CEZ_PND_METERS_URL = (' in DATA_PROBE_SOURCE
assert '"https://pnd.cezdistribuce.cz/cezpnd2/api/v1/consumption/meters"' in DATA_PROBE_SOURCE
assert "AuthState.DATA_PROBE_METERS" in HTTP_AUTH_SOURCE
assert "AuthState.DATA_PROBE_METERS" in DATA_PROBE_SOURCE
assert "return _Metadata(None, False, False, ()), observation" in DATA_PROBE_SOURCE
assert '"data_probe_metadata_root_invalid"' in HTTP_AUTH_SOURCE
assert '"data_probe_meter_selection_observed"' in HTTP_AUTH_SOURCE
assert "class DataProbeMeterSelectionObservation" in HTTP_AUTH_SOURCE
assert '"data_probe_meter_lookup_unavailable"' in HTTP_AUTH_SOURCE
assert "class DataProbeMeterLookupUnavailableObservation" in HTTP_AUTH_SOURCE
for meter_failure_code in (
    "data_probe_meter_identity_required",
    "data_probe_meter_not_found",
    "data_probe_meter_selection_ambiguous",
    "data_probe_meter_identity_mismatch",
    "data_probe_meter_lookup_failed",
):
    assert meter_failure_code in HTTP_AUTH_SOURCE
    assert meter_failure_code in DATA_PROBE_SOURCE
assert 'entry.get("ean")' in DATA_PROBE_SOURCE
assert 'entry.get("elm")' in DATA_PROBE_SOURCE
assert 'parameters.append(("electrometerId", verified_elm))' in DATA_PROBE_SOURCE
assert 'parameters.append(("ean"' not in DATA_PROBE_SOURCE
assert 'extra_headers={"Accept": "*/*"}' in DATA_PROBE_SOURCE
assert 'extra_headers={"Accept": "application/json"}' not in DATA_PROBE_SOURCE
for lookup_reason in (
    "request_failed",
    "status",
    "content_type",
    "utf8",
    "json",
    "root_type",
    "empty",
):
    assert f'"{lookup_reason}"' in HTTP_AUTH_SOURCE
    assert f'"{lookup_reason}"' in DATA_PROBE_SOURCE
assert "ean: str | None = field(default=None, repr=False)" in RUNTIME_CONFIG_SOURCE
assert "len(raw_ean) != 18" in RUNTIME_CONFIG_SOURCE
assert "not raw_ean.isascii()" in RUNTIME_CONFIG_SOURCE
assert "not raw_ean.isdigit()" in RUNTIME_CONFIG_SOURCE
for safe_meter_field in (
    "meter_response_status",
    "json_root_type",
    "meter_count",
    "matches_by_ean",
    "matches_by_elm",
    "selection_mode",
):
    assert safe_meter_field in HTTP_AUTH_SOURCE
assert "MAX_FILE_BYTES = 5 * 1024 * 1024" in CSV_PARSER_SOURCE
assert "MAX_ROWS = 10_000" in CSV_PARSER_SOURCE
assert "MAX_COLUMNS = 50" in CSV_PARSER_SOURCE
assert "MAX_CELL_CHARACTERS = 128" in CSV_PARSER_SOURCE
assert '("utf-8-sig", "utf-8", "cp1250", "iso-8859-2")' in CSV_PARSER_SOURCE
assert 'SUPPORTED_DELIMITERS = (";", ",")' in CSV_PARSER_SOURCE
assert 'Decimal("0.25")' in CSV_PARSER_SOURCE
assert 'frozenset({"", "-", "--", "n/a", "na", "none", "null"})' in CSV_PARSER_SOURCE
assert 'raise PndCsvParseError("csv_status_invalid")' in CSV_PARSER_SOURCE
assert '"platna data", "namerena data ok"' in CSV_PARSER_SOURCE
assert '"neznama hodnota"' in CSV_PARSER_SOURCE
assert '"nedostupna data"' in CSV_PARSER_SOURCE
assert '"neplatna data", "chyba", "chyba mereni"' in CSV_PARSER_SOURCE
assert '_CONSUMPTION_HEADER_KEYWORDS = ("+a", "+e", "spotreb", "odber")' in CSV_PARSER_SOURCE
assert '_PRODUCTION_HEADER_KEYWORDS = ("-a", "-e", "vyrob", "dodavk")' in CSV_PARSER_SOURCE
assert "date_column is not None and time_column is None" in CSV_PARSER_SOURCE
assert 'raise PndCsvParseError("csv_duplicate_conflict")' in CSV_PARSER_SOURCE
assert "expected not in {92, 96, 100}" in CSV_PARSER_SOURCE
assert "class IntervalRecord" in CSV_MODELS_SOURCE
assert "class ParsedPndData" in CSV_MODELS_SOURCE
assert "value_kwh: Decimal | None" in CSV_MODELS_SOURCE
assert 'INVALID = "invalid"' in CSV_MODELS_SOURCE
assert 'DATASET_PATH = Path("/data/cez-pnd-dataset/cez-pnd.sqlite3")' in DATASET_STORE_SOURCE
assert 'raise OSError("unsafe dataset directory owner")' in DATASET_STORE_SOURCE
assert "sqlite3.connect" in DATASET_STORE_SOURCE
assert "BEGIN IMMEDIATE" in DATASET_STORE_SOURCE
assert "ON CONFLICT(channel,interval_start) DO UPDATE" in DATASET_STORE_SOURCE
assert 'CREATE TABLE IF NOT EXISTS sync_state(' in DATASET_STORE_SOURCE
assert 'UPDATE measurements SET revision' not in DATASET_STORE_SOURCE
assert 'StoredMeasurement(*row[:-1], metadata[0])' in DATASET_STORE_SOURCE
assert "CHECK(valid_count+missing_count+invalid_count=expected_count)" in DATASET_STORE_SOURCE
assert 'getattr(os, "O_NOFOLLOW", 0)' in DATASET_STORE_SOURCE
assert "os.chmod(self.path, 0o600)" in DATASET_STORE_SOURCE
assert "NormalizedDatasetStore" in API_SOURCE
assert "SYNTHETIC_START" not in API_SOURCE
assert "SYNTHETIC_REVISION" not in API_SOURCE
assert "data_probe_dataset_committed" in HTTP_AUTH_SOURCE
assert "parse_pnd_csv(" in DATA_PROBE_SOURCE
assert '"data_probe_csv_parse_failed"' in HTTP_AUTH_SOURCE
assert "class DataProbeCsvParseFailureObservation" in HTTP_AUTH_SOURCE
assert "CSV_PARSE_ERROR_CODES" in HTTP_AUTH_SOURCE
assert "csv_parse_failure_observation=DataProbeCsvParseFailureObservation" in DATA_PROBE_SOURCE
assert "Copyright (c) 2026 igracek" in CSV_PARSER_SOURCE
assert "Copyright (c) 2026 igracek" in THIRD_PARTY_NOTICES
assert '"data_probe_export_response_observed"' in HTTP_AUTH_SOURCE
assert "class DataProbeExportObservation" in HTTP_AUTH_SOURCE
assert 'headers={"Accept": "*/*", "Referer": CEZ_PND_START_URL}' in DATA_PROBE_SOURCE
for channel in ("consumption", "production"):
    for export_failure in (
        "status_failed",
        "empty",
        "too_large",
        "content_type_invalid",
        "html_rejected",
    ):
        code = f"data_probe_{channel}_export_{export_failure}"
        assert code in HTTP_AUTH_SOURCE
assert 'prefix = f"data_probe_{channel}_export"' in DATA_PROBE_SOURCE
for export_failure in (
    "status_failed",
    "empty",
    "too_large",
    "content_type_invalid",
    "html_rejected",
):
    assert f'f"{{prefix}}_{export_failure}"' in DATA_PROBE_SOURCE
assert 'tags:\n      - "collector-service-v*"' in WORKFLOW
assert "ghcr.io/dracoanus/home-assistant-cez-pnd-collector" in WORKFLOW
assert "platforms: linux/amd64" in WORKFLOW
assert "sbom: true" in WORKFLOW
assert "provenance: mode=max" in WORKFLOW
assert "Refuse to overwrite immutable tags" in WORKFLOW
assert ":latest" not in WORKFLOW
for uses in re.findall(
    r"^\s*uses:\s*([^\s]+)", WORKFLOW + "\n" + VALIDATION_WORKFLOW, re.MULTILINE
):
    assert re.search(r"@[0-9a-f]{40}$", uses), f"unpinned action: {uses}"

assert "pull_request:" in VALIDATION_WORKFLOW
assert "      - main" in VALIDATION_WORKFLOW
assert '      - "poc/phase2a-runtime/**"' in VALIDATION_WORKFLOW
assert "permissions:\n  contents: read" in VALIDATION_WORKFLOW
assert "runs-on: ubuntu-latest" in VALIDATION_WORKFLOW
assert "python3 collector/ci_validate.py" in VALIDATION_WORKFLOW
assert "python3 -m unittest discover -s collector/tests -v" in VALIDATION_WORKFLOW
assert "python3 collector/static_verify.py" in VALIDATION_WORKFLOW
assert "python3 -m compileall" in VALIDATION_WORKFLOW
assert "git diff --check" in VALIDATION_WORKFLOW
assert "Psych.parse_file" in VALIDATION_WORKFLOW
assert '      - "cez_pnd_collector/**"' in VALIDATION_WORKFLOW
assert '      - "repository.yaml"' in VALIDATION_WORKFLOW
for forbidden in ("privileged", "docker build", "selenium", "pnd.cez"):
    assert forbidden not in VALIDATION_WORKFLOW

for forbidden in (
    "network_mode:",
    "privileged:",
    "ports:",
    "SYS_ADMIN",
    "NET_ADMIN",
    "seccomp=unconfined",
):
    assert forbidden not in SMOKE_COMPOSE
assert SMOKE_COMPOSE.count('user: "2000:2000"') == 2
assert SMOKE_COMPOSE.count("- ALL") == 2
assert SMOKE_COMPOSE.count("no-new-privileges:true") == 2
assert "internal: true" in SMOKE_COMPOSE
assert SMOKE_COMPOSE.count(":ro") == 4
assert "https://collector:8443" in SMOKE_CLIENT
assert "http://" not in SMOKE_CLIENT
assert "urlopen" in SMOKE_CLIENT
assert 'value_kwh") is None' in SMOKE_CLIENT
assert "openssl rand -hex 32" in SMOKE_PREPARE
assert 'printf \'%s\' "${TOKEN}" >' in SMOKE_PREPARE
assert 'echo "${TOKEN}"' not in SMOKE_PREPARE
assert 'Refusing to overwrite an existing smoke runtime directory.' in SMOKE_PREPARE
assert '"message": str(error)' not in SMOKE_CLIENT
assert "trap cleanup_on_exit EXIT INT TERM" in SMOKE_RUN
assert "docker compose -f compose.yaml config" in SMOKE_RUN
assert "./cleanup_material.sh" in SMOKE_RUN
assert "smoke/" in DOCKERIGNORE
assert SMOKE_GITIGNORE.splitlines() == ["/runtime/"]

ast.parse(SMOKE_CLIENT, filename="smoke/smoke_client.py")

assert "Overall smoke result | `passed=true`" in PHASE2B_EVIDENCE
assert "Missing measurement converted to zero | No, PASS" in PHASE2B_EVIDENCE
assert "PIDs limit discarded" in PHASE2B_EVIDENCE
assert "OPEN / NEEDS VERIFICATION on HA OS" in PHASE2B_EVIDENCE

assert not (APP_DIRECTORY / "Dockerfile").exists()
expected_manifest_keys = {
    "name",
    "version",
    "slug",
    "description",
    "url",
    "arch",
    "image",
    "startup",
    "boot",
    "init",
    "stage",
    "timeout",
    "tmpfs",
    "host_network",
    "host_pid",
    "host_ipc",
    "host_uts",
    "host_dbus",
    "hassio_api",
    "homeassistant_api",
    "auth_api",
    "docker_api",
    "full_access",
    "apparmor",
    "audio",
    "video",
    "gpio",
    "usb",
    "uart",
    "udev",
    "devicetree",
    "kernel_modules",
    "realtime",
    "ingress",
    "stdin",
    "options",
    "schema",
}
manifest_keys = set(re.findall(r"^([a-z_]+):", APP_MANIFEST, re.MULTILINE))
assert manifest_keys == expected_manifest_keys
for required in (
    'name: "CEZ PND Collector"',
    'version: "0.3.32"',
    "slug: cez_pnd_collector",
    "  - amd64",
    'image: "ghcr.io/dracoanus/home-assistant-cez-pnd-collector"',
    "stage: experimental",
    "tmpfs: true",
    "host_network: false",
    "host_pid: false",
    "host_ipc: false",
    "host_uts: false",
    "host_dbus: false",
    "hassio_api: false",
    "homeassistant_api: false",
    "auth_api: false",
    "docker_api: false",
    "full_access: false",
    "apparmor: true",
    "ingress: false",
):
    assert required in APP_MANIFEST
for forbidden in (
    "ports:",
    "map:",
    "devices:",
    "privileged:",
    "SYS_ADMIN",
    "NET_ADMIN",
    "latest",
    "--no-sandbox",
    "--disable-setuid-sandbox",
    "--disable-gpu-sandbox",
):
    assert forbidden not in APP_MANIFEST
assert "api_token_sha256" in APP_MANIFEST
assert "api_token:" not in APP_MANIFEST
assert "tls_certificate_b64" in APP_MANIFEST
assert "tls_private_key_b64" in APP_MANIFEST
assert "  cez_discovery_mode: false" in APP_MANIFEST
assert "  cez_http_auth_discovery_mode: false" in APP_MANIFEST
assert "  cez_http_auth_discovery_mode: bool" in APP_MANIFEST
assert "  cez_requests_preauth_compatibility_mode: false" in APP_MANIFEST
assert "  cez_requests_preauth_compatibility_mode: bool" in APP_MANIFEST
assert "  cez_data_probe_mode: false" in APP_MANIFEST
assert "  cez_data_probe_mode: bool" in APP_MANIFEST
assert "  cez_sync_enabled: false" in APP_MANIFEST
assert "  cez_sync_enabled: bool" in APP_MANIFEST
assert "  cez_history_start: null" in APP_MANIFEST
assert "  cez_history_start: str?" in APP_MANIFEST
assert "  cez_data_probe_date: null" in APP_MANIFEST
assert "  cez_data_probe_date: str?" in APP_MANIFEST
assert "  cez_ean: null" in APP_MANIFEST
assert "  cez_ean: password?" in APP_MANIFEST
assert "  cez_elm: password?" in APP_MANIFEST
assert "  cez_allowed_origins: []" in APP_MANIFEST
assert "  cez_start_url: url?" in APP_MANIFEST
assert "  cez_auth_origin: url?" in APP_MANIFEST
assert "  cez_username: password?" in APP_MANIFEST
assert "  cez_password: password?" in APP_MANIFEST
assert "cez_username:" not in APP_MANIFEST.split("schema:", 1)[0]
assert "cez_password:" not in APP_MANIFEST.split("schema:", 1)[0]
assert "plaintext bearer token" in APP_DOCUMENTATION
assert (
    "0.2.1 HA OS DEPLOYMENT GATE FAILED CLOSED / RUNTIME BOOTSTRAP"
    in HA_APP_VALIDATION
)
assert "missing API permission for /apps/self/info" in HA_APP_VALIDATION
assert "http://supervisor/v2/apps/self/info" in HA_APP_VALIDATION
assert "changes only the Supervisor self-info endpoint" in HA_APP_VALIDATION
assert '"code":"invalid_private_configuration"' in HA_APP_VALIDATION
assert "The overall deployment gate result is **FAIL / BLOCKED** for Collector" in HA_APP_VALIDATION
assert "Collector 0.2.2 diagnostic scope" in HA_APP_VALIDATION
assert "Core-origin connectivity remains OPEN" in HA_APP_VALIDATION

for path in SOURCE_FILES:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in {"eval", "exec", "compile"}

ast.parse(ENTRYPOINT_SOURCE, filename=str(ROOT / "collector_entrypoint.py"))

print("PASS: immutable validated Debian runtime base")
print("PASS: root-owned mode-0555 source is set atomically by COPY")
print("PASS: root-only storage bootstrap drops permanently to UID/GID 2000:2000")
print("PASS: exactly three versioned read-only API routes")
print("PASS: TLS and constant-time bearer verifier required")
print("PASS: CEZ hosts exist only in reviewed authentication/data-probe code")
print("PASS: missing measurement is null, never synthesized zero")
print("PASS: immutable GHCR workflow retains SBOM and provenance")
print("PASS: isolated non-root offline container smoke profile")
print("PASS: PR validation workflow is read-only, pinned, and offline")
print("PASS: production App wrapper is prebuilt-image-only and least-privilege")
print("PASS: HA bootstrap stores only the API verifier and fails closed")
print("PASS: one-shot CEZ discovery is explicit, allowlisted, and non-secret")
print("PASS: browserless CEZ auth is offline-only, redirect-explicit, and fail-closed")
print("PASS: retained strict transport still pins validated IPs")
print("PASS: active requests auth validates every hop before its documented second DNS resolution")
print("PASS: one-shot authenticated data probe is bounded, exact-destination, and private")
print("PASS: export observations and failure codes expose only bounded structural metadata")
print("PASS: CEZ CSV parsing is bounded, decimal-exact, DST-aware, and MIT-attributed")
