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
RUNTIME_CONFIG_SOURCE = (ROOT / "collector_service" / "runtime_config.py").read_text(
    encoding="utf-8"
)
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
assert VERSION == "0.2.1"
assert f'__version__ = "{VERSION}"' in SOURCE
assert (
    "COPY --chown=0:0 --chmod=0555 collector_service "
    "/opt/collector-service/collector_service"
) in DOCKERFILE
assert "RUN " not in DOCKERFILE
assert "USER root" not in DOCKERFILE
assert "USER 2000:2000" in DOCKERFILE
assert 'CMD ["/opt/collector-venv/bin/python", "-m", "collector_service.server"]' in DOCKERFILE
for installer in ("apt-get", "apt ", "pip install", "apk add", "curl ", "wget "):
    assert installer not in DOCKERFILE

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
    "selenium.webdriver",
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
assert "value_kwh\": None" in SOURCE
assert "value_kwh\": 0" not in SOURCE
assert "BIND_ADDRESS = \"0.0.0.0\"" in SOURCE
assert "BIND_PORT = 8443" in SOURCE
assert "ssl.PROTOCOL_TLS_SERVER" in SOURCE
assert "os.O_NOFOLLOW" in SOURCE
assert "os.fstat" in SOURCE
assert "signal.SIGTERM" in SOURCE
assert '"event":"service_stopped"' in SOURCE
assert (
    'SUPERVISOR_SELF_INFO_URL = "http://supervisor/v2/apps/self/info"'
    in RUNTIME_CONFIG_SOURCE
)
assert '"http://supervisor/apps/self/info"' not in RUNTIME_CONFIG_SOURCE
assert "HTTPRedirectHandler" in SOURCE
assert "MAX_SUPERVISOR_RESPONSE_BYTES = 256 * 1024" in RUNTIME_CONFIG_SOURCE
assert "base64.b64decode(encoded, validate=True)" in SOURCE
assert "api_token_sha256" in SOURCE
assert "tls_private_key_b64" in SOURCE
assert 'source="supervisor_self_info"' in SOURCE
assert "tempfile.mkstemp" in SOURCE and "os.fchmod(descriptor, 0o600)" in SOURCE
assert "os.unlink(path)" in SOURCE
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
    'version: "0.2.1"',
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
assert "plaintext bearer token" in APP_DOCUMENTATION
assert (
    "0.2.0 HA OS DEPLOYMENT GATE FAILED CLOSED / 0.2.1 HOTFIX UNDER"
    in HA_APP_VALIDATION
)
assert "missing API permission for /apps/self/info" in HA_APP_VALIDATION
assert "http://supervisor/v2/apps/self/info" in HA_APP_VALIDATION
assert "changes only the Supervisor self-info endpoint" in HA_APP_VALIDATION
assert "Core-origin connectivity remains OPEN" in HA_APP_VALIDATION

for path in SOURCE_FILES:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in {"eval", "exec", "compile"}

print("PASS: immutable validated Debian runtime base")
print("PASS: root-owned mode-0555 source is set atomically by COPY")
print("PASS: explicit non-root UID/GID 2000:2000")
print("PASS: exactly three versioned read-only API routes")
print("PASS: TLS and constant-time bearer verifier required")
print("PASS: no CEZ hosts, browser control, commands, or sandbox weakening")
print("PASS: missing measurement is null, never synthesized zero")
print("PASS: immutable GHCR workflow retains SBOM and provenance")
print("PASS: isolated non-root offline container smoke profile")
print("PASS: PR validation workflow is read-only, pinned, and offline")
print("PASS: production App wrapper is prebuilt-image-only and least-privilege")
print("PASS: HA bootstrap stores only the API verifier and fails closed")
