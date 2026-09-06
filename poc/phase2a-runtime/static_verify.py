#!/usr/bin/env python3
"""Static safety checks for the disposable Phase 2A-1 artifact."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
RUNTIME_CONFIG_PATH = ROOT / "config.yaml"
REFERENCE_CONFIG_PATH = ROOT / "config.json"
DOCKERFILE = (ROOT / "Dockerfile").read_text(encoding="utf-8")
PROBE = (ROOT / "runtime_probe.py").read_text(encoding="utf-8")
LOCK = (ROOT / "requirements.lock").read_text(encoding="utf-8")

REQUIRED_MANIFEST_KEYS = {"name", "version", "slug", "description", "arch"}
ALLOWED_MANIFEST_KEYS = {
    *REQUIRED_MANIFEST_KEYS,
    "startup",
    "boot",
    "init",
    "stage",
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
    "journald",
    "ingress",
    "stdin",
    "options",
    "schema",
}
SECURITY_DEFAULTS = {
    "host_network": False,
    "host_pid": False,
    "host_ipc": False,
    "host_uts": False,
    "host_dbus": False,
    "hassio_api": False,
    "homeassistant_api": False,
    "auth_api": False,
    "docker_api": False,
    "full_access": False,
    "apparmor": True,
    "audio": False,
    "video": False,
    "gpio": False,
    "usb": False,
    "uart": False,
    "udev": False,
    "devicetree": False,
    "kernel_modules": False,
    "realtime": False,
    "journald": False,
    "ingress": False,
    "stdin": False,
    "ports": None,
    "map": [],
    "devices": [],
    "privileged": [],
}
COMPARISON_KEYS = {
    *REQUIRED_MANIFEST_KEYS,
    "startup",
    "boot",
    "init",
    "stage",
    *SECURITY_DEFAULTS,
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def parse_yaml_scalar(value: str) -> object:
    """Parse the deliberately small scalar subset used by config.yaml."""
    if value in {"true", "false"}:
        return value == "true"
    if value == "{}":
        return {}
    if value == "[]":
        return []
    if value.startswith('"'):
        return json.loads(value)
    require(bool(re.fullmatch(r"[A-Za-z0-9_./-]+", value)), f"Unsupported YAML scalar: {value!r}")
    return value


def load_runtime_yaml(path: Path) -> dict[str, object]:
    """Load the flat, dependency-free YAML subset used by the runtime manifest."""
    result: dict[str, object] = {}
    active_list: str | None = None

    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        require("\t" not in raw_line, f"Tabs are forbidden in YAML at line {line_number}")
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        if raw_line.startswith("  - "):
            require(active_list is not None, f"Unexpected list item at line {line_number}")
            current = result[active_list]
            require(isinstance(current, list), f"Invalid list at line {line_number}")
            current.append(parse_yaml_scalar(raw_line[4:].strip()))
            continue

        require(not raw_line.startswith(" "), f"Unexpected indentation at line {line_number}")
        match = re.fullmatch(r"([a-z_]+):(?: (.*))?", raw_line)
        require(match is not None, f"Unsupported YAML syntax at line {line_number}")
        key, raw_value = match.groups()
        require(key not in result, f"Duplicate YAML key: {key}")
        if raw_value is None:
            result[key] = []
            active_list = key
        else:
            result[key] = parse_yaml_scalar(raw_value)
            active_list = None

    return result


def effective_value(config: dict[str, object], key: str) -> object:
    return config.get(key, SECURITY_DEFAULTS.get(key))


def main() -> int:
    runtime_config = load_runtime_yaml(RUNTIME_CONFIG_PATH)
    reference_config = json.loads(REFERENCE_CONFIG_PATH.read_text(encoding="utf-8"))

    require(REQUIRED_MANIFEST_KEYS <= runtime_config.keys(), "Runtime manifest is missing a required Home Assistant key")
    require(not (runtime_config.keys() - ALLOWED_MANIFEST_KEYS), "Runtime manifest contains an unknown or unreviewed key")
    require(isinstance(runtime_config["name"], str), "name must be a string")
    require(isinstance(runtime_config["version"], str), "version must be a string")
    require(bool(re.fullmatch(r"[a-z0-9_]+", str(runtime_config["slug"]))), "slug must be URI friendly")
    require(isinstance(runtime_config["description"], str), "description must be a string")
    require(runtime_config["arch"] == ["amd64"], "PoC must target only amd64")
    require(runtime_config.get("startup") == "once", "PoC must use one-shot startup")
    require(runtime_config.get("boot") == "manual", "PoC must require manual start")
    require(runtime_config.get("init") is False, "Docker init must remain disabled for the direct probe process")
    require(runtime_config.get("stage") == "experimental", "PoC must remain experimental")
    require(runtime_config.get("options") == {}, "PoC must expose no runtime options")
    require(runtime_config.get("schema") == {}, "PoC must expose no option schema")

    for setting in ("hassio_api", "homeassistant_api", "auth_api", "docker_api", "full_access"):
        require(runtime_config.get(setting) is False, f"{setting} must be explicitly false")
    for setting in ("host_network", "host_pid", "host_ipc", "host_uts", "host_dbus"):
        require(runtime_config.get(setting) is False, f"{setting} must be explicitly false")
    for setting in ("audio", "video", "gpio", "usb", "uart", "udev", "devicetree", "kernel_modules"):
        require(runtime_config.get(setting) is False, f"{setting} must be explicitly false")
    for setting in ("realtime", "journald", "ingress"):
        require(runtime_config.get(setting) is False, f"{setting} must be explicitly false")
    require(runtime_config.get("apparmor") is True, "AppArmor must remain enabled")
    require("privileged" not in runtime_config, "No privileged capabilities may be requested")
    require("map" not in runtime_config, "No host directories may be mapped")
    require("devices" not in runtime_config, "No host devices may be mapped")
    require("ports" not in runtime_config, "No ports may be published")

    divergences = [
        key
        for key in sorted(COMPARISON_KEYS)
        if effective_value(runtime_config, key) != effective_value(reference_config, key)
    ]
    require(not divergences, f"config.json diverges from config.yaml for: {', '.join(divergences)}")

    require("USER 2000:2000" in DOCKERFILE, "Final image user must be non-root")
    require("addgroup -g 2000" in DOCKERFILE, "Runtime group GID 2000 must exist")
    require("adduser -u 2000" in DOCKERFILE, "Runtime user UID 2000 must exist")
    require("-o 0 -g 0 -m 0555 /home/phase2a /opt/phase2a" in DOCKERFILE, "Image-owned application paths must not be writable")
    require('tempfile.mkdtemp(prefix="phase2a-runtime-", dir="/tmp")' in PROBE, "Private runtime root required")
    require("chromium=152.0.7977.82-r0" in DOCKERFILE, "Chromium must be version pinned")
    require("chromium-chromedriver=152.0.7977.82-r0" in DOCKERFILE, "ChromeDriver must match")
    require("apk info -v" not in DOCKERFILE, "Package verification must not query unavailable APK indexes")
    require(
        "apk --no-network --repositories-file /dev/null info -e" in DOCKERFILE,
        "Package verification must query only the installed APK database",
    )
    require(
        '"chromium=152.0.7977.82-r0"' in DOCKERFILE,
        "Installed Chromium must satisfy the exact pinned version",
    )
    require(
        '"chromium-chromedriver=152.0.7977.82-r0"' in DOCKERFILE,
        "Installed ChromeDriver must satisfy the exact pinned version",
    )
    require("SE_OFFLINE=true" in DOCKERFILE, "Selenium Manager offline mode is required")
    require("SE_AVOID_BROWSER_DOWNLOAD=true" in DOCKERFILE, "Browser downloads must be disabled")
    require("SE_AVOID_STATS=true" in DOCKERFILE, "Selenium telemetry must be disabled")
    require("Service(executable_path=CHROMEDRIVER)" in PROBE, "Explicit packaged driver path required")
    for flag in (
        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--disable-seccomp-filter-sandbox",
        "--disable-gpu-sandbox",
    ):
        require(f'options.add_argument("{flag}")' not in PROBE, f"Forbidden launch flag present: {flag}")
    require("https://" not in PROBE and "http://" in PROBE, "Probe may navigate only to loopback HTTP")
    require("127.0.0.1" in PROBE, "Synthetic server must bind to loopback")
    require("--disable-background-networking" in PROBE, "Background browser networking must be disabled")
    require("--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1" in PROBE, "DNS must fail closed except loopback")
    require("Network.requestWillBeSent" in PROBE, "Observed browser requests must be audited")
    require("chmod 777" not in DOCKERFILE.lower(), "World-writable application directories forbidden")
    require("cez.cz" not in PROBE.lower(), "Runtime probe must not contact CEZ")

    packages = [line for line in LOCK.splitlines() if line and not line.startswith((" ", "#"))]
    require(bool(packages), "Dependency lock must not be empty")
    require(all("==" in line for line in packages), "Every Python dependency must be pinned")
    hashes = re.findall(r"--hash=sha256:[0-9a-f]{64}", LOCK)
    require(len(hashes) == len(packages), "Every pinned Python dependency needs one SHA-256 hash")

    print("SCHEMA-COMPATIBLE: config.yaml uses reviewed keys and values supported by the current Home Assistant App schema.")
    print("STATICALLY VERIFIED: config.yaml is authoritative and security-relevant values match config.json.")
    print("STATICALLY VERIFIED: PoC requests no API, host namespace, host mount, device, port, full access, or additional capability.")
    print("STATICALLY VERIFIED: final runtime user is UID/GID 2000:2000.")
    print("STATICALLY VERIFIED: image paths are non-writable and runtime paths are private temporary directories.")
    print("STATICALLY VERIFIED: no forbidden sandbox flag is passed to Chromium.")
    print("STATICALLY VERIFIED: browser/driver versions match and Selenium wheels are hash locked.")
    print("STATICALLY VERIFIED: installed APK versions are checked without repository indexes or network access.")
    print("STATICALLY VERIFIED: runtime executable downloads and Selenium telemetry are disabled.")
    print("STATICALLY VERIFIED: probe target is a loopback synthetic page; no CEZ endpoint is present.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as error:
        print(f"STATIC VERIFICATION FAILED: {error}", file=sys.stderr)
        raise SystemExit(1)
