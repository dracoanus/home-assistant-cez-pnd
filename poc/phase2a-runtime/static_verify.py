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


def run_cmdline_regression_tests() -> None:
    namespace: dict[str, object] = {
        "__name__": "phase2a_runtime_probe_static_test",
        "__file__": str(ROOT / "runtime_probe.py"),
    }
    exec(compile(PROBE, str(ROOT / "runtime_probe.py"), "exec"), namespace)
    parse = namespace["parse_proc_cmdline"]
    process_type = namespace["process_type"]
    check_internal = namespace["check_internal_zygote_arguments"]
    check_forbidden = namespace["check_forbidden_arguments"]
    evaluate = namespace["evaluate_sandbox"]
    forbidden_flags = namespace["FORBIDDEN_FLAGS"]

    def process(raw: bytes, pid: int = 1) -> dict[str, object]:
        parsed = parse(raw)
        return {
            "pid": pid,
            "name": "chromium",
            "cmdline": parsed["fields"],
            "cmdline_switches": parsed["switches"],
            "cmdline_layout": parsed["layout"],
            "cmdline_source": parsed["source"],
            "cmdline_nul_terminated": parsed["nul_terminated"],
            "cmdline_decode_lossless": parsed["decode_lossless"],
            "cmdline_complete": parsed["complete"],
            "effective_uid": 2000,
            "effective_gid": 2000,
            "seccomp": 2,
            "no_new_privs": 1,
            "namespaces": {"user": "user:[2]", "pid": "pid:[2]", "net": "net:[2]"},
        }

    normal = process(b"/usr/lib/chromium/chromium\0--type=renderer\0--foo=bar\0")
    require(normal["cmdline_layout"] == "nul_separated_argv", "Normal NUL argv layout lost")
    require(normal["cmdline_complete"] is True, "Normal NUL argv marked incomplete")
    require(process_type(normal) == "renderer", "Renderer missing from normal NUL argv")

    single = process(
        b"/usr/lib/chromium/chromium --type=renderer --foo=bar\0", pid=2
    )
    require(single["cmdline_layout"] == "single_process_title", "Single process title not identified")
    require(single["cmdline_nul_terminated"] is True, "Single process title termination lost")
    require(single["cmdline_complete"] is True, "Valid single process title marked incomplete")
    require(process_type(single) == "renderer", "Renderer missing from flattened process title")

    malformed = process(
        b"/usr/lib/chromium/chromium --type=renderer --no-sandbox", pid=6
    )
    require(malformed["cmdline_nul_terminated"] is False, "Malformed termination not retained")
    require(malformed["cmdline_complete"] is False, "Truncated cmdline marked complete")
    require(bool(check_forbidden([malformed])), "Forbidden flag escaped malformed process-title scan")
    for index, flag in enumerate(forbidden_flags, 10):
        forbidden_process = process(
            f"/usr/lib/chromium/chromium --type=renderer {flag}\0".encode(),
            pid=index,
        )
        require(
            check_forbidden([forbidden_process])
            == [{"pid": index, "argument": flag}],
            f"Forbidden switch escaped process-title scan: {flag}",
        )

    zygote = process(
        b"/usr/lib/chromium/chromium --type=zygote --no-zygote-sandbox\0", pid=3
    )
    require(process_type(zygote) == "zygote", "Zygote missing from flattened process title")
    require(
        not check_internal([zygote])["unexpected_non_zygote_pids"],
        "Internal zygote flag rejected on a real zygote",
    )
    renderer_with_zygote_flag = process(
        b"/usr/lib/chromium/chromium\0--type=renderer\0--no-zygote-sandbox\0",
        pid=4,
    )
    require(
        check_internal([renderer_with_zygote_flag])["unexpected_non_zygote_pids"] == [4],
        "Internal zygote flag must fail closed on a renderer",
    )

    browser = process(b"/usr/lib/chromium/chromium\0", pid=5)
    browser["seccomp"] = 0
    browser["no_new_privs"] = 0
    browser["namespaces"] = {"user": "user:[1]", "pid": "pid:[1]", "net": "net:[1]"}

    def case(children: list[dict[str, object]], forbidden: list[dict[str, object]] | None = None) -> dict[str, object]:
        return {
            "processes": [browser, *children],
            "process_evidence_stage": "static_regression",
            "forbidden_arguments": forbidden or [],
        }

    require(evaluate({"case": case([normal, zygote])})["verified"], "Valid sandbox evidence rejected")
    require(
        not evaluate({"case": case([malformed])})["verified"],
        "Sandbox accepted malformed non-NUL-terminated process evidence",
    )
    invalid_utf8 = process(b"/usr/lib/chromium/chromium\0--type=renderer\xff\0", pid=7)
    require(invalid_utf8["cmdline_complete"] is False, "Invalid UTF-8 cmdline marked complete")
    require(
        not evaluate({"case": case([invalid_utf8])})["verified"],
        "Sandbox accepted lossy command-line evidence",
    )
    non_authoritative = dict(normal)
    non_authoritative.pop("cmdline_source")
    require(
        not evaluate({"case": case([non_authoritative])})["verified"],
        "Sandbox accepted command-line evidence without raw procfs provenance",
    )
    for key, value in (
        ("seccomp", 0),
        ("no_new_privs", 0),
        ("namespaces", browser["namespaces"]),
    ):
        invalid = dict(normal)
        invalid[key] = value
        require(not evaluate({"case": case([invalid])})["verified"], f"Sandbox did not fail closed for {key}")
    require(
        not evaluate({"case": case([renderer_with_zygote_flag])})["verified"],
        "Sandbox accepted a renderer carrying the internal zygote flag",
    )


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
    require("executable_path=CHROMEDRIVER" in PROBE, "Explicit packaged driver path required")
    for flag in (
        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--disable-seccomp-filter-sandbox",
        "--disable-gpu-sandbox",
    ):
        require(f'options.add_argument("{flag}")' not in PROBE, f"Forbidden launch flag present: {flag}")
    require(
        'options.add_argument("--no-zygote-sandbox")' not in PROBE,
        "The internal zygote flag must never be supplied by the probe",
    )
    require(
        'INTERNAL_ZYGOTE_FLAG = "--no-zygote-sandbox"' in PROBE,
        "Internally generated zygote flags must be identified explicitly",
    )
    require(
        '"unexpected_non_zygote_pids"' in PROBE,
        "The internal zygote flag must fail closed if observed on another process type",
    )
    require("driver.get(\"chrome://sandbox\")" not in PROBE, "Internal page navigation must not disturb renderer evidence")
    require("record_process_snapshot" in PROBE, "Process evidence must survive action failures")
    require("force_cleanup" in PROBE, "Non-privileged TERM/KILL cleanup fallback is required")
    require("bounded_cleanup_call" in PROBE, "WebDriver and service shutdown must be time bounded")
    require("os.waitpid(-1, os.WNOHANG)" in PROBE, "PID 1 must reap adopted browser children")
    require('evaluate_sandbox(result["cases"])' in PROBE, "Sandbox evaluation must consider every case")
    require("peak_observed_aggregate_pss_kib" in PROBE, "PSS must accompany aggregate RSS")
    require('"pss_complete"' in PROBE, "Incomplete PSS evidence must be reported explicitly")
    require("verify_installed_apk(\"chromium=152.0.7977.82-r0\")" in PROBE, "Runtime Chromium package check must be exact and offline")
    require(
        'verify_installed_apk(\n                "chromium-chromedriver=152.0.7977.82-r0"' in PROBE,
        "Runtime ChromeDriver package check must be exact and offline",
    )
    require("https://" not in PROBE and "http://" in PROBE, "Probe may navigate only to loopback HTTP")
    require("127.0.0.1" in PROBE, "Synthetic server must bind to loopback")
    require("--disable-background-networking" in PROBE, "Background browser networking must be disabled")
    require("--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1" in PROBE, "DNS must fail closed except loopback")
    require("Network.requestWillBeSent" in PROBE, "Observed browser requests must be audited")
    require("chmod 777" not in DOCKERFILE.lower(), "World-writable application directories forbidden")
    require("cez.cz" not in PROBE.lower(), "Runtime probe must not contact CEZ")

    run_cmdline_regression_tests()

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
    print("REGRESSION TESTED: NUL argv, flattened process titles, renderer/zygote classification and fail-closed policy.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as error:
        print(f"STATIC VERIFICATION FAILED: {error}", file=sys.stderr)
        raise SystemExit(1)
