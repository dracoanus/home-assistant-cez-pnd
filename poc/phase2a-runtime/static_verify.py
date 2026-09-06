#!/usr/bin/env python3
"""Static safety checks for the disposable Phase 2A-1 artifact."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
CONFIG = json.loads((ROOT / "config.json").read_text(encoding="utf-8"))
DOCKERFILE = (ROOT / "Dockerfile").read_text(encoding="utf-8")
PROBE = (ROOT / "runtime_probe.py").read_text(encoding="utf-8")
LOCK = (ROOT / "requirements.lock").read_text(encoding="utf-8")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    require(CONFIG["arch"] == ["amd64"], "PoC must target only amd64")
    for setting in ("hassio_api", "homeassistant_api", "auth_api", "docker_api", "full_access"):
        require(CONFIG.get(setting) is False, f"{setting} must be explicitly false")
    require("privileged" not in CONFIG, "No privileged capabilities may be requested")
    require("map" not in CONFIG, "No host directories may be mapped")
    require("ports" not in CONFIG and "host_network" not in CONFIG, "No ports or host network")

    require("USER 2000:2000" in DOCKERFILE, "Final image user must be non-root")
    require("-o 0 -g 0 -m 0555 /home/phase2a /opt/phase2a" in DOCKERFILE, "Image-owned application paths must not be writable")
    require('tempfile.mkdtemp(prefix="phase2a-runtime-", dir="/tmp")' in PROBE, "Private runtime root required")
    require("chromium=152.0.7977.82-r0" in DOCKERFILE, "Chromium must be version pinned")
    require("chromium-chromedriver=152.0.7977.82-r0" in DOCKERFILE, "ChromeDriver must match")
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

    print("STATICALLY VERIFIED: PoC requests no API, host mount, port, full access, or capability.")
    print("STATICALLY VERIFIED: final runtime user is UID/GID 2000:2000.")
    print("STATICALLY VERIFIED: image paths are non-writable and runtime paths are private temporary directories.")
    print("STATICALLY VERIFIED: no forbidden sandbox flag is passed to Chromium.")
    print("STATICALLY VERIFIED: browser/driver versions match and Selenium wheels are hash locked.")
    print("STATICALLY VERIFIED: runtime executable downloads and Selenium telemetry are disabled.")
    print("STATICALLY VERIFIED: probe target is a loopback synthetic page; no CEZ endpoint is present.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as error:
        print(f"STATIC VERIFICATION FAILED: {error}", file=sys.stderr)
        raise SystemExit(1)
