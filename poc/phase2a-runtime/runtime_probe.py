#!/usr/bin/env python3
"""Disposable Phase 2A-1 Chromium runtime probe. This is not Collector code."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit


CHROMIUM = "/usr/bin/chromium"
CHROMEDRIVER = "/usr/bin/chromedriver"
EXPECTED_UID = 2000
EXPECTED_GID = 2000
DOWNLOAD_BYTES = b"phase2a synthetic download\n"
DOWNLOAD_SHA256 = hashlib.sha256(DOWNLOAD_BYTES).hexdigest()
FORBIDDEN_FLAGS = (
    "--no-sandbox",
    "--disable-setuid-sandbox",
    "--disable-seccomp-filter-sandbox",
    "--disable-gpu-sandbox",
)


class ProbeFailure(RuntimeError):
    pass


class SyntheticHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/":
            body = (
                b"<!doctype html><title>Phase 2A synthetic test</title>"
                b"<main id='probe'>synthetic-ok</main>"
                b"<a id='download' href='/download'>download</a>"
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/download":
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", 'attachment; filename="synthetic.txt"')
            self.send_header("Content-Length", str(len(DOWNLOAD_BYTES)))
            self.end_headers()
            self.wfile.write(DOWNLOAD_BYTES)
            return
        self.send_error(404)

    def log_message(self, _format: str, *_args: object) -> None:
        return


def command_output(*args: str) -> str:
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT).strip()


def os_release() -> dict[str, str]:
    values: dict[str, str] = {}
    for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value.strip('"')
    return values


def proc_status(pid: int) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in Path(f"/proc/{pid}/status").read_text(encoding="utf-8").splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            values[key] = value.strip()
    return values


def proc_cmdline(pid: int) -> list[str]:
    raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    return [part.decode("utf-8", "replace") for part in raw.split(b"\0") if part]


def proc_cpu_ticks(pid: int) -> int:
    fields = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8").split()
    return int(fields[13]) + int(fields[14])


def namespace_links(pid: int) -> dict[str, str]:
    links: dict[str, str] = {}
    for name in ("user", "pid", "net", "mnt", "ipc"):
        try:
            links[name] = os.readlink(f"/proc/{pid}/ns/{name}")
        except OSError as error:
            links[name] = f"unavailable: {error}"
    return links


def all_processes() -> dict[int, dict[str, Any]]:
    processes: dict[int, dict[str, Any]] = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        try:
            status = proc_status(pid)
            processes[pid] = {
                "pid": pid,
                "ppid": int(status.get("PPid", "0")),
                "name": status.get("Name", ""),
                "cmdline": proc_cmdline(pid),
                "status": status,
                "cpu_ticks": proc_cpu_ticks(pid),
            }
        except (FileNotFoundError, PermissionError, ProcessLookupError, ValueError):
            continue
    return processes


def descendants(root_pid: int, snapshot: dict[int, dict[str, Any]]) -> set[int]:
    result = {root_pid}
    changed = True
    while changed:
        changed = False
        for pid, process in snapshot.items():
            if process["ppid"] in result and pid not in result:
                result.add(pid)
                changed = True
    return result


def directory_bytes(path: Path) -> int:
    total = 0
    for item in path.rglob("*"):
        try:
            if item.is_file():
                total += item.stat().st_size
        except FileNotFoundError:
            continue
    return total


def filesystem_usage(path: str) -> dict[str, int]:
    usage = shutil.disk_usage(path)
    return {"total_bytes": usage.total, "used_bytes": usage.used, "free_bytes": usage.free}


def process_evidence(process: dict[str, Any]) -> dict[str, Any]:
    pid = process["pid"]
    status = process["status"]
    uid_parts = [int(value) for value in status.get("Uid", "-1 -1 -1 -1").split()]
    gid_parts = [int(value) for value in status.get("Gid", "-1 -1 -1 -1").split()]
    return {
        "pid": pid,
        "ppid": process["ppid"],
        "name": process["name"],
        "cmdline": process["cmdline"],
        "real_uid": uid_parts[0],
        "effective_uid": uid_parts[1],
        "real_gid": gid_parts[0],
        "effective_gid": gid_parts[1],
        "seccomp": int(status.get("Seccomp", "-1")),
        "no_new_privs": int(status.get("NoNewPrivs", "-1")),
        "nspid": [int(value) for value in status.get("NSpid", "").split()],
        "vm_rss_kib": int(status.get("VmRSS", "0 kB").split()[0]),
        "cpu_ticks": process["cpu_ticks"],
        "namespaces": namespace_links(pid),
    }


def wait_for_download(directory: Path, timeout: float = 10.0) -> Path:
    deadline = time.monotonic() + timeout
    target = directory / "synthetic.txt"
    while time.monotonic() < deadline:
        if target.exists() and target.read_bytes() == DOWNLOAD_BYTES:
            return target
        time.sleep(0.1)
    raise ProbeFailure("Synthetic download did not complete with the expected bytes")


def wait_for_cleanup(pids: set[int], timeout: float = 10.0) -> list[int]:
    deadline = time.monotonic() + timeout
    remaining = sorted(pid for pid in pids if Path(f"/proc/{pid}").exists())
    while remaining and time.monotonic() < deadline:
        time.sleep(0.1)
        remaining = sorted(pid for pid in pids if Path(f"/proc/{pid}").exists())
    return remaining


def check_forbidden_arguments(processes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for process in processes:
        for argument in process["cmdline"]:
            if argument in FORBIDDEN_FLAGS:
                matches.append({"pid": process["pid"], "argument": argument})
    return matches


def sandbox_page_result(text: str) -> dict[str, Any]:
    layer1 = bool(
        re.search(r"Layer 1 Sandbox\s+(?:Namespace|SUID)", text, re.IGNORECASE)
        or re.search(r"(?:SUID|Namespace) Sandbox\s+Yes", text, re.IGNORECASE)
    )
    seccomp = bool(re.search(r"Seccomp-BPF sandbox\s+Yes", text, re.IGNORECASE))
    return {"layer1_enabled": layer1, "seccomp_bpf_enabled": seccomp, "body": text}


def run_browser_case(
    name: str,
    action: Callable[[Any, str, Path], dict[str, Any]],
    runtime_root: Path,
) -> dict[str, Any]:
    from selenium import webdriver
    from selenium.webdriver.chrome.service import Service

    result: dict[str, Any] = {"name": name, "passed": False}
    tracked_pids: set[int] = set()
    driver = None
    with tempfile.TemporaryDirectory(prefix=f"{name}-", dir=runtime_root) as root:
        root_path = Path(root)
        profile_dir = root_path / "profile"
        download_dir = root_path / "download"
        profile_dir.mkdir(mode=0o700)
        download_dir.mkdir(mode=0o700)

        server = ThreadingHTTPServer(("127.0.0.1", 0), SyntheticHandler)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        base_url = f"http://127.0.0.1:{server.server_port}"

        options = webdriver.ChromeOptions()
        options.binary_location = CHROMIUM
        options.add_argument("--headless=new")
        options.add_argument("--window-size=1280,720")
        options.add_argument("--disable-background-networking")
        options.add_argument("--disable-component-update")
        options.add_argument("--no-first-run")
        options.add_argument("--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1")
        options.add_argument(f"--user-data-dir={profile_dir}")
        options.set_capability("goog:loggingPrefs", {"performance": "ALL"})
        options.add_experimental_option(
            "prefs",
            {
                "download.default_directory": str(download_dir),
                "download.prompt_for_download": False,
                "safebrowsing.enabled": True,
            },
        )
        service = Service(executable_path=CHROMEDRIVER)
        started = time.monotonic()
        try:
            driver = webdriver.Chrome(service=service, options=options)
            startup_seconds = time.monotonic() - started
            driver_pid = service.process.pid
            time.sleep(0.5)
            snapshot = all_processes()
            tracked_pids = descendants(driver_pid, snapshot)
            browser_processes = [snapshot[pid] for pid in sorted(tracked_pids) if pid in snapshot]
            cpu_ticks_before = sum(process["cpu_ticks"] for process in browser_processes)
            action_started = time.monotonic()
            action_result = action(driver, base_url, download_dir)
            action_seconds = time.monotonic() - action_started
            final_snapshot = all_processes()
            tracked_pids.update(descendants(driver_pid, final_snapshot))
            final_processes = [
                final_snapshot[pid] for pid in sorted(tracked_pids) if pid in final_snapshot
            ]
            cpu_ticks_after = sum(process["cpu_ticks"] for process in final_processes)
            clock_ticks = os.sysconf("SC_CLK_TCK")
            result.update(
                {
                    "startup_seconds": round(startup_seconds, 3),
                    "action_seconds": round(action_seconds, 3),
                    "process_count": len(final_processes),
                    "processes": [process_evidence(process) for process in final_processes],
                    "forbidden_arguments": check_forbidden_arguments(final_processes),
                    "action": action_result,
                    "observed_cpu_seconds_during_action": round(
                        max(0, cpu_ticks_after - cpu_ticks_before) / clock_ticks, 3
                    ),
                    "profile_bytes_before_cleanup": directory_bytes(profile_dir),
                    "download_bytes_before_cleanup": directory_bytes(download_dir),
                    "tmp_filesystem_after_action": filesystem_usage("/tmp"),
                    "dev_shm_after_action": filesystem_usage("/dev/shm"),
                }
            )
            result["peak_observed_rss_kib"] = sum(
                process["vm_rss_kib"] for process in result["processes"]
            )
            result["passed"] = not result["forbidden_arguments"]
        except Exception as error:  # evidence must survive every Selenium failure
            result["error"] = {"type": type(error).__name__, "message": str(error)}
        finally:
            if driver is not None:
                try:
                    driver.quit()
                except Exception as error:
                    result["quit_error"] = {"type": type(error).__name__, "message": str(error)}
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=2)
            result["orphan_pids_after_cleanup"] = wait_for_cleanup(tracked_pids)
            if result["orphan_pids_after_cleanup"]:
                result["passed"] = False
    return result


def core_action(driver: Any, base_url: str, download_dir: Path) -> dict[str, Any]:
    from selenium.webdriver.common.by import By

    driver.get(base_url)
    dom_value = driver.find_element(By.ID, "probe").text
    if dom_value != "synthetic-ok":
        raise ProbeFailure(f"Unexpected DOM value: {dom_value!r}")
    driver.find_element(By.ID, "download").click()
    downloaded = wait_for_download(download_dir)
    driver.get("chrome://sandbox")
    sandbox_text = driver.find_element(By.TAG_NAME, "body").text
    sandbox = sandbox_page_result(sandbox_text)
    observed_urls: set[str] = set()
    for entry in driver.get_log("performance"):
        message = json.loads(entry["message"])["message"]
        if message.get("method") == "Network.requestWillBeSent":
            observed_urls.add(message["params"]["request"]["url"])
    disallowed_urls = []
    for url in sorted(observed_urls):
        parsed = urlsplit(url)
        if parsed.scheme == "http" and parsed.hostname == "127.0.0.1":
            continue
        if parsed.scheme in {"about", "blob", "chrome", "data", "devtools"}:
            continue
        disallowed_urls.append(url)
    if disallowed_urls:
        raise ProbeFailure(f"Browser observed non-synthetic request URLs: {disallowed_urls!r}")
    return {
        "navigation": True,
        "dom_access": True,
        "download": {
            "path_basename": downloaded.name,
            "mode": oct(downloaded.stat().st_mode & 0o777),
            "sha256": hashlib.sha256(downloaded.read_bytes()).hexdigest(),
            "expected_sha256": DOWNLOAD_SHA256,
        },
        "sandbox_page": sandbox,
        "observed_request_urls": sorted(observed_urls),
        "non_synthetic_request_urls": disallowed_urls,
    }


def exception_action(driver: Any, base_url: str, _download_dir: Path) -> dict[str, Any]:
    from selenium.common.exceptions import NoSuchElementException
    from selenium.webdriver.common.by import By

    driver.get(base_url)
    try:
        driver.find_element(By.ID, "intentionally-missing")
    except NoSuchElementException:
        return {"expected_selenium_exception_observed": True}
    raise ProbeFailure("Expected Selenium exception was not raised")


def timeout_action(driver: Any, _base_url: str, _download_dir: Path) -> dict[str, Any]:
    from selenium.common.exceptions import TimeoutException

    driver.set_script_timeout(1)
    try:
        driver.execute_async_script("void 0;")
    except TimeoutException:
        return {"expected_timeout_observed": True}
    raise ProbeFailure("Expected Selenium script timeout was not raised")


def evaluate_sandbox(core: dict[str, Any]) -> dict[str, Any]:
    processes = core.get("processes", [])
    chromium_processes = [
        process for process in processes if any("chromium" in arg for arg in process.get("cmdline", []))
    ]
    renderers = [
        process for process in chromium_processes if "--type=renderer" in process.get("cmdline", [])
    ]
    all_non_root = bool(chromium_processes) and all(
        process["effective_uid"] == EXPECTED_UID and process["effective_gid"] == EXPECTED_GID
        for process in chromium_processes
    )
    renderer_seccomp = bool(renderers) and all(
        process["seccomp"] == 2 and process["no_new_privs"] == 1 for process in renderers
    )
    page = core.get("action", {}).get("sandbox_page", {})
    verified = bool(
        core.get("passed")
        and not core.get("forbidden_arguments")
        and all_non_root
        and renderer_seccomp
        and page.get("layer1_enabled")
        and page.get("seccomp_bpf_enabled")
    )
    return {
        "verified": verified,
        "all_chromium_processes_uid_gid_2000": all_non_root,
        "renderer_count": len(renderers),
        "all_renderers_seccomp_filter_and_no_new_privs": renderer_seccomp,
        "chrome_sandbox_page_layer1": bool(page.get("layer1_enabled")),
        "chrome_sandbox_page_seccomp_bpf": bool(page.get("seccomp_bpf_enabled")),
        "forbidden_arguments_absent": not core.get("forbidden_arguments"),
    }


def main() -> int:
    started = time.monotonic()
    result: dict[str, Any] = {
        "artifact": "DISPOSABLE PHASE 2A-1 POC; NOT PRODUCTION CODE",
        "environment": {
            "os_release": os_release(),
            "kernel": platform.uname()._asdict(),
            "machine": platform.machine(),
            "uid": os.getuid(),
            "euid": os.geteuid(),
            "gid": os.getgid(),
            "egid": os.getegid(),
            "ha_os_version": "NOT PROVIDED; record from target UI",
            "supervisor_version": "NOT PROVIDED; record from target UI",
        },
        "versions": {
            "chromium": command_output(CHROMIUM, "--version"),
            "chromedriver": command_output(CHROMEDRIVER, "--version"),
            "chromium_apk": command_output("apk", "info", "-v", "chromium"),
            "chromedriver_apk": command_output("apk", "info", "-v", "chromium-chromedriver"),
        },
        "filesystem": {
            "tmp": filesystem_usage("/tmp"),
            "dev_shm": filesystem_usage("/dev/shm"),
            "temporary_directories_mode": "0700",
            "persistent_storage_used": False,
        },
        "required_linux_capabilities_declared": [],
    }

    if (os.geteuid(), os.getegid()) != (EXPECTED_UID, EXPECTED_GID):
        result["fatal"] = "Probe is not running as required UID/GID 2000:2000"
        print(json.dumps(result, indent=2, sort_keys=True), flush=True)
        return 1

    runtime_root = Path(tempfile.mkdtemp(prefix="phase2a-runtime-", dir="/tmp"))
    for directory_name, environment_name in (
        ("home", "HOME"),
        ("cache", "XDG_CACHE_HOME"),
        ("config", "XDG_CONFIG_HOME"),
        ("runtime", "XDG_RUNTIME_DIR"),
    ):
        directory = runtime_root / directory_name
        directory.mkdir(mode=0o700)
        os.environ[environment_name] = str(directory)
    result["filesystem"]["runtime_root"] = str(runtime_root)
    try:
        result["cases"] = {
            "normal": run_browser_case("normal", core_action, runtime_root),
            "selenium_exception": run_browser_case("exception", exception_action, runtime_root),
            "timeout": run_browser_case("timeout", timeout_action, runtime_root),
        }
        result["filesystem"]["runtime_root_bytes_before_cleanup"] = directory_bytes(runtime_root)
    finally:
        shutil.rmtree(runtime_root, ignore_errors=False)
        result["filesystem"]["runtime_root_removed"] = not runtime_root.exists()
    result["sandbox"] = evaluate_sandbox(result["cases"]["normal"])
    result["cleanup_verified"] = all(
        case.get("passed") and not case.get("orphan_pids_after_cleanup")
        for case in result["cases"].values()
    )
    result["elapsed_seconds"] = round(time.monotonic() - started, 3)
    result["security_deviations"] = []
    result["passed"] = bool(result["sandbox"]["verified"] and result["cleanup_verified"])
    if not result["sandbox"]["verified"]:
        result["blocking_finding"] = "Required Chromium sandbox was not positively verified"
    print(json.dumps(result, indent=2, sort_keys=True), flush=True)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, lambda _signum, _frame: sys.exit(143))
    raise SystemExit(main())
