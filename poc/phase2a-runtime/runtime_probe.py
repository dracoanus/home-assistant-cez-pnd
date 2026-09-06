#!/usr/bin/env python3
"""Disposable Phase 2A-1 Chromium runtime probe. This is not Collector code."""

from __future__ import annotations

import hashlib
import json
import os
import platform
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
INTERNAL_ZYGOTE_FLAG = "--no-zygote-sandbox"
PROCESS_DISCOVERY_TIMEOUT = 5.0
GRACEFUL_CLEANUP_TIMEOUT = 5.0
FORCED_CLEANUP_TIMEOUT = 5.0
API_CLEANUP_TIMEOUT = 5.0


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


def verify_installed_apk(package_constraint: str) -> str:
    subprocess.run(
        [
            "apk",
            "--no-network",
            "--repositories-file",
            "/dev/null",
            "info",
            "-e",
            package_constraint,
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    return package_constraint


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
    fields = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8").rsplit(")", 1)[1].split()
    return int(fields[11]) + int(fields[12])


def proc_start_time_ticks(pid: int) -> int:
    fields = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8").rsplit(")", 1)[1].split()
    return int(fields[19])


def proc_pss_kib(pid: int) -> int | None:
    try:
        for line in Path(f"/proc/{pid}/smaps_rollup").read_text(encoding="utf-8").splitlines():
            if line.startswith("Pss:"):
                return int(line.split()[1])
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        return None
    return None


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
                "start_time_ticks": proc_start_time_ticks(pid),
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


def text_tail(path: Path, maximum_bytes: int = 65536) -> str:
    try:
        with path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - maximum_bytes))
            return handle.read().decode("utf-8", "replace")
    except FileNotFoundError:
        return ""


def bounded_cleanup_call(operation: Callable[[], None]) -> dict[str, Any]:
    outcome: dict[str, Any] = {"completed": False}
    finished = threading.Event()

    def invoke() -> None:
        try:
            operation()
            outcome["completed"] = True
        except Exception as error:
            outcome["error"] = {"type": type(error).__name__, "message": str(error)}
        finally:
            finished.set()

    thread = threading.Thread(target=invoke, daemon=True)
    thread.start()
    if not finished.wait(API_CLEANUP_TIMEOUT):
        outcome["timed_out"] = True
    return outcome


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
        "start_time_ticks": process["start_time_ticks"],
        "pss_kib": proc_pss_kib(pid),
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


def is_chromium_process(process: dict[str, Any]) -> bool:
    return any("chromium" in argument for argument in process.get("cmdline", []))


def is_chromedriver_process(process: dict[str, Any]) -> bool:
    return any("chromedriver" in argument for argument in process.get("cmdline", []))


def browser_identities(snapshot: dict[int, dict[str, Any]]) -> dict[int, int]:
    return {
        pid: process["start_time_ticks"]
        for pid, process in snapshot.items()
        if is_chromium_process(process) or is_chromedriver_process(process)
    }


def same_process(pid: int, start_time_ticks: int) -> bool:
    try:
        return proc_start_time_ticks(pid) == start_time_ticks
    except (FileNotFoundError, PermissionError, ProcessLookupError, ValueError):
        return False


def reap_children() -> list[int]:
    reaped: list[int] = []
    while True:
        try:
            pid, _status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            break
        if pid == 0:
            break
        reaped.append(pid)
    return reaped


def case_processes(
    driver_pid: int | None,
    baseline: dict[int, int],
    tracked: dict[int, int],
) -> tuple[dict[int, dict[str, Any]], dict[int, dict[str, Any]]]:
    snapshot = all_processes()
    selected: set[int] = set()
    if driver_pid is not None and driver_pid in snapshot:
        selected.update(descendants(driver_pid, snapshot))
    for pid, process in snapshot.items():
        if not (is_chromium_process(process) or is_chromedriver_process(process)):
            continue
        if baseline.get(pid) != process["start_time_ticks"]:
            selected.add(pid)
    for pid, start_time_ticks in tracked.items():
        process = snapshot.get(pid)
        if process and process["start_time_ticks"] == start_time_ticks:
            selected.add(pid)
    current = {pid: snapshot[pid] for pid in selected if pid in snapshot}
    tracked.update({pid: process["start_time_ticks"] for pid, process in current.items()})
    return snapshot, current


def record_process_snapshot(
    result: dict[str, Any],
    stage: str,
    driver_pid: int | None,
    baseline: dict[int, int],
    tracked: dict[int, int],
) -> list[dict[str, Any]]:
    _snapshot, current = case_processes(driver_pid, baseline, tracked)
    evidence = [process_evidence(current[pid]) for pid in sorted(current)]
    result.setdefault("process_snapshots", []).append(
        {
            "stage": stage,
            "process_count": len(evidence),
            "renderer_count": sum("--type=renderer" in item["cmdline"] for item in evidence),
            "aggregate_rss_kib": sum(item["vm_rss_kib"] for item in evidence),
            "aggregate_pss_kib": sum(item["pss_kib"] or 0 for item in evidence),
            "pss_complete": all(item["pss_kib"] is not None for item in evidence),
            "pss_unavailable_pids": [
                item["pid"] for item in evidence if item["pss_kib"] is None
            ],
            "processes": evidence,
        }
    )
    return evidence


def wait_for_renderer_snapshot(
    result: dict[str, Any],
    driver_pid: int,
    baseline: dict[int, int],
    tracked: dict[int, int],
) -> list[dict[str, Any]]:
    deadline = time.monotonic() + PROCESS_DISCOVERY_TIMEOUT
    evidence: list[dict[str, Any]] = []
    while time.monotonic() < deadline:
        evidence = record_process_snapshot(result, "startup", driver_pid, baseline, tracked)
        if any("--type=renderer" in process["cmdline"] for process in evidence):
            return evidence
        result["process_snapshots"].pop()
        time.sleep(0.1)
    return record_process_snapshot(result, "startup_timeout", driver_pid, baseline, tracked)


def remaining_processes(tracked: dict[int, int]) -> list[int]:
    return sorted(pid for pid, start_time in tracked.items() if same_process(pid, start_time))


def signal_tracked_processes(tracked: dict[int, int], signal_number: int) -> list[int]:
    refused: list[int] = []
    snapshot = all_processes()
    for pid in remaining_processes(tracked):
        process = snapshot.get(pid)
        if process is None:
            continue
        uid_parts = [int(value) for value in process["status"].get("Uid", "-1 -1").split()]
        if len(uid_parts) < 2 or uid_parts[1] != EXPECTED_UID:
            refused.append(pid)
            continue
        try:
            os.kill(pid, signal_number)
        except ProcessLookupError:
            continue
    return refused


def wait_and_reap(tracked: dict[int, int], timeout: float) -> list[int]:
    deadline = time.monotonic() + timeout
    remaining = remaining_processes(tracked)
    while remaining and time.monotonic() < deadline:
        reap_children()
        time.sleep(0.1)
        remaining = remaining_processes(tracked)
    reap_children()
    return remaining_processes(tracked)


def force_cleanup(
    driver_pid: int | None,
    baseline: dict[int, int],
    tracked: dict[int, int],
) -> dict[str, Any]:
    _snapshot, current = case_processes(driver_pid, baseline, tracked)
    before = sorted(current)
    refused_term = signal_tracked_processes(tracked, signal.SIGTERM)
    after_term = wait_and_reap(tracked, GRACEFUL_CLEANUP_TIMEOUT)
    _snapshot, _current = case_processes(driver_pid, baseline, tracked)
    after_term = remaining_processes(tracked)
    refused_kill: list[int] = []
    if after_term:
        refused_kill = signal_tracked_processes(tracked, signal.SIGKILL)
    wait_and_reap(tracked, FORCED_CLEANUP_TIMEOUT)
    _snapshot, _current = case_processes(driver_pid, baseline, tracked)
    remaining = wait_and_reap(tracked, 0)
    return {
        "pids_before_forced_cleanup": before,
        "pids_after_sigterm": after_term,
        "sigterm_refused_unexpected_uid": refused_term,
        "sigkill_refused_unexpected_uid": refused_kill,
        "orphan_pids_after_cleanup": remaining,
        "verified": not remaining and not refused_term and not refused_kill,
    }


def check_forbidden_arguments(processes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for process in processes:
        for argument in process["cmdline"]:
            for flag in FORBIDDEN_FLAGS:
                if argument == flag or argument.startswith(f"{flag}="):
                    matches.append({"pid": process["pid"], "argument": argument})
    return matches


def check_internal_zygote_arguments(processes: list[dict[str, Any]]) -> dict[str, Any]:
    observed: set[int] = set()
    unexpected: set[int] = set()
    for process in processes:
        if not any(
            argument == INTERNAL_ZYGOTE_FLAG
            or argument.startswith(f"{INTERNAL_ZYGOTE_FLAG}=")
            for argument in process["cmdline"]
        ):
            continue
        observed.add(process["pid"])
        if "--type=zygote" not in process["cmdline"]:
            unexpected.add(process["pid"])
    return {
        "flag": INTERNAL_ZYGOTE_FLAG,
        "zygote_pids": sorted(observed),
        "unexpected_non_zygote_pids": sorted(unexpected),
    }


def run_browser_case(
    name: str,
    action: Callable[[Any, str, Path, Callable[[str], None]], dict[str, Any]],
    runtime_root: Path,
) -> dict[str, Any]:
    from selenium import webdriver
    from selenium.webdriver.chrome.service import Service

    result: dict[str, Any] = {"name": name, "passed": False}
    baseline_snapshot = all_processes()
    baseline = browser_identities(baseline_snapshot)
    result["preexisting_browser_pids"] = sorted(baseline)
    tracked: dict[int, int] = {}
    driver = None
    driver_pid: int | None = None
    with tempfile.TemporaryDirectory(prefix=f"{name}-", dir=runtime_root) as root:
        root_path = Path(root)
        profile_dir = root_path / "profile"
        download_dir = root_path / "download"
        chromedriver_log = root_path / "chromedriver.log"
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
        service = Service(
            executable_path=CHROMEDRIVER,
            log_output=str(chromedriver_log),
            service_args=["--verbose"],
        )
        started = time.monotonic()
        try:
            driver = webdriver.Chrome(service=service, options=options)
            startup_seconds = time.monotonic() - started
            driver_pid = service.process.pid
            startup_processes = wait_for_renderer_snapshot(
                result, driver_pid, baseline, tracked
            )
            cpu_ticks_before = sum(process["cpu_ticks"] for process in startup_processes)
            action_started = time.monotonic()
            action_result = action(
                driver,
                base_url,
                download_dir,
                lambda stage: result.setdefault("action_progress", []).append(stage),
            )
            action_seconds = time.monotonic() - action_started
            post_action_processes = record_process_snapshot(
                result, "post_action", driver_pid, baseline, tracked
            )
            cpu_ticks_after = sum(process["cpu_ticks"] for process in post_action_processes)
            clock_ticks = os.sysconf("SC_CLK_TCK")
            result.update(
                {
                    "startup_seconds": round(startup_seconds, 3),
                    "action_seconds": round(action_seconds, 3),
                    "action": action_result,
                    "observed_cpu_seconds_during_action": round(
                        max(0, cpu_ticks_after - cpu_ticks_before) / clock_ticks, 3
                    ),
                }
            )
            result["action_passed"] = True
        except Exception as error:  # evidence must survive every Selenium failure
            result["error"] = {"type": type(error).__name__, "message": str(error)}
            result["action_passed"] = False
            if driver_pid is None and service.process is not None:
                driver_pid = service.process.pid
            record_process_snapshot(result, "action_error", driver_pid, baseline, tracked)
        finally:
            record_process_snapshot(
                result, "before_cleanup", driver_pid, baseline, tracked
            )
            snapshots = result.get("process_snapshots", [])
            best_snapshot = max(
                snapshots,
                key=lambda snapshot: (snapshot["renderer_count"], snapshot["process_count"]),
                default={"processes": [], "renderer_count": 0, "process_count": 0},
            )
            result["processes"] = best_snapshot["processes"]
            result["process_evidence_stage"] = best_snapshot.get("stage")
            result["process_count"] = best_snapshot["process_count"]
            all_observed_processes = [
                process
                for snapshot in snapshots
                for process in snapshot["processes"]
            ]
            result["forbidden_arguments"] = check_forbidden_arguments(
                all_observed_processes
            )
            result["internal_zygote_argument"] = check_internal_zygote_arguments(
                all_observed_processes
            )
            observed_chromium = [
                process
                for process in all_observed_processes
                if any("chromium" in argument for argument in process["cmdline"])
            ]
            result["all_observed_chromium_uid_gid_2000"] = bool(
                observed_chromium
            ) and all(
                process["effective_uid"] == EXPECTED_UID
                and process["effective_gid"] == EXPECTED_GID
                for process in observed_chromium
            )
            result["peak_observed_aggregate_rss_kib"] = max(
                (snapshot["aggregate_rss_kib"] for snapshot in snapshots), default=0
            )
            result["peak_observed_aggregate_pss_kib"] = max(
                (snapshot["aggregate_pss_kib"] for snapshot in snapshots), default=0
            )
            result["profile_bytes_before_cleanup"] = directory_bytes(profile_dir)
            result["download_bytes_before_cleanup"] = directory_bytes(download_dir)
            result["tmp_filesystem_before_cleanup"] = filesystem_usage("/tmp")
            result["dev_shm_before_cleanup"] = filesystem_usage("/dev/shm")
            result["chromedriver_returncode_before_cleanup"] = (
                service.process.poll() if service.process is not None else None
            )
            if driver is not None:
                result["webdriver_quit"] = bounded_cleanup_call(driver.quit)
            result["service_stop"] = bounded_cleanup_call(service.stop)
            result["chromedriver_log_tail"] = text_tail(chromedriver_log)
            _snapshot, _current = case_processes(driver_pid, baseline, tracked)
            result["cleanup"] = force_cleanup(driver_pid, baseline, tracked)
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=2)
            result["orphan_pids_after_cleanup"] = result["cleanup"][
                "orphan_pids_after_cleanup"
            ]
            result["passed"] = bool(
                result.get("action_passed")
                and not result["preexisting_browser_pids"]
                and not result["forbidden_arguments"]
                and not result["internal_zygote_argument"]["unexpected_non_zygote_pids"]
                and result["all_observed_chromium_uid_gid_2000"]
                and result["cleanup"]["verified"]
            )
    return result


def core_action(
    driver: Any,
    base_url: str,
    download_dir: Path,
    progress: Callable[[str], None],
) -> dict[str, Any]:
    from selenium.webdriver.common.by import By

    progress("before_synthetic_navigation")
    driver.get(base_url)
    progress("after_synthetic_navigation")
    dom_value = driver.find_element(By.ID, "probe").text
    if dom_value != "synthetic-ok":
        raise ProbeFailure(f"Unexpected DOM value: {dom_value!r}")
    progress("synthetic_dom_verified")
    driver.find_element(By.ID, "download").click()
    downloaded = wait_for_download(download_dir)
    progress("synthetic_download_verified")
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
    progress("browser_request_audit_verified")
    return {
        "navigation": True,
        "dom_access": True,
        "download": {
            "path_basename": downloaded.name,
            "mode": oct(downloaded.stat().st_mode & 0o777),
            "sha256": hashlib.sha256(downloaded.read_bytes()).hexdigest(),
            "expected_sha256": DOWNLOAD_SHA256,
        },
        "observed_request_urls": sorted(observed_urls),
        "non_synthetic_request_urls": disallowed_urls,
    }


def exception_action(
    driver: Any,
    base_url: str,
    _download_dir: Path,
    progress: Callable[[str], None],
) -> dict[str, Any]:
    from selenium.common.exceptions import NoSuchElementException
    from selenium.webdriver.common.by import By

    progress("before_synthetic_navigation")
    driver.get(base_url)
    progress("after_synthetic_navigation")
    try:
        driver.find_element(By.ID, "intentionally-missing")
    except NoSuchElementException:
        progress("expected_selenium_exception_verified")
        return {"expected_selenium_exception_observed": True}
    raise ProbeFailure("Expected Selenium exception was not raised")


def timeout_action(
    driver: Any,
    _base_url: str,
    _download_dir: Path,
    progress: Callable[[str], None],
) -> dict[str, Any]:
    from selenium.common.exceptions import TimeoutException

    driver.set_script_timeout(1)
    progress("before_expected_script_timeout")
    try:
        driver.execute_async_script("void 0;")
    except TimeoutException:
        progress("expected_script_timeout_verified")
        return {"expected_timeout_observed": True}
    raise ProbeFailure("Expected Selenium script timeout was not raised")


def evaluate_sandbox(cases: dict[str, dict[str, Any]]) -> dict[str, Any]:
    evidence_case, core = max(
        cases.items(),
        key=lambda item: (
            sum("--type=renderer" in process["cmdline"] for process in item[1].get("processes", [])),
            len(item[1].get("processes", [])),
        ),
    )
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
    browser_processes = [
        process
        for process in chromium_processes
        if not any(argument.startswith("--type=") for argument in process["cmdline"])
        and not any("crashpad" in argument for argument in process["cmdline"])
    ]
    browser_process = browser_processes[0] if browser_processes else None
    namespace_names = ("user", "pid", "net")
    renderer_namespace_isolation = bool(browser_process and renderers) and all(
        all(
            not browser_process["namespaces"].get(namespace, "").startswith(
                "unavailable:"
            )
            and not renderer["namespaces"].get(namespace, "").startswith("unavailable:")
            and renderer["namespaces"].get(namespace)
            != browser_process["namespaces"].get(namespace)
            for namespace in namespace_names
        )
        for renderer in renderers
    )
    internal_zygote = check_internal_zygote_arguments(processes)
    verified = bool(
        not core.get("forbidden_arguments")
        and all_non_root
        and renderer_seccomp
        and renderer_namespace_isolation
        and not internal_zygote["unexpected_non_zygote_pids"]
    )
    return {
        "verified": verified,
        "evidence_case": evidence_case,
        "evidence_stage": core.get("process_evidence_stage"),
        "all_chromium_processes_uid_gid_2000": all_non_root,
        "renderer_count": len(renderers),
        "all_renderers_seccomp_filter_and_no_new_privs": renderer_seccomp,
        "all_renderers_isolated_in_user_pid_network_namespaces": renderer_namespace_isolation,
        "chrome_sandbox_page": "not used as authoritative evidence",
        "internal_zygote_argument": internal_zygote,
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
            "chromium_apk": verify_installed_apk("chromium=152.0.7977.82-r0"),
            "chromedriver_apk": verify_installed_apk(
                "chromium-chromedriver=152.0.7977.82-r0"
            ),
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
    result["sandbox"] = evaluate_sandbox(result["cases"])
    result["cleanup_verified"] = all(
        case.get("cleanup", {}).get("verified")
        for case in result["cases"].values()
    )
    result["functional_cases_passed"] = all(
        case.get("action_passed") for case in result["cases"].values()
    )
    result["case_policy_verified"] = all(
        not case.get("preexisting_browser_pids")
        and not case.get("forbidden_arguments")
        and not case.get("internal_zygote_argument", {}).get(
            "unexpected_non_zygote_pids"
        )
        and case.get("all_observed_chromium_uid_gid_2000")
        for case in result["cases"].values()
    )
    result["elapsed_seconds"] = round(time.monotonic() - started, 3)
    result["security_deviations"] = []
    result["passed"] = bool(
        result["sandbox"]["verified"]
        and result["cleanup_verified"]
        and result["functional_cases_passed"]
        and result["case_policy_verified"]
    )
    if not result["sandbox"]["verified"]:
        result["blocking_finding"] = "Required Chromium sandbox was not positively verified"
    print(json.dumps(result, indent=2, sort_keys=True), flush=True)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, lambda _signum, _frame: sys.exit(143))
    raise SystemExit(main())
