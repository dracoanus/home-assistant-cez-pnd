#!/usr/bin/env python3
"""Minimal offline Chromium/Selenium functional smoke test."""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import quote

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By


FORBIDDEN_ARGUMENTS = {
    "--no-sandbox",
    "--disable-setuid-sandbox",
    "--disable-gpu-sandbox",
}
LOG_TAIL_MAX_BYTES = 32 * 1024
LOG_TAIL_MAX_LINES = 200
VERSION_OUTPUT_MAX_CHARS = 512
SANDBOX_DISCOVERY_TIMEOUT_SECONDS = 3
POST_CLEANUP_TIMEOUT_SECONDS = 2


class LoopbackHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        body = b"<!doctype html><html><body><p id='probe'>loopback-ok</p></body></html>"
        if self.path != "/":
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


def milestone(result: dict[str, Any], name: str) -> None:
    result["milestones"].append(name)
    result["last_completed_milestone"] = name


def executable_version(executable: str) -> dict[str, Any]:
    diagnostic: dict[str, Any] = {"executable": executable}
    try:
        completed = subprocess.run(
            [executable, "--version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
        output = (completed.stdout or completed.stderr).strip()
        diagnostic["returncode"] = completed.returncode
        diagnostic["version_output"] = output[:VERSION_OUTPUT_MAX_CHARS]
        diagnostic["output_truncated"] = len(output) > VERSION_OUTPUT_MAX_CHARS
    except Exception as error:
        diagnostic["error"] = {
            "type": type(error).__name__,
            "message": str(error)[:VERSION_OUTPUT_MAX_CHARS],
        }
    return diagnostic


def bounded_log_tail(log_path: Path) -> dict[str, Any]:
    try:
        size = log_path.stat().st_size
        with log_path.open("rb") as log_file:
            log_file.seek(max(0, size - LOG_TAIL_MAX_BYTES))
            raw_tail = log_file.read(LOG_TAIL_MAX_BYTES)
        lines = raw_tail.decode("utf-8", errors="replace").splitlines()
        line_truncated = len(lines) > LOG_TAIL_MAX_LINES
        return {
            "text": "\n".join(lines[-LOG_TAIL_MAX_LINES:]),
            "source_size_bytes": size,
            "tail_max_bytes": LOG_TAIL_MAX_BYTES,
            "tail_max_lines": LOG_TAIL_MAX_LINES,
            "truncated": size > LOG_TAIL_MAX_BYTES or line_truncated,
        }
    except Exception as error:
        return {
            "error": {
                "type": type(error).__name__,
                "message": str(error)[:VERSION_OUTPUT_MAX_CHARS],
            }
        }


def process_start_time(pid: int) -> int:
    stat = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    fields_after_name = stat[stat.rfind(")") + 2 :].split()
    return int(fields_after_name[19])


def process_argument_present(argv: list[str], argument: str) -> bool:
    return any(
        item == argument
        or re.search(rf"(?:^|\s){re.escape(argument)}(?:=|\s|$)", item)
        for item in argv
    )


def chromium_processes() -> list[dict[str, Any]]:
    processes: list[dict[str, Any]] = []
    own_namespaces = {
        namespace: os.readlink(f"/proc/self/ns/{namespace}")
        for namespace in ("user", "pid", "net")
    }
    for proc_path in Path("/proc").iterdir():
        if not proc_path.name.isdigit():
            continue
        pid = int(proc_path.name)
        chromium_confirmed = False
        try:
            start_before = process_start_time(pid)
            executable = os.readlink(proc_path / "exe")
            if not executable.startswith("/usr/lib/chromium/chromium"):
                continue
            chromium_confirmed = True
            raw_cmdline = (proc_path / "cmdline").read_bytes()
            status_lines = (proc_path / "status").read_text(encoding="ascii").splitlines()
            namespaces = {
                namespace: os.readlink(proc_path / "ns" / namespace)
                for namespace in own_namespaces
            }
            start_after = process_start_time(pid)
        except FileNotFoundError:
            continue
        except (OSError, UnicodeError, ValueError) as error:
            if not chromium_confirmed:
                continue
            processes.append(
                {
                    "pid": pid,
                    "complete": False,
                    "error": type(error).__name__,
                }
            )
            continue

        status = {
            key: value.strip()
            for line in status_lines
            if ":" in line
            for key, value in [line.split(":", 1)]
        }
        argv = [part.decode("utf-8", errors="replace") for part in raw_cmdline.split(b"\0") if part]
        is_renderer = process_argument_present(argv, "--type=renderer")
        forbidden = sorted(
            argument
            for argument in FORBIDDEN_ARGUMENTS
            if process_argument_present(argv, argument)
        )
        uid_fields = status.get("Uid", "").split()
        gid_fields = status.get("Gid", "").split()
        processes.append(
            {
                "pid": pid,
                "start_time_ticks": start_before,
                "identity_stable": start_before == start_after,
                "complete": bool(raw_cmdline and uid_fields and gid_fields),
                "renderer": is_renderer,
                "effective_uid": int(uid_fields[1]) if len(uid_fields) >= 2 else None,
                "effective_gid": int(gid_fields[1]) if len(gid_fields) >= 2 else None,
                "no_new_privs": status.get("NoNewPrivs"),
                "seccomp": status.get("Seccomp"),
                "cap_eff": status.get("CapEff"),
                "separate_namespaces": {
                    namespace: namespaces[namespace] != own_namespaces[namespace]
                    for namespace in own_namespaces
                },
                "forbidden_arguments": forbidden,
            }
        )
    return processes


def verify_renderer_sandbox() -> dict[str, Any]:
    deadline = time.monotonic() + SANDBOX_DISCOVERY_TIMEOUT_SECONDS
    processes: list[dict[str, Any]] = []
    while time.monotonic() < deadline:
        processes = chromium_processes()
        if any(process.get("renderer") for process in processes):
            break
        time.sleep(0.1)

    renderers = [process for process in processes if process.get("renderer")]
    complete_live_evidence = all(
        process.get("complete") and process.get("identity_stable") for process in processes
    )
    renderers_verified = bool(renderers) and all(
        renderer.get("effective_uid") == 2000
        and renderer.get("effective_gid") == 2000
        and renderer.get("no_new_privs") == "1"
        and renderer.get("seccomp") == "2"
        and renderer.get("cap_eff") == "0000000000000000"
        and all(renderer.get("separate_namespaces", {}).values())
        and not renderer.get("forbidden_arguments")
        for renderer in renderers
    )
    forbidden_absent = all(not process.get("forbidden_arguments") for process in processes)
    return {
        "verified": complete_live_evidence and renderers_verified and forbidden_absent,
        "renderer_count": len(renderers),
        "all_live_chromium_evidence_complete": complete_live_evidence,
        "forbidden_arguments_absent": forbidden_absent,
        "renderers": renderers,
    }


def wait_for_chromium_cleanup() -> list[int]:
    deadline = time.monotonic() + POST_CLEANUP_TIMEOUT_SECONDS
    remaining: list[int] = []
    while time.monotonic() < deadline:
        remaining = [process["pid"] for process in chromium_processes()]
        if not remaining:
            return []
        time.sleep(0.1)
    return remaining


def main() -> int:
    result: dict[str, Any] = {
        "passed": False,
        "uid": os.geteuid(),
        "gid": os.getegid(),
        "milestones": [],
        "last_completed_milestone": None,
    }
    if (os.geteuid(), os.getegid()) != (2000, 2000):
        raise RuntimeError("collector-runtime must run as UID/GID 2000:2000")

    server = ThreadingHTTPServer(("127.0.0.1", 0), LoopbackHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    loopback_url = f"http://127.0.0.1:{server.server_port}/"

    driver: webdriver.Chrome | None = None
    service: Service | None = None
    with tempfile.TemporaryDirectory(prefix="collector-runtime-") as runtime_directory:
        runtime_path = Path(runtime_directory)
        runtime_path.chmod(0o700)
        profile = runtime_path / "profile"
        profile.mkdir(mode=0o700)
        log_path = runtime_path / "chromedriver.log"
        log_path.touch(mode=0o600)
        log_path.chmod(0o600)
        try:
            arguments = [
                "--headless=new",
                "--disable-background-networking",
                "--disable-component-update",
                "--no-first-run",
                "--no-default-browser-check",
                "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",
                f"--user-data-dir={profile}",
                "--window-size=1280,720",
            ]
            if FORBIDDEN_ARGUMENTS.intersection(arguments):
                raise RuntimeError("forbidden Chromium sandbox argument configured")
            result["configured_chromium_arguments"] = arguments.copy()
            result["chromium"] = executable_version("/usr/bin/chromium")
            result["chromedriver"] = executable_version("/usr/bin/chromedriver")

            service = Service(
                executable_path="/usr/bin/chromedriver",
                service_args=["--verbose"],
                log_output=str(log_path),
            )

            options = webdriver.ChromeOptions()
            options.binary_location = "/usr/bin/chromium"
            for argument in arguments:
                options.add_argument(argument)

            milestone(result, "before_webdriver_session")
            driver = webdriver.Chrome(service=service, options=options)
            milestone(result, "webdriver_session_created")
            result["browser_version"] = driver.capabilities.get("browserVersion")
            result["chromedriver_version"] = driver.capabilities.get(
                "chrome", {}
            ).get("chromedriverVersion", "").split(" ", 1)[0]

            driver.get("about:blank")
            milestone(result, "about_blank_loaded")

            if driver.execute_script("return 1") != 1:
                raise RuntimeError("basic JavaScript returned an unexpected value")
            milestone(result, "basic_javascript_verified")

            inline_html = "<html><body><p id='probe'>data-ok</p></body></html>"
            driver.get("data:text/html;charset=utf-8," + quote(inline_html))
            milestone(result, "data_page_loaded")
            if driver.find_element(By.ID, "probe").text != "data-ok":
                raise RuntimeError("data URL DOM text did not match")
            milestone(result, "data_dom_verified")

            driver.get(loopback_url)
            milestone(result, "loopback_page_loaded")
            if driver.find_element(By.ID, "probe").text != "loopback-ok":
                raise RuntimeError("loopback DOM text did not match")
            milestone(result, "loopback_dom_verified")

            result["sandbox"] = verify_renderer_sandbox()
            if not result["sandbox"]["verified"]:
                raise RuntimeError("renderer sandbox could not be positively verified")
            milestone(result, "renderer_sandbox_verified")
            result["passed"] = True
        except Exception as error:
            result["error"] = {"type": type(error).__name__, "message": str(error)}
        finally:
            if driver is not None:
                try:
                    driver.quit()
                    milestone(result, "webdriver_quit_completed")
                except Exception as error:
                    result["cleanup_error"] = {
                        "type": type(error).__name__,
                        "message": str(error),
                    }
                    result["passed"] = False
            if service is not None:
                service.stop()
                result["chromedriver_returncode"] = (
                    service.process.poll() if service.process is not None else None
                )
            else:
                result["chromedriver_returncode"] = None
            result["orphan_chromium_pids"] = wait_for_chromium_cleanup()
            result["cleanup_verified"] = not result["orphan_chromium_pids"]
            if not result["cleanup_verified"]:
                result["passed"] = False
            result["chromedriver_log_tail"] = bounded_log_tail(log_path)
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=2)
            result["loopback_server_stopped"] = not server_thread.is_alive()
            if not result["loopback_server_stopped"]:
                result["passed"] = False

    print(json.dumps(result, indent=2, sort_keys=True), flush=True)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
