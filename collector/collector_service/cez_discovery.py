"""One-shot, fail-closed CEZ browser authentication discovery foundation."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import shutil
import tempfile
import time
from typing import Callable, Protocol
from urllib.parse import urlsplit, urlunsplit

from .restricted_proxy import (
    EgressGate,
    local_egress_proxy,
    normalize_hostname as _normalize_hostname,
)
from .runtime_config import DiscoveryConfiguration


FORBIDDEN_CHROMIUM_ARGUMENTS = frozenset(
    {
        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--disable-gpu-sandbox",
        "--disable-seccomp-filter-sandbox",
    }
)
SAFE_EVENTS = frozenset(
    {
        "browser_started",
        "login_page_reached",
        "credentials_submitted",
        "authentication_succeeded",
        "authentication_failed",
        "unexpected_origin",
        "timeout",
        "browser_cleanup_complete",
    }
)
SAFE_PATH_CATEGORIES = frozenset({"root", "login_like", "account_like", "other"})
PAGE_LOAD_TIMEOUT_SECONDS = 20
SCRIPT_TIMEOUT_SECONDS = 10
AUTHENTICATION_OBSERVATION_SECONDS = 30
WEBDRIVER_ENTER_KEY = "\ue007"
TMP_DIRECTORY = Path("/tmp")


class _Element(Protocol):
    def find_elements(self, by: str, value: str) -> list[_Element]: ...
    def get_attribute(self, name: str) -> str | None: ...
    def is_displayed(self) -> bool: ...
    def is_enabled(self) -> bool: ...
    def send_keys(self, value: str) -> None: ...


class _Driver(Protocol):
    current_url: str

    def find_elements(self, by: str, value: str) -> list[_Element]: ...
    def get(self, url: str) -> None: ...
    def set_page_load_timeout(self, seconds: float) -> None: ...
    def set_script_timeout(self, seconds: float) -> None: ...
    def execute_cdp_cmd(self, command: str, parameters: dict[str, str]) -> object: ...
    def delete_all_cookies(self) -> None: ...
    def quit(self) -> None: ...


@dataclass(frozen=True)
class SafeDiscoveryEvent:
    """Allowlisted event containing no browser or credential payload."""

    event: str
    hostname: str | None = None
    path_category: str | None = None

    def __post_init__(self) -> None:
        if self.event not in SAFE_EVENTS:
            raise ValueError("unsafe discovery event")
        if self.hostname is not None:
            if _normalize_hostname(self.hostname) != self.hostname:
                raise ValueError("unsafe discovery hostname")
        if (
            self.path_category is not None
            and self.path_category not in SAFE_PATH_CATEGORIES
        ):
            raise ValueError("unsafe discovery path category")

    def as_dict(self) -> dict[str, str]:
        result = {"event": self.event}
        if self.hostname is not None:
            result["hostname"] = self.hostname
        if self.path_category is not None:
            result["path_category"] = self.path_category
        return result


@dataclass(frozen=True)
class DiscoveryOutcome:
    """Non-secret final state of one discovery execution."""

    succeeded: bool
    cleanup_verified: bool


@dataclass(frozen=True)
class _LoginForm:
    form: _Element
    username: _Element
    password: _Element
    action_origin: str
    action_hostname: str
    action_path_category: str


class _DiscoveryStopped(Exception):
    """Internal non-secret control-flow signal after a safe event."""


class _UnexpectedOrigin(Exception):
    """An observed top-level navigation left the configured allowlist."""

    def __init__(self, hostname: str | None) -> None:
        self.hostname = hostname
        super().__init__("unexpected_origin")


def normalize_start_url(value: str) -> str:
    """Normalize a user-supplied HTTPS start URL without query or fragment."""

    parsed = _parse_https(value, origin_only=False, allow_suffix=False)
    hostname = _normalize_hostname(parsed.hostname or "")
    netloc = hostname if parsed.port in (None, 443) else f"{hostname}:{parsed.port}"
    return urlunsplit(("https", netloc, parsed.path or "/", "", ""))


def normalize_https_origin(value: str) -> str:
    """Normalize one explicit HTTPS origin."""

    parsed = _parse_https(value, origin_only=True, allow_suffix=False)
    hostname = _normalize_hostname(parsed.hostname or "")
    return f"https://{hostname}"


def origin_from_url(value: str) -> str:
    """Return the normalized HTTPS origin of a validated URL."""

    parsed = _parse_https(value, origin_only=False, allow_suffix=True)
    return f"https://{_normalize_hostname(parsed.hostname or '')}"


def _parse_https(value: str, *, origin_only: bool, allow_suffix: bool):
    if not isinstance(value, str) or not value or len(value) > 2048:
        raise ValueError("invalid HTTPS destination")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise ValueError("invalid HTTPS destination") from error
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
        or (not allow_suffix and (parsed.query or parsed.fragment))
        or (origin_only and parsed.path not in ("", "/"))
    ):
        raise ValueError("invalid HTTPS destination")
    return parsed


def safe_location(url: str) -> tuple[str, str]:
    """Reduce a URL to a hostname and fixed path category."""

    parsed = _parse_https(url, origin_only=False, allow_suffix=True)
    hostname = _normalize_hostname(parsed.hostname or "")
    path = parsed.path.lower()
    if path in ("", "/"):
        category = "root"
    elif any(part in path for part in ("login", "signin", "auth")):
        category = "login_like"
    elif any(part in path for part in ("account", "portal", "dashboard")):
        category = "account_like"
    else:
        category = "other"
    return hostname, category


def _validate_observed_location(
    url: str, allowed_origins: frozenset[str]
) -> tuple[str, str]:
    origin = origin_from_url(url)
    if origin not in allowed_origins:
        hostname = _normalize_hostname(urlsplit(url).hostname or "")
        raise _UnexpectedOrigin(hostname)
    return safe_location(url)


def _raise_if_egress_rejected(gate: EgressGate) -> None:
    if gate.rejection_detected:
        raise _UnexpectedOrigin(gate.rejected_hostname)


def chromium_arguments(profile: Path, proxy_port: int) -> tuple[str, ...]:
    """Build the fixed sandbox-preserving Chromium argument set."""

    arguments = (
        "--headless=new",
        "--disable-background-networking",
        "--disable-component-update",
        "--disable-quic",
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
        "--host-resolver-rules=MAP * ~NOTFOUND",
        "--incognito",
        "--no-first-run",
        "--no-default-browser-check",
        f"--proxy-server=http://127.0.0.1:{proxy_port}",
        "--proxy-bypass-list=<-loopback>",
        f"--user-data-dir={profile}",
        "--window-size=1280,720",
    )
    if any(
        argument.split("=", 1)[0] in FORBIDDEN_CHROMIUM_ARGUMENTS
        for argument in arguments
    ):
        raise ValueError("forbidden Chromium argument")
    return arguments


def _create_driver(arguments: tuple[str, ...]) -> tuple[_Driver, object]:
    from selenium import webdriver
    from selenium.webdriver.chrome.service import Service

    service = Service(executable_path="/usr/bin/chromedriver", log_output=os.devnull)
    options = webdriver.ChromeOptions()
    options.binary_location = "/usr/bin/chromium"
    options.add_experimental_option(
        "prefs",
        {
            "credentials_enable_service": False,
            "download.prompt_for_download": False,
            "profile.default_content_setting_values.automatic_downloads": 2,
            "profile.password_manager_enabled": False,
        },
    )
    for argument in arguments:
        options.add_argument(argument)
    try:
        driver = webdriver.Chrome(service=service, options=options)
    except Exception:
        service.stop()
        raise
    return driver, service


def _find_login_form(driver: _Driver) -> _LoginForm | None:
    matches: list[_LoginForm] = []
    for form in driver.find_elements("tag name", "form"):
        inputs = [
            element
            for element in form.find_elements("tag name", "input")
            if element.is_displayed() and element.is_enabled()
        ]
        passwords = [
            element
            for element in inputs
            if (element.get_attribute("type") or "").lower() == "password"
        ]
        usernames = [
            element
            for element in inputs
            if (element.get_attribute("type") or "text").lower() in {"text", "email"}
        ]
        if len(passwords) != 1 or len(usernames) != 1:
            continue
        action = form.get_attribute("action") or driver.current_url
        try:
            action_origin = origin_from_url(action)
            action_hostname, action_category = safe_location(action)
        except ValueError:
            continue
        matches.append(
            _LoginForm(
                form,
                usernames[0],
                passwords[0],
                action_origin,
                action_hostname,
                action_category,
            )
        )
    return matches[0] if len(matches) == 1 else None


def _credential_destination_is_current(
    driver: _Driver,
    form: _LoginForm,
    expected_auth_origin: str,
) -> bool:
    """Revalidate both page and form destination before each secret action."""

    try:
        current_origin = origin_from_url(driver.current_url)
        current_action = form.form.get_attribute("action") or driver.current_url
        action_origin = origin_from_url(current_action)
    except ValueError:
        return False
    return current_origin == expected_auth_origin == action_origin


def run_discovery(
    configuration: DiscoveryConfiguration,
    emit: Callable[[SafeDiscoveryEvent], None],
    *,
    driver_factory: Callable[
        [tuple[str, ...]], tuple[_Driver, object]
    ] = _create_driver,
) -> DiscoveryOutcome:
    """Execute one bounded discovery run and return only non-secret state."""

    if (os.geteuid(), os.getegid()) != (2000, 2000):
        emit(SafeDiscoveryEvent("authentication_failed"))
        return DiscoveryOutcome(False, False)

    driver: _Driver | None = None
    service: object | None = None
    succeeded = False
    cleanup_verified = True
    runtime_directory = tempfile.mkdtemp(
        prefix="cez-discovery-", dir=TMP_DIRECTORY
    )
    Path(runtime_directory).chmod(0o700)
    profile = Path(runtime_directory, "profile")
    profile.mkdir(mode=0o700)
    gate = EgressGate(configuration.allowed_origins)
    try:
        with local_egress_proxy(gate) as proxy_port:
            arguments = chromium_arguments(profile, proxy_port)
            driver, service = driver_factory(arguments)
            driver.set_page_load_timeout(PAGE_LOAD_TIMEOUT_SECONDS)
            driver.set_script_timeout(SCRIPT_TIMEOUT_SECONDS)
            driver.execute_cdp_cmd("Browser.setDownloadBehavior", {"behavior": "deny"})
            emit(SafeDiscoveryEvent("browser_started"))
            _raise_if_egress_rejected(gate)

            driver.get(configuration.start_url)
            _raise_if_egress_rejected(gate)
            hostname, category = _validate_observed_location(
                driver.current_url, configuration.allowed_origins
            )
            form = _find_login_form(driver)
            if (
                form is None
                or origin_from_url(driver.current_url) != configuration.auth_origin
            ):
                emit(SafeDiscoveryEvent("authentication_failed", hostname, category))
                raise _DiscoveryStopped
            if not _credential_destination_is_current(
                driver, form, configuration.auth_origin
            ):
                emit(
                    SafeDiscoveryEvent(
                        "unexpected_origin",
                        form.action_hostname,
                        form.action_path_category,
                    )
                )
                raise _DiscoveryStopped
            emit(SafeDiscoveryEvent("login_page_reached", hostname, category))

            before_submission_url = driver.current_url
            _raise_if_egress_rejected(gate)
            if not _credential_destination_is_current(
                driver, form, configuration.auth_origin
            ):
                emit(SafeDiscoveryEvent("unexpected_origin", hostname, category))
                raise _DiscoveryStopped
            form.username.send_keys(configuration.username)
            _raise_if_egress_rejected(gate)
            if not _credential_destination_is_current(
                driver, form, configuration.auth_origin
            ):
                emit(SafeDiscoveryEvent("unexpected_origin", hostname, category))
                raise _DiscoveryStopped
            form.password.send_keys(configuration.password)
            _raise_if_egress_rejected(gate)
            if not _credential_destination_is_current(
                driver, form, configuration.auth_origin
            ):
                emit(SafeDiscoveryEvent("unexpected_origin", hostname, category))
                raise _DiscoveryStopped
            emit(SafeDiscoveryEvent("credentials_submitted", hostname, category))
            form.password.send_keys(WEBDRIVER_ENTER_KEY)

            deadline = time.monotonic() + AUTHENTICATION_OBSERVATION_SECONDS
            while time.monotonic() < deadline:
                _raise_if_egress_rejected(gate)
                hostname, category = _validate_observed_location(
                    driver.current_url, configuration.allowed_origins
                )
                if (
                    driver.current_url != before_submission_url
                    and _find_login_form(driver) is None
                ):
                    emit(
                        SafeDiscoveryEvent(
                            "authentication_succeeded", hostname, category
                        )
                    )
                    succeeded = True
                    break
                time.sleep(0.25)
            if not succeeded:
                emit(SafeDiscoveryEvent("timeout", hostname, category))
    except _DiscoveryStopped:
        pass
    except _UnexpectedOrigin as error:
        emit(
            SafeDiscoveryEvent(
                "unexpected_origin",
                error.hostname,
                "other" if error.hostname is not None else None,
            )
        )
    except Exception:
        if gate.rejection_detected:
            emit(
                SafeDiscoveryEvent(
                    "unexpected_origin",
                    gate.rejected_hostname,
                    "other" if gate.rejected_hostname is not None else None,
                )
            )
        else:
            emit(SafeDiscoveryEvent("authentication_failed"))
    finally:
        if driver is not None:
            try:
                driver.delete_all_cookies()
            except Exception:
                cleanup_verified = False
            try:
                driver.quit()
            except Exception:
                cleanup_verified = False
        if service is not None:
            try:
                service.stop()  # type: ignore[attr-defined]
            except Exception:
                cleanup_verified = False
        try:
            shutil.rmtree(runtime_directory)
        except OSError:
            cleanup_verified = False
        if cleanup_verified and not Path(runtime_directory).exists():
            emit(SafeDiscoveryEvent("browser_cleanup_complete"))
        else:
            succeeded = False
    return DiscoveryOutcome(succeeded, cleanup_verified)


def emit_json_event(event: SafeDiscoveryEvent) -> None:
    """Print one allowlisted diagnostic event without sensitive values."""

    print(json.dumps(event.as_dict(), separators=(",", ":")), flush=True)
