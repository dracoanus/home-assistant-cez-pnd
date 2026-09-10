"""Fail-closed browserless CEZ authentication state-machine foundation.

The module is intentionally not wired into Collector startup.  A caller must
provide a transport which neither follows redirects nor trusts proxy
environment variables.  This keeps all tests offline and leaves live protocol
verification as an explicit later gate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from html.parser import HTMLParser
import ipaddress
import socket
import time
from typing import Callable, Mapping, Protocol, Sequence
from urllib.parse import urlencode, urljoin, urlsplit, urlunsplit

from .runtime_config import (
    DataProbeConfiguration,
    DiscoveryConfiguration,
    HttpAuthDiscoveryConfiguration,
)
from .structured_logging import structured_event_json


CEZ_PND_START_URL = (
    "https://pnd.cezdistribuce.cz/cezpnd2/external/dashboard/view"
)
CEZ_PND_DASHBOARD_DATA_URL = (
    "https://pnd.cezdistribuce.cz/cezpnd2/external/dashboard/view/data"
)
CEZ_HTTP_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)
CONNECT_TIMEOUT_SECONDS = 10.0
READ_TIMEOUT_SECONDS = 30.0
TOTAL_TIMEOUT_SECONDS = 60.0
MAX_REDIRECTS = 8
MAX_RESPONSE_BODY_BYTES = 512 * 1024
MAX_HTML_BYTES = 256 * 1024
MAX_RESPONSE_HEADER_BYTES = 64 * 1024
MAX_FORM_CONTROLS = 64
MAX_FORM_VALUE_BYTES = 32 * 1024
MAX_COOKIE_COUNT = 32
MAX_COOKIE_BYTES = 4096


class AuthState(str, Enum):
    PREAUTH = "preauth"
    CREDENTIAL_FORM = "credential_form"
    CREDENTIAL_SUBMISSION = "credential_submission"
    AUTH_REDIRECTS = "auth_redirects"
    AUTHENTICATED = "authenticated"
    DATA_PROBE_METADATA = "data_probe_metadata"
    DATA_PROBE_EXPORT = "data_probe_export"


class AuthStatus(str, Enum):
    AUTHENTICATED = "authenticated"
    NEEDS_LIVE_VERIFICATION = "needs_live_verification"
    FAILED = "failed"


SAFE_HTTP_AUTH_EVENTS = frozenset(
    {
        "http_auth_started",
        "http_auth_result",
        "preauth_reached",
        "login_form_validated",
        "credentials_submitted",
        "auth_redirect_observed",
        "authenticated",
        "data_probe_started",
        "dashboard_metadata_verified",
        "consumption_export_received",
        "production_export_received",
        "data_probe_complete",
        "data_probe_failed",
        "auth_state_needs_live_verification",
        "destination_rejected",
        "dns_resolution_failed",
        "tls_verification_failed",
        "timeout",
        "authentication_failed",
        "protocol_error",
        "http_auth_cleanup_complete",
        "http_auth_cleanup_failed",
    }
)
REVIEWED_HOSTNAMES = frozenset(
    {"pnd.cezdistribuce.cz", "mepas.cez.cz", "dip.cezdistribuce.cz"}
)
REVIEWED_COOKIE_DOMAINS = frozenset({"cez.cz", "cezdistribuce.cz"})


@dataclass(frozen=True)
class SafeHttpAuthEvent:
    event: str
    hostname: str | None = None
    status: AuthStatus | None = None
    code: str | None = None

    def __post_init__(self) -> None:
        if self.event not in SAFE_HTTP_AUTH_EVENTS:
            raise ValueError("unsafe HTTP authentication event")
        if self.hostname is not None and self.hostname not in REVIEWED_HOSTNAMES:
            raise ValueError("unsafe HTTP authentication hostname")
        if self.event == "http_auth_result":
            if self.hostname is not None or self.status is None or self.code is None:
                raise ValueError("invalid HTTP authentication result event")
            AuthResult(self.status, self.code)
        elif self.status is not None or self.code is not None:
            raise ValueError("unexpected HTTP authentication result fields")

    @classmethod
    def from_result(cls, result: AuthResult) -> SafeHttpAuthEvent:
        return cls("http_auth_result", status=result.status, code=result.code)

    def as_dict(self) -> dict[str, str]:
        result = {"event": self.event}
        if self.hostname is not None:
            result["hostname"] = self.hostname
        if self.status is not None and self.code is not None:
            result["status"] = self.status.value
            result["code"] = self.code
        return result


SAFE_ERROR_CODES = frozenset(
    {
        "auth_destination_rejected",
        "auth_response_invalid",
        "auth_response_too_large",
        "auth_redirect_invalid",
        "auth_redirect_limit",
        "auth_form_missing",
        "auth_form_ambiguous",
        "auth_form_invalid",
        "auth_form_too_large",
        "auth_form_document_too_large",
        "auth_form_control_limit",
        "auth_form_name_too_large",
        "auth_form_value_too_large",
        "auth_cookie_invalid_syntax",
        "auth_cookie_invalid_name",
        "auth_cookie_invalid_domain",
        "auth_cookie_domain_mismatch",
        "auth_cookie_domain_not_allowed",
        "auth_cookie_limit",
        "auth_operation_timeout",
        "auth_transport_policy_invalid",
        "auth_transport_failed",
        "auth_dns_resolution_failed",
        "auth_tls_verification_failed",
        "auth_protocol_error",
        "auth_transport_invariant_failed",
        "auth_connect_failed",
        "auth_request_write_failed",
        "auth_response_protocol_failed",
        "auth_response_header_limit",
        "auth_response_body_limit",
        "auth_cleanup_failed",
        "auth_state_unverified",
        "data_probe_auth_failed",
        "data_probe_metadata_failed",
        "data_probe_metadata_invalid",
        "data_probe_consumption_export_failed",
        "data_probe_production_export_failed",
        "data_probe_storage_failed",
    }
)


@dataclass(frozen=True)
class AuthResult:
    """Non-secret result suitable for a future allowlisted diagnostic."""

    status: AuthStatus
    code: str

    def __post_init__(self) -> None:
        if not isinstance(self.status, AuthStatus):
            raise ValueError("unsafe authentication result status")
        if self.status is AuthStatus.FAILED and self.code not in SAFE_ERROR_CODES:
            raise ValueError("unsafe authentication result code")
        if (
            self.status is AuthStatus.NEEDS_LIVE_VERIFICATION
            and self.code != "auth_success_condition_needs_live_verification"
        ):
            raise ValueError("unsafe authentication result code")
        if (
            self.status is AuthStatus.AUTHENTICATED
            and self.code != "auth_authenticated_endpoint_verified"
        ):
            raise ValueError("unsafe authentication result code")


@dataclass(frozen=True)
class HttpResponse:
    """Bounded response returned by a redirect-disabled transport."""

    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes


@dataclass(frozen=True)
class ValidatedDestination:
    """Normalized URL and the immutable DNS result approved for connection."""

    url: str
    hostname: str
    port: int
    addresses: tuple[str, ...]


class HttpTransport(Protocol):
    """Minimal transport contract; a production implementation is not wired yet."""

    trust_environment: bool
    follows_redirects: bool
    manages_cookies: bool

    def request(
        self,
        method: str,
        destination: ValidatedDestination,
        *,
        headers: Mapping[str, str],
        body: bytes | None,
        connect_timeout: float,
        read_timeout: float,
        total_timeout: float,
        maximum_body_bytes: int,
    ) -> HttpResponse: ...

    def close(self) -> None: ...


Resolver = Callable[[str, int], Sequence[str]]


@dataclass(frozen=True)
class _Credentials:
    username: str = field(repr=False)
    password: str = field(repr=False)


@dataclass(frozen=True)
class _DestinationRule:
    methods: frozenset[str]
    path_prefixes: tuple[str, ...]


# Reference-derived candidate contract.  Runtime validity remains unverified.
DESTINATION_CONTRACT: Mapping[AuthState, Mapping[str, _DestinationRule]] = {
    AuthState.PREAUTH: {
        "pnd.cezdistribuce.cz": _DestinationRule(
            frozenset({"GET"}), ("/cezpnd2",)
        ),
        "mepas.cez.cz": _DestinationRule(
            frozenset({"GET"}), ("/cas", "/idp", "/login")
        ),
        "dip.cezdistribuce.cz": _DestinationRule(
            frozenset({"GET"}), ("/login", "/cezpnd2", "/idp")
        ),
    },
    AuthState.CREDENTIAL_FORM: {
        "mepas.cez.cz": _DestinationRule(
            frozenset({"GET"}), ("/cas", "/idp", "/login")
        ),
        "dip.cezdistribuce.cz": _DestinationRule(
            frozenset({"GET"}), ("/login", "/cezpnd2", "/idp")
        ),
    },
    AuthState.CREDENTIAL_SUBMISSION: {
        "mepas.cez.cz": _DestinationRule(
            frozenset({"POST"}), ("/cas", "/idp", "/login")
        ),
        "dip.cezdistribuce.cz": _DestinationRule(
            frozenset({"POST"}), ("/login", "/cezpnd2", "/idp")
        ),
    },
    AuthState.AUTH_REDIRECTS: {
        "mepas.cez.cz": _DestinationRule(
            frozenset({"GET"}), ("/cas", "/idp", "/login")
        ),
        "dip.cezdistribuce.cz": _DestinationRule(
            frozenset({"GET"}), ("/login", "/cezpnd2", "/idp")
        ),
        "pnd.cezdistribuce.cz": _DestinationRule(
            frozenset({"GET"}), ("/cezpnd2",)
        ),
    },
    AuthState.AUTHENTICATED: {
        "pnd.cezdistribuce.cz": _DestinationRule(
            frozenset({"GET"}), ("/cezpnd2",)
        ),
    },
    AuthState.DATA_PROBE_METADATA: {
        "pnd.cezdistribuce.cz": _DestinationRule(
            frozenset({"GET"}), ("/cezpnd2/external/dashboard/view/data",)
        ),
    },
    AuthState.DATA_PROBE_EXPORT: {
        "pnd.cezdistribuce.cz": _DestinationRule(
            frozenset({"GET"}), ("/cezpnd2/external/data/export",)
        ),
    },
}


class _AuthFailure(Exception):
    def __init__(self, code: str) -> None:
        if code not in SAFE_ERROR_CODES:
            raise ValueError("unknown authentication error code")
        self.code = code
        super().__init__(code)


def _default_resolver(hostname: str, port: int) -> Sequence[str]:
    return tuple(
        address[4][0]
        for address in socket.getaddrinfo(
            hostname, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
        )
    )


def _path_matches(path: str, prefixes: tuple[str, ...]) -> bool:
    return any(path == prefix or path.startswith(f"{prefix}/") for prefix in prefixes)


def validate_destination(
    url: str,
    state: AuthState,
    method: str,
    resolver: Resolver = _default_resolver,
) -> ValidatedDestination:
    """Validate one request and freeze the sole DNS result used to connect."""

    normalized, hostname = _validate_destination_contract(url, state, method)
    try:
        addresses = tuple(
            sorted(
                {ipaddress.ip_address(address) for address in resolver(hostname, 443)},
                key=lambda address: (address.version, address.packed),
            )
        )
        if not addresses or any(not address.is_global for address in addresses):
            raise _AuthFailure("auth_destination_rejected")
    except _AuthFailure:
        raise
    except socket.gaierror as error:
        raise _AuthFailure("auth_dns_resolution_failed") from error
    except (OSError, ValueError) as error:
        raise _AuthFailure("auth_destination_rejected") from error
    return ValidatedDestination(
        normalized,
        hostname,
        443,
        tuple(str(address) for address in addresses),
    )


def _validate_destination_contract(
    url: str, state: AuthState, method: str
) -> tuple[str, str]:
    """Validate URL policy without performing DNS resolution."""

    try:
        parsed = urlsplit(url)
        port = parsed.port
        hostname = (parsed.hostname or "").rstrip(".").encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError) as error:
        raise _AuthFailure("auth_destination_rejected") from error
    method = method.upper()
    rules = DESTINATION_CONTRACT.get(state, {})
    rule = rules.get(hostname)
    exact_path_required = state in {
        AuthState.DATA_PROBE_METADATA,
        AuthState.DATA_PROBE_EXPORT,
    }
    path_allowed = (
        (parsed.path or "/") in rule.path_prefixes
        if rule is not None and exact_path_required
        else rule is not None and _path_matches(parsed.path or "/", rule.path_prefixes)
    )
    if (
        parsed.scheme != "https"
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
        or parsed.fragment
        or rule is None
        or method not in rule.methods
        or not path_allowed
        or (state is AuthState.CREDENTIAL_SUBMISSION and parsed.query)
    ):
        raise _AuthFailure("auth_destination_rejected")
    netloc = hostname if port is None else f"{hostname}:443"
    return urlunsplit(("https", netloc, parsed.path or "/", parsed.query, "")), hostname


def sanitized_location(url: str) -> tuple[str, str]:
    """Return only a hostname and fixed path category for safe diagnostics."""

    try:
        parsed = urlsplit(url)
        hostname = (parsed.hostname or "").rstrip(".").encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        return "invalid", "other"
    path = parsed.path.lower()
    if any(value in path for value in ("login", "signin", "auth", "cas", "idp")):
        category = "login_like"
    elif any(value in path for value in ("dashboard", "account", "cezpnd2")):
        category = "application_like"
    else:
        category = "other"
    return hostname or "invalid", category


@dataclass
class _ParsedForm:
    action: str
    method: str
    controls: list[tuple[str, str, str]]


class _LoginFormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[_ParsedForm] = []
        self.current: _ParsedForm | None = None
        self.controls = 0
        self.malformed = False

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        attributes = {name.lower(): value or "" for name, value in attrs}
        if tag.lower() == "form":
            if self.current is not None:
                self.malformed = True
                return
            self.current = _ParsedForm(
                attributes.get("action", ""),
                attributes.get("method", "get").upper(),
                [],
            )
        elif tag.lower() == "input" and self.current is not None:
            self.controls += 1
            if self.controls > MAX_FORM_CONTROLS:
                raise _AuthFailure("auth_form_control_limit")
            name = attributes.get("name", "")
            value = attributes.get("value", "")
            input_type = attributes.get("type", "text").lower()
            if len(name.encode("utf-8")) > 256:
                raise _AuthFailure("auth_form_name_too_large")
            if len(value.encode("utf-8")) > MAX_FORM_VALUE_BYTES:
                raise _AuthFailure("auth_form_value_too_large")
            if name:
                self.current.controls.append((name, value, input_type))

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() != "form":
            return
        if self.current is None:
            self.malformed = True
            return
        self.forms.append(self.current)
        self.current = None

    def close(self) -> None:
        super().close()
        if self.current is not None:
            self.malformed = True


class _PndFinalResponseParser(HTMLParser):
    """Detect login forms and safely collect bounded final-response text."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.text_values: list[str] = []
        self._form_depth = 0
        self.login_form_present = False
        self.malformed = False

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        tag = tag.lower()
        attributes = {name.lower(): value or "" for name, value in attrs}
        if tag == "form":
            self._form_depth += 1
            if self._form_depth > 1:
                self.malformed = True
            action = attributes.get("action", "").casefold()
            if attributes.get("id", "").casefold() == "fm1" or any(
                marker in action for marker in ("/cas", "/login", "/idp")
            ):
                self.login_form_present = True
        elif tag == "input" and self._form_depth:
            if (
                attributes.get("type", "text").lower() == "password"
                or attributes.get("name", "").casefold() in {"username", "password"}
            ):
                self.login_form_present = True

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "form":
            if self._form_depth == 0:
                self.malformed = True
            else:
                self._form_depth -= 1

    def handle_data(self, data: str) -> None:
        self.text_values.append(data)

    def close(self) -> None:
        super().close()
        if self._form_depth:
            self.malformed = True


def _parse_login_form(html: bytes, page_url: str) -> _ParsedForm:
    if len(html) > MAX_HTML_BYTES:
        raise _AuthFailure("auth_form_document_too_large")
    try:
        text = html.decode("utf-8", errors="strict")
        parser = _LoginFormParser()
        parser.feed(text)
        parser.close()
    except UnicodeError as error:
        raise _AuthFailure("auth_form_invalid") from error
    if parser.malformed:
        raise _AuthFailure("auth_form_invalid")

    candidates: list[_ParsedForm] = []
    critical = {"username", "password", "execution", "_eventId", "lt", "submit"}
    for form in parser.forms:
        names = [name for name, _, _ in form.controls]
        if any(names.count(name) > 1 for name in critical):
            raise _AuthFailure("auth_form_invalid")
        types = {name: input_type for name, _, input_type in form.controls}
        if "password" not in names:
            continue
        if form.method != "POST" or "username" not in names or types["password"] != "password":
            raise _AuthFailure("auth_form_invalid")
        action = urljoin(page_url, form.action or page_url)
        _validate_destination_contract(
            action, AuthState.CREDENTIAL_SUBMISSION, "POST"
        )
        form.action = action
        candidates.append(form)
    if not candidates:
        raise _AuthFailure("auth_form_missing")
    if len(candidates) != 1:
        raise _AuthFailure("auth_form_ambiguous")
    return candidates[0]


@dataclass(frozen=True)
class _Cookie:
    domain: str = field(repr=False)
    name: str = field(repr=False)
    value: str = field(repr=False)
    host_only: bool


def _domain_matches(hostname: str, domain: str) -> bool:
    return hostname == domain or hostname.endswith("." + domain)


def _is_reviewed_cookie_domain(domain: str) -> bool:
    return any(
        domain == boundary or domain.endswith("." + boundary)
        for boundary in REVIEWED_COOKIE_DOMAINS
    )


def _normalize_cookie_domain(value: str) -> str:
    domain = value.strip().lower()
    if domain.startswith("."):
        domain = domain[1:]
    labels = domain.split(".")
    if (
        not domain
        or len(domain) > 253
        or any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789-" for character in label)
            for label in labels
        )
    ):
        raise _AuthFailure("auth_cookie_invalid_domain")
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        return domain
    raise _AuthFailure("auth_cookie_invalid_domain")


class _MemoryCookieJar:
    """Small CEZ-bound cookie jar with bounded, memory-only values."""

    def __init__(self) -> None:
        self._cookies: dict[tuple[str, str, bool], _Cookie] = {}

    def absorb(self, response: HttpResponse, response_url: str) -> None:
        hostname = (urlsplit(response_url).hostname or "").lower()
        if hostname not in REVIEWED_HOSTNAMES:
            raise _AuthFailure("auth_cookie_domain_not_allowed")
        for name, value in response.headers:
            if name.lower() != "set-cookie":
                continue
            if len(value.encode("utf-8")) > MAX_COOKIE_BYTES:
                raise _AuthFailure("auth_cookie_limit")
            first = value.split(";", 1)[0]
            cookie_name, separator, cookie_value = first.partition("=")
            cookie_name = cookie_name.strip()
            if not separator:
                raise _AuthFailure("auth_cookie_invalid_syntax")
            if not cookie_name or any(ch in cookie_name for ch in "\r\n\t ;,"):
                raise _AuthFailure("auth_cookie_invalid_name")
            domain_attributes = []
            for item in value.split(";")[1:]:
                attribute, separator, attribute_value = item.partition("=")
                if attribute.strip().lower() == "domain":
                    if not separator:
                        raise _AuthFailure("auth_cookie_invalid_syntax")
                    domain_attributes.append(attribute_value)
            if len(domain_attributes) > 1:
                raise _AuthFailure("auth_cookie_invalid_syntax")
            host_only = not domain_attributes
            domain = (
                hostname
                if host_only
                else _normalize_cookie_domain(domain_attributes[0])
            )
            if not host_only and not _domain_matches(hostname, domain):
                continue
            if not host_only and not _is_reviewed_cookie_domain(domain):
                raise _AuthFailure("auth_cookie_domain_not_allowed")
            cookie = _Cookie(domain, cookie_name, cookie_value, host_only)
            self._cookies[(domain, cookie_name, host_only)] = cookie
            if len(self._cookies) > MAX_COOKIE_COUNT:
                raise _AuthFailure("auth_cookie_limit")

    def header_for(self, url: str) -> str | None:
        hostname = (urlsplit(url).hostname or "").lower()
        if hostname not in REVIEWED_HOSTNAMES:
            raise _AuthFailure("auth_cookie_domain_not_allowed")
        pairs = [
            f"{cookie.name}={cookie.value}"
            for cookie in self._cookies.values()
            if (cookie.host_only and cookie.domain == hostname)
            or (not cookie.host_only and _domain_matches(hostname, cookie.domain))
        ]
        value = "; ".join(pairs)
        if len(value.encode("utf-8")) > MAX_COOKIE_COUNT * MAX_COOKIE_BYTES:
            raise _AuthFailure("auth_cookie_limit")
        return value or None

    def clear(self) -> None:
        self._cookies.clear()

    @property
    def count(self) -> int:
        return len(self._cookies)


class CezHttpAuthClient:
    """Offline-testable HTTP-primary authentication foundation."""

    def __init__(
        self,
        configuration: (
            DataProbeConfiguration
            | DiscoveryConfiguration
            | HttpAuthDiscoveryConfiguration
        ),
        transport: HttpTransport,
        *,
        resolver: Resolver = _default_resolver,
        monotonic: Callable[[], float] = time.monotonic,
        emit: Callable[[SafeHttpAuthEvent], None] | None = None,
    ) -> None:
        self._credentials = _Credentials(
            configuration.username, configuration.password
        )
        self._transport = transport
        self._resolver = resolver
        self._monotonic = monotonic
        self._cookies = _MemoryCookieJar()
        self._emit = emit or (lambda _event: None)

    def __repr__(self) -> str:
        return "CezHttpAuthClient(transport_policy=explicit)"

    def authenticate(
        self,
        on_authenticated: Callable[[CezHttpAuthClient], None] | None = None,
    ) -> AuthResult:
        """Run the candidate protocol and always close all session state."""

        result = AuthResult(AuthStatus.FAILED, "auth_transport_failed")
        try:
            self._emit(SafeHttpAuthEvent("http_auth_started"))
            if self._transport.trust_environment or self._transport.follows_redirects:
                raise _AuthFailure("auth_transport_policy_invalid")
            deadline = self._monotonic() + TOTAL_TIMEOUT_SECONDS
            page_url, response = self._follow_get_redirects(
                CEZ_PND_START_URL, AuthState.PREAUTH, deadline
            )
            page_host = urlsplit(page_url).hostname
            if response.status != 200 or page_host not in {
                "mepas.cez.cz",
                "dip.cezdistribuce.cz",
            }:
                raise _AuthFailure("auth_state_unverified")
            self._emit(SafeHttpAuthEvent("preauth_reached", page_host))
            form = _parse_login_form(response.body, page_url)
            action_host = urlsplit(form.action).hostname
            self._emit(SafeHttpAuthEvent("login_form_validated", action_host))

            # Revalidate immediately before credentials become request data.
            action = validate_destination(
                form.action,
                AuthState.CREDENTIAL_SUBMISSION,
                "POST",
                self._resolver,
            )
            referer, referer_host = _validate_destination_contract(
                page_url, AuthState.CREDENTIAL_FORM, "GET"
            )
            if referer_host != action.hostname:
                raise _AuthFailure("auth_destination_rejected")
            fields = [(name, value) for name, value, _ in form.controls]
            fields = [
                (name, value)
                for name, value in fields
                if name not in {"username", "password"}
            ]
            field_names = {name for name, _ in fields}
            if "_eventId" not in field_names:
                fields.append(("_eventId", "submit"))
            if "submit" not in field_names:
                fields.append(("submit", "PŘIHLÁSIT SE"))
            fields.extend(
                (
                    ("username", self._credentials.username),
                    ("password", self._credentials.password),
                )
            )
            encoded = urlencode(fields).encode("utf-8")
            response = self._request(
                "POST",
                action,
                AuthState.CREDENTIAL_SUBMISSION,
                deadline,
                body=encoded,
                extra_headers={
                    "Accept": "*/*",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Referer": referer,
                },
            )
            self._emit(SafeHttpAuthEvent("credentials_submitted", action.hostname))
            final_url, response = self._follow_auth_redirects(
                action.url, response, deadline
            )
            if response.status != 200:
                raise _AuthFailure("auth_state_unverified")
            _validate_destination_contract(
                final_url, AuthState.AUTHENTICATED, "GET"
            )
            _verify_authenticated_application_page(response)
            result = AuthResult(
                AuthStatus.AUTHENTICATED,
                "auth_authenticated_endpoint_verified",
            )
            self._emit(SafeHttpAuthEvent("authenticated"))
            if on_authenticated is not None:
                on_authenticated(self)
        except _AuthFailure as error:
            result = AuthResult(AuthStatus.FAILED, error.code)
            self._emit(SafeHttpAuthEvent(_failure_event(error.code)))
        except Exception:
            result = AuthResult(AuthStatus.FAILED, "auth_transport_failed")
            self._emit(SafeHttpAuthEvent("authentication_failed"))
        finally:
            self._cookies.clear()
            try:
                self._transport.close()
            except Exception:
                result = AuthResult(AuthStatus.FAILED, "auth_cleanup_failed")
                self._emit(SafeHttpAuthEvent("http_auth_cleanup_failed"))
            else:
                self._emit(SafeHttpAuthEvent("http_auth_cleanup_complete"))
        return result

    def new_operation_deadline(self) -> float:
        """Start one separately bounded post-authentication operation window."""

        return self._monotonic() + TOTAL_TIMEOUT_SECONDS

    def request_data_probe(
        self,
        url: str,
        state: AuthState,
        deadline: float,
        *,
        extra_headers: Mapping[str, str] | None = None,
    ) -> HttpResponse:
        """Issue one GET constrained to an exact data-probe destination state."""

        if state not in {
            AuthState.DATA_PROBE_METADATA,
            AuthState.DATA_PROBE_EXPORT,
        }:
            raise _AuthFailure("auth_destination_rejected")
        return self._request(
            "GET", url, state, deadline, extra_headers=extra_headers
        )

    def _follow_get_redirects(
        self, url: str, state: AuthState, deadline: float
    ) -> tuple[str, HttpResponse]:
        response = self._request("GET", url, state, deadline)
        redirects = 0
        while 300 <= response.status < 400:
            redirects += 1
            if redirects > MAX_REDIRECTS:
                raise _AuthFailure("auth_redirect_limit")
            location = _single_header(response.headers, "location")
            if location is None:
                raise _AuthFailure("auth_redirect_invalid")
            url = urljoin(url, location)
            redirect_host = urlsplit(url).hostname
            if redirect_host in REVIEWED_HOSTNAMES:
                self._emit(SafeHttpAuthEvent("auth_redirect_observed", redirect_host))
            host = urlsplit(url).hostname
            next_state = (
                AuthState.CREDENTIAL_FORM
                if host in {"mepas.cez.cz", "dip.cezdistribuce.cz"}
                else state
            )
            response = self._request("GET", url, next_state, deadline)
            state = next_state
        return url, response

    def _follow_auth_redirects(
        self, url: str, response: HttpResponse, deadline: float
    ) -> tuple[str, HttpResponse]:
        redirects = 0
        while 300 <= response.status < 400:
            redirects += 1
            if redirects > MAX_REDIRECTS:
                raise _AuthFailure("auth_redirect_limit")
            if response.status not in {301, 302, 303}:
                raise _AuthFailure("auth_redirect_invalid")
            location = _single_header(response.headers, "location")
            if location is None:
                raise _AuthFailure("auth_redirect_invalid")
            url = urljoin(url, location)
            redirect_host = urlsplit(url).hostname
            if redirect_host in REVIEWED_HOSTNAMES:
                self._emit(SafeHttpAuthEvent("auth_redirect_observed", redirect_host))
            response = self._request(
                "GET", url, AuthState.AUTH_REDIRECTS, deadline
            )
        return url, response

    def _request(
        self,
        method: str,
        url: str | ValidatedDestination,
        state: AuthState,
        deadline: float,
        *,
        body: bytes | None = None,
        extra_headers: Mapping[str, str] | None = None,
    ) -> HttpResponse:
        remaining = deadline - self._monotonic()
        if remaining <= 0:
            raise _AuthFailure("auth_operation_timeout")
        destination = (
            url
            if isinstance(url, ValidatedDestination)
            else validate_destination(url, state, method, self._resolver)
        )
        headers = {
            "Accept": "text/html,application/xhtml+xml",
            "User-Agent": CEZ_HTTP_USER_AGENT,
        }
        transport_manages_cookies = getattr(self._transport, "manages_cookies", False)
        if not transport_manages_cookies:
            cookie = self._cookies.header_for(destination.url)
            if cookie is not None:
                headers["Cookie"] = cookie
        if extra_headers:
            headers.update(extra_headers)
        try:
            response = self._transport.request(
                method,
                destination,
                headers=headers,
                body=body,
                connect_timeout=min(CONNECT_TIMEOUT_SECONDS, remaining),
                read_timeout=min(READ_TIMEOUT_SECONDS, remaining),
                total_timeout=remaining,
                maximum_body_bytes=MAX_RESPONSE_BODY_BYTES,
            )
        except Exception as error:
            code = getattr(error, "code", "auth_transport_failed")
            if code not in SAFE_ERROR_CODES:
                code = "auth_transport_failed"
            raise _AuthFailure(code) from error
        if self._monotonic() > deadline:
            raise _AuthFailure("auth_operation_timeout")
        if not isinstance(response.status, int) or not 100 <= response.status <= 599:
            raise _AuthFailure("auth_response_invalid")
        if len(response.body) > MAX_RESPONSE_BODY_BYTES:
            raise _AuthFailure("auth_response_too_large")
        header_bytes = sum(
            len(name.encode("utf-8")) + len(value.encode("utf-8")) + 4
            for name, value in response.headers
        )
        if header_bytes > MAX_RESPONSE_HEADER_BYTES:
            raise _AuthFailure("auth_response_too_large")
        if not transport_manages_cookies:
            self._cookies.absorb(response, destination.url)
        return response


def _single_header(
    headers: tuple[tuple[str, str], ...], name: str
) -> str | None:
    values = [value for key, value in headers if key.lower() == name.lower()]
    if len(values) != 1 or not values[0] or "\r" in values[0] or "\n" in values[0]:
        return None
    return values[0]


def _verify_authenticated_application_page(response: HttpResponse) -> None:
    """Reject a bounded final response that is clearly login, auth, or error content."""

    if len(response.body) > MAX_RESPONSE_BODY_BYTES:
        raise _AuthFailure("auth_state_unverified")
    if response.status != 200:
        raise _AuthFailure("auth_state_unverified")
    try:
        parser = _PndFinalResponseParser()
        parser.feed(response.body.decode("utf-8", errors="strict"))
        parser.close()
    except (UnicodeError, ValueError) as error:
        raise _AuthFailure("auth_state_unverified") from error
    page_text = " ".join(" ".join(parser.text_values).split()).casefold()
    failure_markers = (
        "recaptcha",
        "g-recaptcha",
        "captcha challenge",
        "neplatné uživatelské jméno",
        "chybné jméno",
        "invalid credentials",
        "bad credentials",
        "zablokován",
        "účet je uzamčen",
        "account locked",
        "odstávka",
        "probíhá údržba",
        "under maintenance",
        "central authentication service",
        "internal server error",
        "service unavailable",
    )
    if (
        parser.malformed
        or parser.login_form_present
        or any(marker in page_text for marker in failure_markers)
    ):
        raise _AuthFailure("auth_state_unverified")


def _failure_event(code: str) -> str:
    if code.startswith("data_probe_"):
        return "data_probe_failed"
    if code == "auth_destination_rejected":
        return "destination_rejected"
    if code == "auth_dns_resolution_failed":
        return "dns_resolution_failed"
    if code == "auth_tls_verification_failed":
        return "tls_verification_failed"
    if code == "auth_operation_timeout":
        return "timeout"
    if code in {
        "auth_protocol_error",
        "auth_transport_invariant_failed",
        "auth_connect_failed",
        "auth_request_write_failed",
        "auth_response_protocol_failed",
        "auth_response_header_limit",
        "auth_response_body_limit",
        "auth_redirect_invalid",
        "auth_redirect_limit",
    }:
        return "protocol_error"
    return "authentication_failed"


def emit_json_event(event: SafeHttpAuthEvent) -> None:
    """Emit one allowlisted event without URLs, queries, or secret values."""

    print(structured_event_json(event.as_dict()), flush=True)
