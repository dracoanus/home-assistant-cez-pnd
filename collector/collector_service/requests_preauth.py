"""Requests transport and the retained PREAUTH-only compatibility experiment."""

from __future__ import annotations

import time
from typing import Callable, Iterable, Mapping, Protocol, Sequence
from urllib.parse import urljoin, urlsplit

from .cez_http_auth import (
    AuthResult,
    AuthState,
    AuthStatus,
    CEZ_PND_START_URL,
    CONNECT_TIMEOUT_SECONDS,
    MAX_COOKIE_BYTES,
    MAX_COOKIE_COUNT,
    MAX_REDIRECTS,
    MAX_RESPONSE_BODY_BYTES,
    MAX_RESPONSE_HEADER_BYTES,
    READ_TIMEOUT_SECONDS,
    REVIEWED_HOSTNAMES,
    SAFE_ERROR_CODES,
    SafeHttpAuthEvent,
    TOTAL_TIMEOUT_SECONDS,
    HttpResponse,
    ValidatedDestination,
    _AuthFailure,
    _default_resolver,
    _failure_event,
    _is_reviewed_cookie_domain,
    _normalize_cookie_domain,
    _single_header,
    validate_destination,
)


class _Response(Protocol):
    status_code: int
    headers: object

    def iter_content(self, chunk_size: int) -> Iterable[bytes]: ...
    def close(self) -> None: ...


class _Session(Protocol):
    trust_env: bool
    cookies: object

    def request(self, method: str, url: str, **kwargs: object) -> _Response: ...
    def close(self) -> None: ...


Resolver = Callable[[str, int], Sequence[str]]


def _default_session() -> _Session:
    import requests

    session = requests.Session()
    session.trust_env = False
    session.proxies.clear()
    session.cookies = requests.cookies.RequestsCookieJar()
    return session


class RequestsSessionTransport:
    """Redirect-disabled requests transport with bounded, memory-only state."""

    trust_environment = False
    follows_redirects = False
    manages_cookies = True

    def __init__(
        self,
        *,
        resolver: Resolver = _default_resolver,
        session_factory: Callable[[], _Session] = _default_session,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._resolver = resolver
        self._session = session_factory()
        self._monotonic = monotonic
        self._closed = False
        if self._session.trust_env:
            self.close()
            raise ValueError("proxy-enabled session rejected")

    def resolve(self, hostname: str, port: int) -> Sequence[str]:
        if self._closed or port != 443:
            raise _AuthFailure("auth_dns_resolution_failed")
        return self._resolver(hostname, port)

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
    ) -> HttpResponse:
        if self._closed or method not in {"GET", "POST"}:
            raise _AuthFailure("auth_transport_policy_invalid")
        deadline = self._monotonic() + total_timeout
        response: _Response | None = None
        try:
            response = self._session.request(
                method,
                destination.url,
                headers=headers,
                data=body,
                allow_redirects=False,
                verify=True,
                timeout=(connect_timeout, read_timeout),
                stream=True,
            )
            header_pairs = tuple(
                (str(name), str(value))
                for name, value in response.headers.items()  # type: ignore[attr-defined]
            )
            header_size = sum(
                len(name.encode("utf-8")) + len(value.encode("utf-8")) + 4
                for name, value in header_pairs
            )
            if header_size > MAX_RESPONSE_HEADER_BYTES:
                raise _AuthFailure("auth_response_header_limit")
            chunks: list[bytes] = []
            size = 0
            for chunk in response.iter_content(chunk_size=64 * 1024):
                if self._monotonic() > deadline:
                    raise _AuthFailure("auth_operation_timeout")
                size += len(chunk)
                if size > maximum_body_bytes:
                    raise _AuthFailure("auth_response_body_limit")
                chunks.append(chunk)
            self._validate_memory_cookies(self._session.cookies)
            status = response.status_code
            if self._monotonic() > deadline:
                raise _AuthFailure("auth_operation_timeout")
            if not isinstance(status, int) or not 100 <= status <= 599:
                raise _AuthFailure("auth_response_invalid")
            return HttpResponse(status, header_pairs, b"".join(chunks))
        except _AuthFailure:
            raise
        except (TimeoutError, OSError) as error:
            raise _AuthFailure("auth_transport_failed") from error
        except Exception as error:
            code = getattr(error, "code", "auth_transport_failed")
            if code not in SAFE_ERROR_CODES:
                code = "auth_transport_failed"
            raise _AuthFailure(code) from error
        finally:
            if response is not None:
                response.close()

    def close(self) -> None:
        if self._closed:
            return
        self._session.cookies.clear()  # type: ignore[attr-defined]
        self._session.close()
        self._closed = True

    @staticmethod
    def _validate_memory_cookies(cookies: object) -> None:
        values = list(cookies)  # type: ignore[arg-type]
        if len(values) > MAX_COOKIE_COUNT:
            raise _AuthFailure("auth_cookie_limit")
        for cookie in values:
            domain = _normalize_cookie_domain(str(cookie.domain))
            if not _is_reviewed_cookie_domain(domain):
                raise _AuthFailure("auth_cookie_domain_not_allowed")
            size = len(f"{cookie.name}={cookie.value}".encode("utf-8"))
            if size > MAX_COOKIE_BYTES:
                raise _AuthFailure("auth_cookie_limit")


class RequestsPreauthCompatibilityClient:
    """Follow only the CEZ PREAUTH GET chain through requests.Session."""

    def __init__(
        self,
        *,
        resolver: Resolver = _default_resolver,
        session_factory: Callable[[], _Session] = _default_session,
        monotonic: Callable[[], float] = time.monotonic,
        emit: Callable[[SafeHttpAuthEvent], None] | None = None,
    ) -> None:
        self._resolver = resolver
        self._session_factory = session_factory
        self._monotonic = monotonic
        self._emit = emit or (lambda _event: None)

    def run(self) -> AuthResult:
        result = AuthResult(AuthStatus.FAILED, "auth_transport_failed")
        transport: RequestsSessionTransport | None = None
        try:
            self._emit(SafeHttpAuthEvent("http_auth_started"))
            transport = RequestsSessionTransport(
                resolver=self._resolver,
                session_factory=self._session_factory,
                monotonic=self._monotonic,
            )
            deadline = self._monotonic() + TOTAL_TIMEOUT_SECONDS
            url = CEZ_PND_START_URL
            state = AuthState.PREAUTH
            redirects = 0
            while True:
                destination = validate_destination(url, state, "GET", transport.resolve)
                remaining = deadline - self._monotonic()
                if remaining <= 0:
                    raise _AuthFailure("auth_operation_timeout")
                response = transport.request(
                    "GET",
                    destination,
                    headers={
                        "Accept": "text/html,application/xhtml+xml",
                        "User-Agent": "CEZ-PND-Collector/requests-preauth-compatibility",
                    },
                    body=None,
                    connect_timeout=min(CONNECT_TIMEOUT_SECONDS, remaining),
                    read_timeout=min(READ_TIMEOUT_SECONDS, remaining),
                    total_timeout=remaining,
                    maximum_body_bytes=MAX_RESPONSE_BODY_BYTES,
                )
                if not 300 <= response.status < 400:
                    hostname = urlsplit(destination.url).hostname
                    if response.status != 200 or hostname not in {
                        "mepas.cez.cz",
                        "dip.cezdistribuce.cz",
                    }:
                        raise _AuthFailure("auth_state_unverified")
                    self._emit(SafeHttpAuthEvent("preauth_reached", hostname))
                    result = AuthResult(
                        AuthStatus.NEEDS_LIVE_VERIFICATION,
                        "auth_success_condition_needs_live_verification",
                    )
                    break
                redirects += 1
                if redirects > MAX_REDIRECTS:
                    raise _AuthFailure("auth_redirect_limit")
                location = _single_header(response.headers, "location")
                if location is None:
                    raise _AuthFailure("auth_redirect_invalid")
                url = urljoin(destination.url, location)
                hostname = urlsplit(url).hostname
                if hostname in REVIEWED_HOSTNAMES:
                    self._emit(SafeHttpAuthEvent("auth_redirect_observed", hostname))
                state = (
                    AuthState.CREDENTIAL_FORM
                    if hostname in {"mepas.cez.cz", "dip.cezdistribuce.cz"}
                    else AuthState.PREAUTH
                )
        except _AuthFailure as error:
            result = AuthResult(AuthStatus.FAILED, error.code)
            self._emit(SafeHttpAuthEvent(_failure_event(error.code)))
        except Exception:
            result = AuthResult(AuthStatus.FAILED, "auth_transport_failed")
            self._emit(SafeHttpAuthEvent("authentication_failed"))
        finally:
            try:
                if transport is not None:
                    transport.close()
            except Exception:
                result = AuthResult(AuthStatus.FAILED, "auth_cleanup_failed")
                self._emit(SafeHttpAuthEvent("http_auth_cleanup_failed"))
            else:
                self._emit(SafeHttpAuthEvent("http_auth_cleanup_complete"))
        return result
