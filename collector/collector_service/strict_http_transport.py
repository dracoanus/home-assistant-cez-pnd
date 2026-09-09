"""Pinned-resolution HTTPS transport for the narrow CEZ auth protocol."""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import time
from typing import Callable, Mapping, Sequence
from urllib.parse import urlsplit

from .cez_http_auth import HttpResponse, REVIEWED_HOSTNAMES, ValidatedDestination


MAX_ADDRESS_ATTEMPTS = 4
READ_CHUNK_BYTES = 64 * 1024
ALLOWED_METHODS = frozenset({"GET", "POST"})
SAFE_TRANSPORT_CODES = frozenset(
    {
        "auth_dns_resolution_failed",
        "auth_tls_verification_failed",
        "auth_operation_timeout",
        "auth_protocol_error",
        "auth_transport_invariant_failed",
        "auth_connect_failed",
        "auth_request_write_failed",
        "auth_response_protocol_failed",
        "auth_response_header_limit",
        "auth_response_body_limit",
    }
)


class StrictTransportError(Exception):
    """Transport failure carrying only a fixed, non-secret code."""

    def __init__(self, code: str) -> None:
        if code not in SAFE_TRANSPORT_CODES:
            raise ValueError("unknown transport error code")
        self.code = code
        super().__init__(code)


def create_strict_tls_context() -> ssl.SSLContext:
    """Create a system-trust context with hostname checks and TLS 1.2+."""

    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.set_alpn_protocols(["http/1.1"])
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


class StrictHttpsTransport:
    """GET/POST-only transport connecting solely to prevalidated addresses."""

    trust_environment = False
    follows_redirects = False

    def __init__(
        self,
        *,
        tls_context: ssl.SSLContext | None = None,
        resolver: Callable[[str, int], Sequence[str]] | None = None,
        socket_factory: Callable[..., socket.socket] = socket.socket,
        connection_factory: Callable[..., http.client.HTTPConnection] = http.client.HTTPConnection,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._tls_context = tls_context or create_strict_tls_context()
        if (
            not self._tls_context.check_hostname
            or self._tls_context.verify_mode != ssl.CERT_REQUIRED
            or self._tls_context.minimum_version < ssl.TLSVersion.TLSv1_2
        ):
            raise ValueError("insecure TLS context rejected")
        self._resolver = resolver or self._system_resolve
        self._socket_factory = socket_factory
        self._connection_factory = connection_factory
        self._monotonic = monotonic
        self._active_socket: socket.socket | None = None
        self._closed = False

    def __repr__(self) -> str:
        return "StrictHttpsTransport(proxy=disabled,redirects=disabled,tls=verified)"

    def resolve(self, hostname: str, port: int) -> Sequence[str]:
        """Resolve exactly once and return a deterministic validated snapshot."""

        if self._closed or port != 443:
            raise StrictTransportError("auth_dns_resolution_failed")
        try:
            raw_addresses = tuple(self._resolver(hostname, port))
            addresses = tuple(
                sorted(
                    {ipaddress.ip_address(value) for value in raw_addresses},
                    key=lambda address: (address.version, address.packed),
                )
            )
        except (OSError, ValueError) as error:
            raise StrictTransportError("auth_dns_resolution_failed") from error
        if not addresses or any(not address.is_global for address in addresses):
            raise StrictTransportError("auth_dns_resolution_failed")
        return tuple(str(address) for address in addresses)

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
        """Connect to a validated IP and issue one non-redirecting HTTPS request."""

        if self._closed:
            raise StrictTransportError("auth_transport_invariant_failed")
        method = method.upper()
        parsed = urlsplit(destination.url)
        if (
            method not in ALLOWED_METHODS
            or destination.port != 443
            or parsed.scheme != "https"
            or parsed.hostname != destination.hostname
            or parsed.port not in (None, 443)
            or destination.hostname not in REVIEWED_HOSTNAMES
            or not destination.addresses
            or body is not None and method != "POST"
            or body is not None and len(body) > 64 * 1024
        ):
            raise StrictTransportError("auth_transport_invariant_failed")
        if any(
            name.lower()
            in {
                "host",
                "connection",
                "content-length",
                "proxy-authorization",
                "transfer-encoding",
                "upgrade",
            }
            for name in headers
        ):
            raise StrictTransportError("auth_transport_invariant_failed")

        try:
            addresses = tuple(
                str(address)
                for address in sorted(
                    {ipaddress.ip_address(value) for value in destination.addresses},
                    key=lambda address: (address.version, address.packed),
                )
            )
        except ValueError as error:
            raise StrictTransportError("auth_dns_resolution_failed") from error
        if not addresses or any(
            not ipaddress.ip_address(address).is_global for address in addresses
        ):
            raise StrictTransportError("auth_dns_resolution_failed")
        destination = ValidatedDestination(
            destination.url, destination.hostname, destination.port, addresses
        )

        deadline = self._monotonic() + total_timeout
        tls_socket = self._connect(destination, connect_timeout, deadline)
        self._active_socket = tls_socket
        connection = self._connection_factory(destination.hostname, 443)
        connection.sock = tls_socket
        phase = "request_write"
        try:
            request_target = parsed.path or "/"
            if parsed.query:
                request_target += f"?{parsed.query}"
            connection.putrequest(
                method, request_target, skip_host=True, skip_accept_encoding=True
            )
            connection.putheader("Host", destination.hostname)
            for name, value in headers.items():
                connection.putheader(name, value)
            if body is not None:
                connection.putheader("Content-Length", str(len(body)))
            connection.endheaders(body)
            phase = "response_protocol"
            self._set_read_timeout(tls_socket, read_timeout, deadline)
            response = connection.getresponse()
            header_pairs = tuple((name, value) for name, value in response.getheaders())
            header_size = sum(
                len(name.encode("utf-8")) + len(value.encode("utf-8")) + 4
                for name, value in header_pairs
            )
            if header_size > 64 * 1024:
                raise StrictTransportError("auth_response_header_limit")
            chunks: list[bytes] = []
            length = 0
            phase = "response_body"
            while True:
                self._set_read_timeout(tls_socket, read_timeout, deadline)
                chunk = response.read(
                    min(READ_CHUNK_BYTES, maximum_body_bytes + 1 - length)
                )
                if not chunk:
                    break
                chunks.append(chunk)
                length += len(chunk)
                if length > maximum_body_bytes:
                    raise StrictTransportError("auth_response_body_limit")
            return HttpResponse(response.status, header_pairs, b"".join(chunks))
        except StrictTransportError:
            raise
        except (TimeoutError, socket.timeout) as error:
            raise StrictTransportError("auth_operation_timeout") from error
        except (http.client.HTTPException, OSError, ValueError) as error:
            code = _response_code(phase, "auth_response_protocol_failed")
            raise StrictTransportError(code) from error
        finally:
            connection.close()
            self._active_socket = None

    def close(self) -> None:
        if self._active_socket is not None:
            self._active_socket.close()
            self._active_socket = None
        self._closed = True

    def _connect(
        self,
        destination: ValidatedDestination,
        connect_timeout: float,
        deadline: float,
    ) -> socket.socket:
        addresses = destination.addresses[:MAX_ADDRESS_ATTEMPTS]
        last_error: Exception | None = None
        for address_text in addresses:
            address = ipaddress.ip_address(address_text)
            if not address.is_global:
                raise StrictTransportError("auth_dns_resolution_failed")
            remaining = deadline - self._monotonic()
            if remaining <= 0:
                raise StrictTransportError("auth_operation_timeout")
            family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
            raw_socket = self._socket_factory(family, socket.SOCK_STREAM)
            try:
                raw_socket.settimeout(min(connect_timeout, remaining))
                endpoint = (
                    (address_text, 443, 0, 0)
                    if address.version == 6
                    else (address_text, 443)
                )
                raw_socket.connect(endpoint)
                remaining = deadline - self._monotonic()
                if remaining <= 0:
                    raise StrictTransportError("auth_operation_timeout")
                raw_socket.settimeout(min(connect_timeout, remaining))
                return self._tls_context.wrap_socket(
                    raw_socket, server_hostname=destination.hostname
                )
            except ssl.SSLCertVerificationError as error:
                raw_socket.close()
                raise StrictTransportError("auth_tls_verification_failed") from error
            except StrictTransportError:
                raw_socket.close()
                raise
            except (TimeoutError, socket.timeout, OSError) as error:
                raw_socket.close()
                last_error = error
        if isinstance(last_error, (TimeoutError, socket.timeout)):
            raise StrictTransportError("auth_operation_timeout") from last_error
        raise StrictTransportError("auth_connect_failed") from last_error

    def _set_read_timeout(
        self, connection: socket.socket, read_timeout: float, deadline: float
    ) -> None:
        remaining = deadline - self._monotonic()
        if remaining <= 0:
            raise StrictTransportError("auth_operation_timeout")
        connection.settimeout(min(read_timeout, remaining))

    @staticmethod
    def _system_resolve(hostname: str, port: int) -> Sequence[str]:
        return tuple(
            address[4][0]
            for address in socket.getaddrinfo(
                hostname,
                port,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
                proto=socket.IPPROTO_TCP,
            )
        )


def _response_code(phase: str, response_code: str) -> str:
    return "auth_request_write_failed" if phase == "request_write" else response_code
