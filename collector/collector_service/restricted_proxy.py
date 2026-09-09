"""Loopback CONNECT proxy enforcing the Phase 3A destination allowlist."""

from __future__ import annotations

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
import ipaddress
import re
import select
import socket
from socketserver import ThreadingMixIn
import threading
from typing import Iterator
from urllib.parse import urlsplit


CONNECT_TIMEOUT_SECONDS = 10
MAX_HOSTNAME_LENGTH = 253


class EgressGate:
    """Thread-safe allowlist for local proxy destinations."""

    def __init__(self, origins: frozenset[str]) -> None:
        self.allowed_hosts = frozenset(
            hostname
            for origin in origins
            if (hostname := urlsplit(origin).hostname) is not None
        )
        self._rejected_hostname: str | None = None
        self._rejection_detected = False
        self._lock = threading.Lock()

    def parse_allowed_target(self, target: str) -> str | None:
        host, separator, port_text = target.rpartition(":")
        if separator != ":" or not host or port_text != "443":
            self.record_rejection(host or "invalid")
            return None
        try:
            normalized = normalize_hostname(host)
        except ValueError:
            self.record_rejection("invalid")
            return None
        if normalized not in self.allowed_hosts:
            self.record_rejection(normalized)
            return None
        return normalized

    def record_rejection(self, hostname: str) -> None:
        try:
            normalized: str | None = normalize_hostname(hostname)
        except ValueError:
            normalized = None
        with self._lock:
            self._rejection_detected = True
            self._rejected_hostname = normalized

    @property
    def rejected_hostname(self) -> str | None:
        with self._lock:
            return self._rejected_hostname

    @property
    def rejection_detected(self) -> bool:
        with self._lock:
            return self._rejection_detected


class _ConnectProxy(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, gate: EgressGate) -> None:
        self.gate = gate
        super().__init__(("127.0.0.1", 0), _ConnectProxyHandler)


class _ConnectProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_CONNECT(self) -> None:  # noqa: N802
        gate: EgressGate = self.server.gate  # type: ignore[attr-defined]
        hostname = gate.parse_allowed_target(self.path)
        if hostname is None:
            self.send_error(403)
            return
        upstream = _connect_public_https(hostname)
        if upstream is None:
            self.send_error(502)
            return
        try:
            self.send_response(200, "Connection established")
            self.end_headers()
            self.connection.setblocking(False)
            upstream.setblocking(False)
            sockets = (self.connection, upstream)
            while True:
                readable, _, exceptional = select.select(sockets, (), sockets, 1.0)
                if exceptional:
                    return
                for source in readable:
                    target = upstream if source is self.connection else self.connection
                    chunk = source.recv(64 * 1024)
                    if not chunk:
                        return
                    target.sendall(chunk)
        finally:
            upstream.close()

    def do_GET(self) -> None:  # noqa: N802
        gate: EgressGate = self.server.gate  # type: ignore[attr-defined]
        gate.record_rejection("non_https")
        self.send_error(403)

    def log_message(self, _format: str, *_args: object) -> None:
        """Suppress proxy request targets and headers."""


def _connect_public_https(hostname: str) -> socket.socket | None:
    try:
        addresses = socket.getaddrinfo(
            hostname, 443, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
        )
    except OSError:
        return None
    for family, socktype, protocol, _, address in addresses:
        connection: socket.socket | None = None
        try:
            if not ipaddress.ip_address(address[0]).is_global:
                continue
            connection = socket.socket(family, socktype, protocol)
            connection.settimeout(CONNECT_TIMEOUT_SECONDS)
            connection.connect(address)
            return connection
        except OSError:
            if connection is not None:
                connection.close()
    return None


@contextmanager
def local_egress_proxy(gate: EgressGate) -> Iterator[int]:
    proxy = _ConnectProxy(gate)
    thread = threading.Thread(target=proxy.serve_forever, daemon=True)
    thread.start()
    try:
        yield proxy.server_port
    finally:
        proxy.shutdown()
        proxy.server_close()
        thread.join(timeout=2)


def normalize_hostname(value: str) -> str:
    """Return a safe normalized DNS hostname and reject IP literals."""

    try:
        hostname = value.rstrip(".").encode("idna").decode("ascii").lower()
        ipaddress.ip_address(hostname)
    except UnicodeError as error:
        raise ValueError("invalid hostname") from error
    except ValueError:
        pass
    else:
        raise ValueError("IP destinations are forbidden")
    if (
        not hostname
        or len(hostname) > MAX_HOSTNAME_LENGTH
        or "." not in hostname
        or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in hostname.split(".")
        )
    ):
        raise ValueError("invalid hostname")
    return hostname
