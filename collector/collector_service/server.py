"""TLS server entry point for the offline Collector API skeleton."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import sys

from .api import ApiResponse, CollectorApi, TokenVerifier
from .security_files import descriptor_path, open_verified_file


BIND_ADDRESS = "0.0.0.0"
BIND_PORT = 8443
TOKEN_VERIFIER_FILE = Path("/data/auth/client.json")
TLS_CERT_FILE = Path("/data/tls/server.crt")
TLS_KEY_FILE = Path("/data/tls/server.key")
MAX_RESPONSE_BYTES = 1024 * 1024


class CollectorHttpServer(HTTPServer):
    """Small bounded HTTP server for the internal HA App network."""

    request_queue_size = 8

    def get_request(self) -> tuple[socket.socket, tuple[str, int]]:
        connection, address = super().get_request()
        connection.settimeout(5.0)
        return connection, address


class CollectorRequestHandler(BaseHTTPRequestHandler):
    """Adapter from HTTP to the pure Collector API."""

    server_version = "CEZ-PND-Collector"
    sys_version = ""

    def do_GET(self) -> None:  # noqa: N802
        self._respond()

    def do_POST(self) -> None:  # noqa: N802
        self._respond()

    def do_PUT(self) -> None:  # noqa: N802
        self._respond()

    def do_DELETE(self) -> None:  # noqa: N802
        self._respond()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._respond()

    def _respond(self) -> None:
        app: CollectorApi = self.server.collector_api  # type: ignore[attr-defined]
        response = app.handle(self.command, self.path, self.headers)
        encoded = json.dumps(
            response.body,
            ensure_ascii=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        if len(encoded) > MAX_RESPONSE_BYTES:
            response = CollectorApi._error(
                503, "response_limit_exceeded", False, response.request_id, response.route
            )
            encoded = json.dumps(response.body, separators=(",", ":")).encode("utf-8")
        self.send_response(response.status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        try:
            self.wfile.write(encoded)
        except (BrokenPipeError, ConnectionResetError):
            pass
        _audit(response, self.command)

    def log_message(self, _format: str, *args: object) -> None:
        """Suppress BaseHTTPRequestHandler's raw request logging."""


def main() -> int:
    os.umask(0o077)
    if os.geteuid() != 2000 or os.getegid() != 2000:
        print('{"event":"startup_failed","code":"non_root_identity_mismatch"}', file=sys.stderr)
        return 1
    try:
        verifier = TokenVerifier.from_file(TOKEN_VERIFIER_FILE)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        with open_verified_file(TLS_CERT_FILE, private=False) as cert_descriptor:
            with open_verified_file(TLS_KEY_FILE, private=True) as key_descriptor:
                context.load_cert_chain(
                    descriptor_path(cert_descriptor), descriptor_path(key_descriptor)
                )
        server = CollectorHttpServer((BIND_ADDRESS, BIND_PORT), CollectorRequestHandler)
        server.collector_api = CollectorApi(verifier)  # type: ignore[attr-defined]
        server.socket = context.wrap_socket(server.socket, server_side=True)
    except (OSError, ValueError, json.JSONDecodeError, ssl.SSLError):
        print('{"event":"startup_failed","code":"invalid_private_configuration"}', file=sys.stderr)
        return 1

    print(
        json.dumps(
            {
                "event": "service_started",
                "bind": BIND_ADDRESS,
                "port": BIND_PORT,
                "transport": "https",
            },
            separators=(",", ":"),
        ),
        flush=True,
    )
    signal.signal(signal.SIGTERM, _request_stop)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        print('{"event":"service_stopped"}', flush=True)
    return 0


def _audit(response: ApiResponse, method: str) -> None:
    print(
        json.dumps(
            {
                "event": "request_completed",
                "request_id": response.request_id,
                "method": method,
                "route": response.route,
                "status": response.status,
            },
            separators=(",", ":"),
        ),
        flush=True,
    )


def _request_stop(_signum: int, _frame: object) -> None:
    raise KeyboardInterrupt


if __name__ == "__main__":
    raise SystemExit(main())
