"""TLS server entry point for the offline Collector API skeleton."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
import signal
import socket
import ssl
import sys

from .api import ApiResponse, CollectorApi
from .cez_discovery import emit_json_event, run_discovery
from .cez_http_auth import (
    AuthStatus,
    CezHttpAuthClient,
    SafeHttpAuthEvent,
    emit_json_event as emit_http_auth_json_event,
)
from .runtime_config import (
    DiscoveryConfigurationError,
    PrivateConfigurationError,
    load_runtime_configuration,
)
from .structured_logging import structured_event_json
from .dataset_store import NormalizedDatasetStore
from .pairing import (
    MAX_PAIRING_BODY_BYTES,
    PairingApi,
    PairingDiscoveryWorker,
    SupervisorDiscoveryClient,
)


BIND_ADDRESS = "0.0.0.0"
BIND_PORT = 8443
MAX_RESPONSE_BYTES = 1024 * 1024


class CollectorHttpServer(HTTPServer):
    """Small bounded HTTP server for the internal HA App network."""

    request_queue_size = 8

    def get_request(self) -> tuple[socket.socket, tuple[str, int]]:
        connection, address = super().get_request()
        connection.settimeout(5.0)
        if isinstance(connection, ssl.SSLSocket):
            try:
                connection.do_handshake()
            except Exception:
                connection.close()
                raise
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
        if self.path.split("?", 1)[0].startswith("/pairing/"):
            pairing_api: PairingApi | None = getattr(self.server, "pairing_api", None)
            if pairing_api is None:
                response = CollectorApi._error(404, "not_found", False, "unavailable", "unknown")
            else:
                body = self._read_pairing_body()
                if body is None:
                    response = CollectorApi._error(400, "invalid_request_body", False, "unavailable", "unknown")
                else:
                    response = pairing_api.handle(self.command, self.path, self.headers, body)
        else:
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

    def _read_pairing_body(self) -> bytes | None:
        if self.headers.get("Transfer-Encoding") is not None:
            return None
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            return b""
        try:
            length = int(raw_length)
        except ValueError:
            return None
        if not 0 <= length <= MAX_PAIRING_BODY_BYTES:
            return None
        return self.rfile.read(length)

    def log_message(self, _format: str, *args: object) -> None:
        """Suppress BaseHTTPRequestHandler's raw request logging."""


def main() -> int:
    os.umask(0o077)
    if os.geteuid() != 2000 or os.getegid() != 2000:
        print(
            structured_event_json(
                {"event": "startup_failed", "code": "non_root_identity_mismatch"}
            ),
            file=sys.stderr,
        )
        return 1
    try:
        configuration = load_runtime_configuration()
    except (PrivateConfigurationError, DiscoveryConfigurationError) as error:
        print(
            structured_event_json({"event": "startup_failed", "code": error.code}),
            file=sys.stderr,
        )
        return 1
    except (OSError, ValueError, json.JSONDecodeError):
        print(
            structured_event_json(
                {"event": "startup_failed", "code": "invalid_private_configuration"}
            ),
            file=sys.stderr,
        )
        return 1

    if configuration.discovery is not None:
        outcome = run_discovery(configuration.discovery, emit_json_event)
        return 0 if outcome.succeeded and outcome.cleanup_verified else 1

    if getattr(configuration, "requests_preauth_compatibility", False):
        from .requests_preauth import RequestsPreauthCompatibilityClient

        result = RequestsPreauthCompatibilityClient(
            emit=emit_http_auth_json_event,
        ).run()
        emit_http_auth_json_event(SafeHttpAuthEvent.from_result(result))
        return 0 if result.status is AuthStatus.NEEDS_LIVE_VERIFICATION else 1

    data_probe_configuration = getattr(configuration, "data_probe", None)
    if data_probe_configuration is not None:
        from .cez_data_probe import run_data_probe
        from .requests_preauth import RequestsSessionTransport

        try:
            transport = RequestsSessionTransport()
            result = run_data_probe(
                data_probe_configuration,
                transport,
                resolver=transport.resolve,
                emit=emit_http_auth_json_event,
            )
        except Exception:
            emit_http_auth_json_event(SafeHttpAuthEvent("data_probe_failed"))
            return 1
        emit_http_auth_json_event(SafeHttpAuthEvent.from_result(result))
        return 0 if result.status is AuthStatus.AUTHENTICATED else 1

    http_auth_configuration = getattr(configuration, "http_auth_discovery", None)
    if http_auth_configuration is not None:
        from .requests_preauth import RequestsSessionTransport

        try:
            transport = RequestsSessionTransport()
            result = CezHttpAuthClient(
                http_auth_configuration,
                transport,
                resolver=transport.resolve,
                emit=emit_http_auth_json_event,
            ).authenticate()
        except Exception:
            emit_http_auth_json_event(SafeHttpAuthEvent("protocol_error"))
            return 1
        emit_http_auth_json_event(SafeHttpAuthEvent.from_result(result))
        return 0 if result.status is AuthStatus.AUTHENTICATED else 1

    try:
        server = CollectorHttpServer((BIND_ADDRESS, BIND_PORT), CollectorRequestHandler)
        dataset_store = NormalizedDatasetStore()
        server.collector_api = CollectorApi(  # type: ignore[attr-defined]
            configuration.verifier, dataset_store
        )
        pairing_worker = None
        if getattr(configuration, "managed_identity", None) is not None:
            credentials = configuration.verifier
            supervisor = SupervisorDiscoveryClient(configuration.supervisor_token)
            pairing_worker = PairingDiscoveryWorker(
                configuration.managed_identity,
                credentials,
                supervisor,
                _emit_pairing_event,
            )
            server.pairing_api = PairingApi(  # type: ignore[attr-defined]
                credentials, pairing_worker.finalize, _emit_pairing_event
            )
        server.socket = configuration.tls_context.wrap_socket(
            server.socket,
            server_side=True,
            do_handshake_on_connect=False,
        )
    except (OSError, ValueError, json.JSONDecodeError):
        print(
            structured_event_json(
                {"event": "startup_failed", "code": "invalid_private_configuration"}
            ),
            file=sys.stderr,
        )
        return 1

    signal.signal(signal.SIGTERM, _request_stop)
    print(
        structured_event_json(
            {
                "event": "service_started",
                "bind": BIND_ADDRESS,
                "port": BIND_PORT,
                "transport": "https",
                "configuration_source": configuration.source,
            }
        ),
        flush=True,
    )
    if getattr(configuration, "managed_identity", None) is not None:
        _emit_pairing_event(
            {"event": "managed_identity_created" if configuration.managed_identity_created else "managed_identity_loaded"}
        )
        pairing_worker.start()
    sync_worker = None
    sync_configuration = getattr(configuration, "sync", None)
    if sync_configuration is not None:
        from .sync_worker import SyncWorker

        sync_worker = SyncWorker(sync_configuration, store=dataset_store)
        sync_worker.start()
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        if sync_worker is not None:
            sync_worker.stop()
        if pairing_worker is not None:
            pairing_worker.stop()
        server.server_close()
        print(structured_event_json({"event": "service_stopped"}), flush=True)
    return 0


def _audit(response: ApiResponse, method: str) -> None:
    print(
        structured_event_json(
            {
                "event": "request_completed",
                "request_id": response.request_id,
                "method": method,
                "route": response.route,
                "status": response.status,
            }
        ),
        flush=True,
    )


def _request_stop(_signum: int, _frame: object) -> None:
    raise KeyboardInterrupt


def _emit_pairing_event(event: dict[str, object]) -> None:
    print(structured_event_json(event), flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
