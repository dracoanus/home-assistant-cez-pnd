"""TLS server entry point for the offline Collector API skeleton."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
import signal
import socket
import ssl
import sys
import threading
import time

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
from .structured_logging import structured_event_json, write_json_line
from .event_broker import EventBroker
from .shutdown import ShutdownWatchdog
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
MAX_ACTIVE_HANDLERS = 8
SOCKET_TIMEOUT_SECONDS = 5.0
REQUEST_DEADLINE_SECONDS = 35.0
HANDLER_STOP_BUDGET_SECONDS = 5.0


class CollectorHttpServer(HTTPServer):
    """Small bounded HTTP server for the internal HA App network."""

    request_queue_size = 8

    def __init__(self, *args, **kwargs):
        self.event_broker = EventBroker()
        self._handlers_lock = threading.RLock()
        self._handlers: dict[threading.Thread, tuple[socket.socket, float]] = {}
        self._stopping = threading.Event()
        self._deadline_thread: threading.Thread | None = None
        super().__init__(*args, **kwargs)

    def get_request(self) -> tuple[socket.socket, tuple[str, int]]:
        connection, address = super().get_request()
        connection.settimeout(SOCKET_TIMEOUT_SECONDS)
        return connection, address

    def process_request(self, request, client_address) -> None:
        # Admission happens before spawning; the accept path never waits for TLS.
        with self._handlers_lock:
            if self._stopping.is_set() or len(self._handlers) >= MAX_ACTIVE_HANDLERS:
                self.close_request(request)
                return
            if self._deadline_thread is None:
                self._deadline_thread = threading.Thread(
                    target=self._expire_requests, name="collector-http-deadlines", daemon=True
                )
                self._deadline_thread.start()
            thread = threading.Thread(
                target=self._handle_request, args=(request, client_address),
                name="collector-http", daemon=True,
            )
            self._handlers[thread] = (request, time.monotonic() + REQUEST_DEADLINE_SECONDS)
            try:
                thread.start()
            except Exception:
                del self._handlers[thread]
                self.close_request(request)

    def _handle_request(self, request, client_address) -> None:
        try:
            if isinstance(request, ssl.SSLSocket):
                request.do_handshake()
            if not self._stopping.is_set():
                self.finish_request(request, client_address)
        except Exception:
            # Never expose request contents or exception strings from a handler.
            pass
        finally:
            try:
                self.shutdown_request(request)
            except OSError:
                pass
            finally:
                with self._handlers_lock:
                    self._handlers.pop(threading.current_thread(), None)

    @staticmethod
    def _close_connection(connection: socket.socket) -> None:
        try:
            connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            connection.close()
        except OSError:
            pass

    def _expire_requests(self) -> None:
        # One bounded monitor enforces a wall-clock limit, including slow headers.
        while not self._stopping.wait(0.25):
            with self._handlers_lock:
                expired = [sock for sock, deadline in self._handlers.values()
                           if time.monotonic() >= deadline]
            for connection in expired:
                self._close_connection(connection)

    def begin_shutdown(self) -> None:
        with self._handlers_lock:
            self._stopping.set()
            connections = [sock for sock, _ in self._handlers.values()]
        self.event_broker.close()
        for connection in connections:
            self._close_connection(connection)

    def shutdown(self) -> None:
        self.begin_shutdown()
        super().shutdown()

    def server_close(self, *, deadline: float | None = None) -> bool:
        if deadline is None:
            deadline = time.monotonic() + HANDLER_STOP_BUDGET_SECONDS
        self.begin_shutdown()
        super().server_close()
        with self._handlers_lock:
            threads = list(self._handlers)
        if self._deadline_thread is not None:
            threads.append(self._deadline_thread)
        for thread in threads:
            if thread is not threading.current_thread():
                thread.join(max(0.0, deadline - time.monotonic()))
        return not any(thread.is_alive() for thread in threads)


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
        if response.status == 204:
            encoded = b""
        if len(encoded) > MAX_RESPONSE_BYTES:
            response = CollectorApi._error(
                503, "response_limit_exceeded", False, response.request_id, response.route
            )
            encoded = json.dumps(response.body, separators=(",", ":")).encode("utf-8")
        self.send_response(response.status)
        self.send_header("Content-Type", "application/json")
        if response.status != 204:
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
    # Start the guard before configuration, pairing, sync, or request activity.
    watchdog = ShutdownWatchdog()
    signal.signal(signal.SIGTERM, _shutdown_signal_handler(watchdog))
    os.umask(0o077)
    if os.geteuid() != 2000 or os.getegid() != 2000:
        write_json_line(
            structured_event_json(
                {"event": "startup_failed", "code": "non_root_identity_mismatch"}
            ),
            file=sys.stderr,
        )
        return 1
    try:
        configuration = load_runtime_configuration()
    except (PrivateConfigurationError, DiscoveryConfigurationError) as error:
        write_json_line(
            structured_event_json({"event": "startup_failed", "code": error.code}),
            file=sys.stderr,
        )
        return 1
    except (OSError, ValueError, json.JSONDecodeError):
        write_json_line(
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
            configuration.verifier, dataset_store, event_broker=server.event_broker
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
        write_json_line(
            structured_event_json(
                {"event": "startup_failed", "code": "invalid_private_configuration"}
            ),
            file=sys.stderr,
        )
        return 1

    try:
        return _serve(configuration, server, pairing_worker, dataset_store, watchdog)
    except KeyboardInterrupt:
        # A signal during startup still leaves the process guard armed.
        return 1


def _serve(configuration, server, pairing_worker, dataset_store, watchdog) -> int:
    sync_worker = None
    worker_stopped = True
    try:
        _start_message(configuration)
        if getattr(configuration, "managed_identity", None) is not None:
            _emit_pairing_event(
                {"event": "managed_identity_created" if configuration.managed_identity_created else "managed_identity_loaded"}
            )
            pairing_worker.start()
        sync_configuration = getattr(configuration, "sync", None)
        if sync_configuration is not None:
            from .sync_worker import SyncWorker

            sync_worker = SyncWorker(sync_configuration, store=dataset_store)
            sync_worker.start()
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        watchdog.arm()
        # Signal every component before the first join.
        if sync_worker is not None:
            sync_worker.request_stop()
        if pairing_worker is not None:
            pairing_worker.request_stop()
        if watchdog.remaining() > 0:
            server.begin_shutdown()
        worker_stopped = False
        if watchdog.remaining() > 0:
            worker_stopped = server.server_close(deadline=watchdog.cleanup_deadline) is not False
        if sync_worker is not None and watchdog.remaining() > 0:
            worker_stopped = sync_worker.stop(timeout=watchdog.remaining()) and worker_stopped
        if pairing_worker is not None and watchdog.remaining() > 0:
            worker_stopped = pairing_worker.stop(timeout=watchdog.remaining()) and worker_stopped
        # Never begin potentially blocking logging after the shared budget.
        if watchdog.remaining() > 0 and worker_stopped:
            write_json_line(structured_event_json({"event": "service_stopped"}), flush=True)
        else:
            # Wait for the independent fail-stop; do not exit with live writers.
            threading.Event().wait()
    return 0 if worker_stopped else 1


def _start_message(configuration) -> None:
    write_json_line(
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


def _audit(response: ApiResponse, method: str) -> None:
    write_json_line(
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


def _shutdown_signal_handler(watchdog):
    def signal_stop(signum: int, frame: object) -> None:
        # An armed deadline is the irreversible service shutdown state.
        # Repeated signals cannot interrupt cleanup or partial guard arming.
        if watchdog.deadline is not None:
            return
        watchdog.arm()
        _request_stop(signum, frame)
    return signal_stop


def _emit_pairing_event(event: dict[str, object]) -> None:
    write_json_line(structured_event_json(event), flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
