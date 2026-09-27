"""Persistent managed API credentials and Supervisor discovery bootstrap."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
from http.client import HTTPException
import json
from pathlib import Path
import re
import secrets
import threading
from typing import Callable, Mapping
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from .api import ApiResponse, EXPECTED_SCOPES, METER_ID_PATTERN, SHA256_PATTERN, TOKEN_PATTERN
from .managed_identity import ManagedIdentity
from .security_files import atomic_write_private, read_private_file


PAIRING_STATE_FILE = Path("/data/cez-pnd-identity/pairing-state.json")
PAIRING_SCHEMA_VERSION = 1
PAIRING_STATE_SCHEMA_VERSION = 2
PAIRING_PREFIX = "/pairing/v1"
SUPERVISOR_DISCOVERY_URL = "http://supervisor/discovery"
MAX_STATE_BYTES = 16 * 1024
MAX_DISCOVERY_BYTES = 16 * 1024
MAX_PAIRING_BODY_BYTES = 2048
BOOTSTRAP_LIFETIME = timedelta(minutes=10)
PENDING_LIFETIME = timedelta(hours=24)
MAX_BOOTSTRAP_ATTEMPTS = 8
PAIRING_ID_PATTERN = re.compile(r"^[a-f0-9]{32}$")
DISCOVERY_UUID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
PEM_CERTIFICATE_BEGIN = "-----BEGIN " + "CERTIFICATE-----\n"


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        raise ValueError("Supervisor discovery redirected")


@dataclass(frozen=True)
class PairingBootstrap:
    pairing_id: str
    secret: str = field(repr=False)
    expires_at: str


class ManagedCredentialStore:
    """One ACTIVE, one PENDING, and one bounded bootstrap authorization."""

    def __init__(self, meter_id: str, path: Path = PAIRING_STATE_FILE) -> None:
        self.meter_id = meter_id
        self.scopes = EXPECTED_SCOPES
        self.path = path
        self._lock = threading.RLock()
        if path.exists():
            self._read()

    def authorize(self, authorization: str | None, scope: str) -> bool:
        state = self._read()
        return scope in self.scopes and _authorization_matches(
            authorization, state.get("active_token_sha256")
        )

    def create_bootstrap(self, *, now: datetime | None = None) -> PairingBootstrap | None:
        with self._lock:
            current = _utc_now(now)
            state = self._read()
            if state["state"] == "active":
                return None
            if state["state"] == "pending" and not _expired(state["pending_expires_at"], current):
                return None
            secret = secrets.token_urlsafe(32)
            pairing_id = secrets.token_hex(16)
            expires = _utc_text(current + BOOTSTRAP_LIFETIME)
            self._write(
                {
                    **_empty_state(),
                    "state": "bootstrap_available",
                    "pairing_id": pairing_id,
                    "bootstrap_sha256": _digest(secret),
                    "bootstrap_expires_at": expires,
                    "active_token_sha256": state.get("active_token_sha256"),
                    "discovery_uuid": state.get("discovery_uuid"),
                }
            )
            return PairingBootstrap(pairing_id, secret, expires)

    def set_discovery_uuid(self, discovery_uuid: str | None) -> None:
        if discovery_uuid is not None and not DISCOVERY_UUID_PATTERN.fullmatch(discovery_uuid):
            raise ValueError("invalid discovery UUID")
        with self._lock:
            state = self._read()
            state["discovery_uuid"] = discovery_uuid
            self._write(state)

    def discovery_uuid(self) -> str | None:
        return self._read().get("discovery_uuid")

    def claim(self, pairing_id: object, secret: object, verifier: object, *, now: datetime | None = None) -> str:
        with self._lock:
            current = _utc_now(now)
            state = self._read()
            if state["state"] in {"pending", "active"}:
                if state["state"] == "pending" and _expired(
                    state["pending_expires_at"], current
                ):
                    return "pairing_bootstrap_unavailable"
                expected_verifier = (
                    state["pending_token_sha256"]
                    if state["state"] == "pending"
                    else state["active_token_sha256"]
                )
                if not _matching_pairing_authorization(state, pairing_id, secret):
                    return "pairing_authorization_invalid"
                if not isinstance(verifier, str) or not SHA256_PATTERN.fullmatch(verifier):
                    return "pairing_verifier_invalid"
                return (
                    "pairing_claimed"
                    if hmac.compare_digest(verifier, expected_verifier)
                    else "pairing_verifier_conflict"
                )
            if state["state"] != "bootstrap_available":
                return "pairing_bootstrap_unavailable"
            if _expired(state["bootstrap_expires_at"], current):
                return "pairing_bootstrap_expired"
            if state["bootstrap_attempts"] >= MAX_BOOTSTRAP_ATTEMPTS:
                return "pairing_attempt_limit"
            if not isinstance(pairing_id, str) or not PAIRING_ID_PATTERN.fullmatch(pairing_id):
                self._failed_attempt(state)
                return "pairing_authorization_invalid"
            if not isinstance(secret, str) or not TOKEN_PATTERN.fullmatch(secret):
                self._failed_attempt(state)
                return "pairing_authorization_invalid"
            if not isinstance(verifier, str) or not SHA256_PATTERN.fullmatch(verifier):
                return "pairing_verifier_invalid"
            matches = hmac.compare_digest(pairing_id, state["pairing_id"]) & hmac.compare_digest(
                _digest(secret), state["bootstrap_sha256"]
            )
            if not matches:
                self._failed_attempt(state)
                return "pairing_authorization_invalid"
            state.update(
                state="pending",
                pending_token_sha256=verifier,
                pending_expires_at=_utc_text(current + PENDING_LIFETIME),
                bootstrap_attempts=0,
            )
            self._write(state)
            return "pairing_claimed"

    def activate(self, authorization: str | None, *, now: datetime | None = None) -> str:
        with self._lock:
            current = _utc_now(now)
            state = self._read()
            if _authorization_matches(authorization, state.get("active_token_sha256")):
                return "pairing_activated"
            if state["state"] != "pending" or _expired(state["pending_expires_at"], current):
                return "pairing_pending_unavailable"
            if not _authorization_matches(authorization, state["pending_token_sha256"]):
                return "pairing_pending_unauthorized"
            state.update(
                state="active",
                active_token_sha256=state["pending_token_sha256"],
                pending_token_sha256=None,
                pending_expires_at=None,
                bootstrap_attempts=0,
            )
            self._write(state)
            return "pairing_activated"

    def complete_finalize(self) -> None:
        """Clear only recovery/discovery material after external cleanup."""

        with self._lock:
            state = self._read()
            if state["state"] != "active" or state["active_token_sha256"] is None:
                raise ValueError("pairing_active_unavailable")
            state.update(
                pairing_id=None,
                bootstrap_sha256=None,
                bootstrap_expires_at=None,
                discovery_uuid=None,
            )
            self._write(state)

    def _failed_attempt(self, state: dict[str, object]) -> None:
        state["bootstrap_attempts"] = int(state["bootstrap_attempts"]) + 1
        self._write(state)

    def _read(self) -> dict[str, object]:
        if not self.path.exists():
            return _empty_state()
        try:
            raw = json.loads(read_private_file(self.path, maximum_bytes=MAX_STATE_BYTES).decode("utf-8"))
            _validate_state(raw)
            return raw
        except (OSError, UnicodeError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise ValueError("pairing_state_invalid") from error

    def _write(self, state: dict[str, object]) -> None:
        _validate_state(state)
        atomic_write_private(
            self.path,
            json.dumps(state, sort_keys=True, separators=(",", ":")).encode("utf-8"),
            maximum_bytes=MAX_STATE_BYTES,
        )


class PairingApi:
    """Three explicit pairing operations isolated from the read API."""

    def __init__(self, credentials: ManagedCredentialStore,
                 on_finalize: Callable[[], None] | None = None,
                 emit: Callable[[dict[str, object]], None] | None = None) -> None:
        self.credentials = credentials
        self._on_finalize = on_finalize
        self._emit = emit or (lambda _event: None)

    def handle(self, method: str, target: str, headers: Mapping[str, str], body: bytes) -> ApiResponse:
        request_id = secrets.token_hex(8)
        if target not in {
            f"{PAIRING_PREFIX}/claim",
            f"{PAIRING_PREFIX}/activate",
            f"{PAIRING_PREFIX}/finalize",
        }:
            return _pairing_response(404, "pairing_not_found", request_id, "unknown")
        if method != "POST":
            return _pairing_response(405, "pairing_method_not_allowed", request_id, target)
        if _header(headers, "Content-Type") != "application/json":
            return _pairing_response(400, "pairing_request_invalid", request_id, target)
        if len(body) > MAX_PAIRING_BODY_BYTES:
            return _pairing_response(413, "pairing_request_too_large", request_id, target)
        if target.endswith("/claim"):
            try:
                payload = _strict_json_object(body)
            except (UnicodeError, ValueError, json.JSONDecodeError, RecursionError):
                return _pairing_response(400, "pairing_request_invalid", request_id, target)
            if set(payload) != {
                "pairing_schema_version", "pairing_id", "pairing_secret", "api_token_sha256"
            } or type(payload["pairing_schema_version"]) is not int or payload["pairing_schema_version"] != 1:
                return _pairing_response(400, "pairing_request_invalid", request_id, target)
            try:
                code = self.credentials.claim(
                    payload["pairing_id"], payload["pairing_secret"], payload["api_token_sha256"]
                )
            except (OSError, ValueError):
                self._emit({"event": "pairing_claim_failed"})
                return _pairing_response(503, "pairing_state_unavailable", request_id, target)
            self._emit({"event": "pairing_claim_succeeded" if code == "pairing_claimed" else "pairing_claim_failed"})
            return _pairing_response(200 if code == "pairing_claimed" else 401, code, request_id, target)
        if body:
            try:
                payload = _strict_json_object(body)
            except (UnicodeError, ValueError, json.JSONDecodeError, RecursionError):
                return _pairing_response(400, "pairing_request_invalid", request_id, target)
            if payload:
                return _pairing_response(400, "pairing_request_invalid", request_id, target)
        authorization = _header(headers, "Authorization")
        if target.endswith("/activate"):
            try:
                code = self.credentials.activate(authorization)
            except (OSError, ValueError):
                self._emit({"event": "pairing_activation_failed"})
                return _pairing_response(503, "pairing_state_unavailable", request_id, target)
            self._emit({"event": "pairing_activated" if code == "pairing_activated" else "pairing_activation_failed"})
            return _pairing_response(200 if code == "pairing_activated" else 401, code, request_id, target)
        if not self.credentials.authorize(authorization, "health:read"):
            self._emit({"event": "pairing_finalize_failed"})
            return _pairing_response(401, "pairing_active_unauthorized", request_id, target)
        try:
            if self._on_finalize is None:
                raise ValueError("pairing_finalize_unavailable")
            self._on_finalize()
        except (HTTPException, OSError, ValueError):
            self._emit({"event": "pairing_finalize_failed"})
            return _pairing_response(503, "pairing_finalize_unavailable", request_id, target)
        self._emit({"event": "pairing_finalized"})
        return _pairing_response(200, "pairing_finalized", request_id, target)


class SupervisorDiscoveryClient:
    """Fixed local bounded Supervisor discovery client."""

    def __init__(self, supervisor_token: str) -> None:
        if not isinstance(supervisor_token, str) or not supervisor_token or len(supervisor_token) > 8192 or any(c.isspace() for c in supervisor_token):
            raise ValueError("invalid Supervisor token")
        self._token = supervisor_token

    def publish(self, payload: dict[str, object]) -> str:
        _validate_discovery_payload(payload)
        body = json.dumps({"service": "cez_pnd", "config": payload}, separators=(",", ":")).encode("utf-8")
        if len(body) > MAX_DISCOVERY_BYTES:
            raise ValueError("discovery payload too large")
        response = self._request(SUPERVISOR_DISCOVERY_URL, "POST", body)
        uuid = response.get("uuid")
        if not isinstance(uuid, str) or not DISCOVERY_UUID_PATTERN.fullmatch(uuid):
            raise ValueError("invalid discovery response")
        return uuid

    def remove(self, discovery_uuid: str) -> None:
        if not DISCOVERY_UUID_PATTERN.fullmatch(discovery_uuid):
            raise ValueError("invalid discovery UUID")
        self._request(
            f"{SUPERVISOR_DISCOVERY_URL}/{discovery_uuid}",
            "DELETE",
            None,
            not_found_ok=True,
        )

    def _request(
        self,
        url: str,
        method: str,
        body: bytes | None,
        *,
        not_found_ok: bool = False,
    ) -> dict[str, object]:
        request = Request(url, data=body, method=method, headers={
            "Authorization": f"Bearer {self._token}", "Accept": "application/json",
            "Content-Type": "application/json",
        })
        try:
            with build_opener(ProxyHandler({}), _RejectRedirects()).open(
                request, timeout=5.0
            ) as response:
                if response.status != 200:
                    raise ValueError("Supervisor discovery failed")
                raw = response.read(4097)
        except HTTPError as error:
            if not_found_ok and method == "DELETE" and error.code == 404:
                return {}
            raise ValueError("Supervisor discovery failed") from error
        except (URLError, HTTPException, TimeoutError, OSError, ValueError) as error:
            raise ValueError("Supervisor discovery failed") from error
        if len(raw) > 4096:
            raise ValueError("Supervisor discovery response too large")
        try:
            envelope = _strict_json_object(raw)
        except (UnicodeError, ValueError, json.JSONDecodeError, RecursionError) as error:
            raise ValueError("invalid discovery response") from error
        if envelope.get("result") != "ok":
            raise ValueError("invalid discovery response")
        if method == "DELETE" and envelope.get("data") is None:
            return {}
        if not isinstance(envelope.get("data"), dict):
            raise ValueError("invalid discovery response")
        return envelope["data"]


class PairingDiscoveryWorker:
    """Publish and renew a single short-lived bootstrap without blocking service."""

    def __init__(self, identity: ManagedIdentity, credentials: ManagedCredentialStore,
                 supervisor: SupervisorDiscoveryClient, emit: Callable[[dict[str, object]], None]) -> None:
        self.identity, self.credentials, self.supervisor, self.emit = identity, credentials, supervisor, emit
        self._stop = threading.Event()
        self._finalize_lock = threading.Lock()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="pairing-discovery", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=6.0)

    def finalize(self) -> None:
        """Remove discovery and clear recovery state without revoking ACTIVE."""

        with self._finalize_lock:
            discovery_uuid = self.credentials.discovery_uuid()
            if discovery_uuid is not None:
                self.supervisor.remove(discovery_uuid)
                self.emit({"event": "pairing_discovery_removed"})
            self.credentials.complete_finalize()

    def _run(self) -> None:
        self._publish_new()
        while not self._stop.wait(60.0):
            try:
                state = self.credentials._read()
                current = _utc_now()
                expired_bootstrap = state["state"] == "bootstrap_available" and _expired(state["bootstrap_expires_at"], current)
                expired_pending = state["state"] == "pending" and _expired(state["pending_expires_at"], current)
            except (OSError, ValueError):
                self.emit({"event": "pairing_state_failed"})
                return
            if expired_bootstrap or expired_pending:
                if expired_bootstrap:
                    self.emit({"event": "pairing_bootstrap_expired"})
                self._publish_new()

    def _publish_new(self) -> None:
        with self._finalize_lock, self.credentials._lock:
            try:
                state = self.credentials._read()
                current = _utc_now()
            except (OSError, ValueError):
                self.emit({"event": "pairing_state_failed"})
                return

            state_name = state["state"]
            still_valid = (
                state_name == "active"
                or (
                    state_name == "pending"
                    and not _expired(state["pending_expires_at"], current)
                )
                or (
                    state_name == "bootstrap_available"
                    and state.get("discovery_uuid") is not None
                    and not _expired(state["bootstrap_expires_at"], current)
                )
            )
            if still_valid:
                return

            old_uuid = state.get("discovery_uuid")
            if old_uuid:
                try:
                    self.supervisor.remove(old_uuid)
                except (HTTPException, OSError, ValueError):
                    self.emit({"event": "pairing_discovery_failed"})
                    return
                try:
                    self.credentials.set_discovery_uuid(None)
                    self.emit({"event": "pairing_discovery_removed"})
                except (OSError, ValueError):
                    self.emit({"event": "pairing_state_failed"})
                    return
            try:
                bootstrap = self.credentials.create_bootstrap(now=current)
            except (OSError, ValueError):
                self.emit({"event": "pairing_state_failed"})
                return
            if bootstrap is None:
                return
            payload = {
                "pairing_schema_version": 1,
                "meter_id": self.identity.meter_id,
                "ca_certificate": self.identity.ca_certificate_pem,
                "pairing_id": bootstrap.pairing_id,
                "pairing_secret": bootstrap.secret,
                "expires_at": bootstrap.expires_at,
                "api_port": 8443,
            }
            for attempt in range(3):
                try:
                    discovery_uuid = self.supervisor.publish(payload)
                    try:
                        self.credentials.set_discovery_uuid(discovery_uuid)
                    except (OSError, ValueError):
                        self.emit({"event": "pairing_state_failed"})
                        return
                    self.emit({"event": "pairing_discovery_published"})
                    return
                except (HTTPException, OSError, ValueError):
                    if attempt < 2 and not self._stop.wait(2 ** attempt):
                        continue
                    break
            self.emit({"event": "pairing_discovery_failed"})


def _empty_state() -> dict[str, object]:
    return {
        "schema_version": PAIRING_STATE_SCHEMA_VERSION, "state": "unpaired", "active_token_sha256": None,
        "pending_token_sha256": None, "pending_expires_at": None, "pairing_id": None,
        "bootstrap_sha256": None, "bootstrap_expires_at": None,
        "bootstrap_attempts": 0, "discovery_uuid": None,
    }


def _validate_discovery_payload(payload: object) -> None:
    expected = {
        "pairing_schema_version", "meter_id", "ca_certificate", "pairing_id",
        "pairing_secret", "expires_at", "api_port",
    }
    if not isinstance(payload, dict) or set(payload) != expected:
        raise ValueError("invalid discovery payload")
    if (
        type(payload["pairing_schema_version"]) is not int
        or payload["pairing_schema_version"] != 1
        or type(payload["api_port"]) is not int
        or payload["api_port"] != 8443
    ):
        raise ValueError("invalid discovery payload")
    if not isinstance(payload["meter_id"], str) or not METER_ID_PATTERN.fullmatch(payload["meter_id"]):
        raise ValueError("invalid discovery payload")
    certificate = payload["ca_certificate"]
    if not isinstance(certificate, str) or not certificate.startswith(PEM_CERTIFICATE_BEGIN) or len(certificate.encode("ascii")) > 8 * 1024:
        raise ValueError("invalid discovery payload")
    if not isinstance(payload["pairing_id"], str) or not PAIRING_ID_PATTERN.fullmatch(payload["pairing_id"]):
        raise ValueError("invalid discovery payload")
    if not isinstance(payload["pairing_secret"], str) or not TOKEN_PATTERN.fullmatch(payload["pairing_secret"]):
        raise ValueError("invalid discovery payload")
    _parse_utc(payload["expires_at"])


def _validate_state(raw: object) -> None:
    expected = set(_empty_state())
    if (
        not isinstance(raw, dict)
        or set(raw) != expected
        or type(raw["schema_version"]) is not int
        or raw["schema_version"] != PAIRING_STATE_SCHEMA_VERSION
    ):
        raise ValueError("invalid pairing state")
    if raw["state"] not in {"unpaired", "bootstrap_available", "pending", "active"}:
        raise ValueError("invalid pairing state")
    if type(raw["bootstrap_attempts"]) is not int or not 0 <= raw["bootstrap_attempts"] <= MAX_BOOTSTRAP_ATTEMPTS:
        raise ValueError("invalid pairing attempts")
    for key in ("active_token_sha256", "pending_token_sha256", "bootstrap_sha256"):
        value = raw[key]
        if value is not None and (not isinstance(value, str) or not SHA256_PATTERN.fullmatch(value)):
            raise ValueError("invalid verifier")
    if raw["pairing_id"] is not None and (not isinstance(raw["pairing_id"], str) or not PAIRING_ID_PATTERN.fullmatch(raw["pairing_id"])):
        raise ValueError("invalid pairing id")
    for key in ("pending_expires_at", "bootstrap_expires_at"):
        if raw[key] is not None:
            _parse_utc(raw[key])
    if raw["discovery_uuid"] is not None and (not isinstance(raw["discovery_uuid"], str) or not DISCOVERY_UUID_PATTERN.fullmatch(raw["discovery_uuid"])):
        raise ValueError("invalid discovery UUID")
    state = raw["state"]
    if state == "unpaired":
        if any(raw[key] is not None for key in (
            "active_token_sha256", "pending_token_sha256", "pending_expires_at",
            "pairing_id", "bootstrap_sha256", "bootstrap_expires_at"
        )) or raw["bootstrap_attempts"] != 0:
            raise ValueError("incomplete pairing state")
    elif state == "bootstrap_available":
        if any(raw[key] is None for key in ("pairing_id", "bootstrap_sha256", "bootstrap_expires_at")) or any(
            raw[key] is not None for key in ("pending_token_sha256", "pending_expires_at")
        ):
            raise ValueError("incomplete pairing state")
    elif state == "pending":
        if any(raw[key] is None for key in (
            "pending_token_sha256", "pending_expires_at", "pairing_id",
            "bootstrap_sha256", "bootstrap_expires_at"
        )) or raw["bootstrap_attempts"] != 0:
            raise ValueError("incomplete pairing state")
    elif state == "active":
        recovery_values = (
            raw["pairing_id"], raw["bootstrap_sha256"], raw["bootstrap_expires_at"]
        )
        if raw["active_token_sha256"] is None or any(raw[key] is not None for key in (
            "pending_token_sha256", "pending_expires_at"
        )) or not (all(value is None for value in recovery_values) or all(
            value is not None for value in recovery_values
        )) or raw["bootstrap_attempts"] != 0:
            raise ValueError("incomplete pairing state")


def _matching_pairing_authorization(
    state: Mapping[str, object], pairing_id: object, secret: object
) -> bool:
    if (
        not isinstance(pairing_id, str)
        or not PAIRING_ID_PATTERN.fullmatch(pairing_id)
        or not isinstance(secret, str)
        or not TOKEN_PATTERN.fullmatch(secret)
        or not isinstance(state.get("pairing_id"), str)
        or not isinstance(state.get("bootstrap_sha256"), str)
    ):
        return False
    return hmac.compare_digest(pairing_id, state["pairing_id"]) & hmac.compare_digest(
        _digest(secret), state["bootstrap_sha256"]
    )


def _authorization_matches(authorization: str | None, verifier: object) -> bool:
    if not isinstance(verifier, str) or authorization is None:
        return False
    scheme, separator, token = authorization.partition(" ")
    if separator != " " or scheme != "Bearer" or not TOKEN_PATTERN.fullmatch(token):
        return False
    return hmac.compare_digest(_digest(token), verifier)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _utc_now(value: datetime | None = None) -> datetime:
    current = value or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValueError("timezone required")
    return current.astimezone(timezone.utc)


def _utc_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_utc(value: object) -> datetime:
    if not isinstance(value, str) or len(value) != 20 or not value.endswith("Z"):
        raise ValueError("invalid UTC timestamp")
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    if _utc_text(parsed) != value:
        raise ValueError("invalid UTC timestamp")
    return parsed


def _expired(value: object, now: datetime) -> bool:
    return value is None or _parse_utc(value) <= now


def _header(headers: Mapping[str, str], name: str) -> str | None:
    return next((value for key, value in headers.items() if key.lower() == name.lower()), None)


def _strict_json_object(raw: bytes) -> dict[str, object]:
    """Decode one JSON object while rejecting duplicate keys and non-finite values."""

    def exact_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def reject_constant(_value: str) -> object:
        raise ValueError("invalid JSON constant")

    decoded = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=exact_object,
        parse_constant=reject_constant,
    )
    if not isinstance(decoded, dict):
        raise ValueError("JSON object required")
    return decoded


def _pairing_response(status: int, code: str, request_id: str, route: str) -> ApiResponse:
    return ApiResponse(status, {"pairing_schema_version": 1, "status": code}, route, request_id)
