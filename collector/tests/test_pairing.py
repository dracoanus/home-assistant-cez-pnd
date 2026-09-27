"""Managed pairing state and Supervisor discovery tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
from http.client import IncompleteRead
import json
from pathlib import Path
import secrets
import tempfile
import threading
import unittest
from unittest import mock
from types import SimpleNamespace

from collector_service.api import SYNTHETIC_METER_ID
from collector_service import pairing


NOW = datetime(2026, 9, 12, 12, 0, tzinfo=timezone.utc)
SYNTHETIC_CA = pairing.PEM_CERTIFICATE_BEGIN + "synthetic\n-----END " + "CERTIFICATE-----\n"


class PairingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "pairing.json"
        self.patches = (
            mock.patch.object(pairing, "atomic_write_private", side_effect=lambda path, content, **_: path.write_bytes(content)),
            mock.patch.object(pairing, "read_private_file", side_effect=lambda path, **_: path.read_bytes()),
        )
        for patcher in self.patches:
            patcher.start()
        self.store = pairing.ManagedCredentialStore(SYNTHETIC_METER_ID, self.path)
        self.token = secrets.token_urlsafe(32)
        self.verifier = hashlib.sha256(self.token.encode("ascii")).hexdigest()

    def tearDown(self) -> None:
        for patcher in reversed(self.patches):
            patcher.stop()
        self.temporary.cleanup()

    def _bootstrap(self):
        return self.store.create_bootstrap(now=NOW)

    def test_claim_persists_pending_and_pending_cannot_read_api(self) -> None:
        bootstrap = self._bootstrap()
        self.assertEqual(self.store.claim(bootstrap.pairing_id, bootstrap.secret, self.verifier, now=NOW), "pairing_claimed")
        reloaded = pairing.ManagedCredentialStore(SYNTHETIC_METER_ID, self.path)
        self.assertFalse(reloaded.authorize(f"Bearer {self.token}", "health:read"))
        self.assertEqual(reloaded._read()["state"], "pending")
        self.assertNotIn(bootstrap.secret, self.path.read_text(encoding="utf-8"))

    def test_activation_promotes_only_matching_pending_and_is_idempotent(self) -> None:
        bootstrap = self._bootstrap()
        self.store.claim(bootstrap.pairing_id, bootstrap.secret, self.verifier, now=NOW)
        self.assertEqual(self.store.activate("Bearer " + secrets.token_urlsafe(32), now=NOW), "pairing_pending_unauthorized")
        self.assertEqual(self.store.activate(f"Bearer {self.token}", now=NOW), "pairing_activated")
        reloaded = pairing.ManagedCredentialStore(SYNTHETIC_METER_ID, self.path)
        self.assertTrue(reloaded.authorize(f"Bearer {self.token}", "status:read"))
        self.assertTrue(self.store.authorize(f"Bearer {self.token}", "health:read"))
        self.assertEqual(self.store.activate(f"Bearer {self.token}", now=NOW), "pairing_activated")
        self.assertEqual(
            self.store.claim(bootstrap.pairing_id, bootstrap.secret, self.verifier, now=NOW),
            "pairing_claimed",
        )
        self.assertEqual(
            self.store.claim(
                bootstrap.pairing_id,
                bootstrap.secret,
                hashlib.sha256(b"different-token").hexdigest(),
                now=NOW,
            ),
            "pairing_verifier_conflict",
        )

    def test_bootstrap_repr_does_not_expose_secret(self) -> None:
        bootstrap = self._bootstrap()
        self.assertNotIn(bootstrap.secret, repr(bootstrap))

    def test_expired_invalid_replayed_and_malformed_claims_fail(self) -> None:
        bootstrap = self._bootstrap()
        self.assertEqual(self.store.claim(bootstrap.pairing_id, "x" * 43, self.verifier, now=NOW), "pairing_authorization_invalid")
        self.assertEqual(self.store.claim(bootstrap.pairing_id, bootstrap.secret, "invalid", now=NOW), "pairing_verifier_invalid")
        self.assertEqual(self.store.claim(bootstrap.pairing_id, bootstrap.secret, self.verifier, now=NOW + timedelta(minutes=11)), "pairing_bootstrap_expired")
        fresh = self.store.create_bootstrap(now=NOW + timedelta(minutes=11))
        self.assertEqual(self.store.claim(fresh.pairing_id, fresh.secret, self.verifier, now=NOW + timedelta(minutes=11)), "pairing_claimed")
        self.assertEqual(self.store.claim(fresh.pairing_id, fresh.secret, self.verifier, now=NOW + timedelta(minutes=11)), "pairing_claimed")
        other_verifier = hashlib.sha256(b"different-token").hexdigest()
        self.assertEqual(self.store.claim(fresh.pairing_id, fresh.secret, other_verifier, now=NOW + timedelta(minutes=11)), "pairing_verifier_conflict")

    def test_concurrent_claims_create_only_one_pending(self) -> None:
        bootstrap = self._bootstrap()
        results = []
        def claim() -> None:
            results.append(self.store.claim(bootstrap.pairing_id, bootstrap.secret, self.verifier, now=NOW))
        threads = [threading.Thread(target=claim) for _ in range(2)]
        for thread in threads: thread.start()
        for thread in threads: thread.join()
        self.assertEqual(results, ["pairing_claimed", "pairing_claimed"])

    def test_attempt_limit_and_pending_expiry_are_bounded(self) -> None:
        bootstrap = self._bootstrap()
        for _ in range(pairing.MAX_BOOTSTRAP_ATTEMPTS):
            self.store.claim(bootstrap.pairing_id, "x" * 43, self.verifier, now=NOW)
        self.assertEqual(
            self.store.claim(bootstrap.pairing_id, bootstrap.secret, self.verifier, now=NOW),
            "pairing_attempt_limit",
        )
        replacement = self.store.create_bootstrap(now=NOW + timedelta(minutes=11))
        self.store.claim(replacement.pairing_id, replacement.secret, self.verifier, now=NOW + timedelta(minutes=11))
        self.assertEqual(
            self.store.activate(f"Bearer {self.token}", now=NOW + timedelta(hours=25)),
            "pairing_pending_unavailable",
        )
        self.assertEqual(
            self.store.claim(
                replacement.pairing_id,
                replacement.secret,
                self.verifier,
                now=NOW + timedelta(hours=25),
            ),
            "pairing_bootstrap_unavailable",
        )

    def test_pairing_api_is_bounded_exact_and_secret_free(self) -> None:
        bootstrap = self._bootstrap()
        api = pairing.PairingApi(self.store)
        body = json.dumps({
            "pairing_schema_version": 1, "pairing_id": bootstrap.pairing_id,
            "pairing_secret": bootstrap.secret, "api_token_sha256": self.verifier,
        }).encode()
        with mock.patch.object(pairing, "_utc_now", return_value=NOW):
            response = api.handle("POST", "/pairing/v1/claim", {"Content-Type": "application/json"}, body)
        self.assertEqual((response.status, response.body["status"]), (200, "pairing_claimed"))
        self.assertNotIn(bootstrap.secret, json.dumps(response.body))
        self.assertEqual(api.handle("GET", "/pairing/v1/claim", {}, b"").status, 405)
        headers = {"Content-Type": "application/json"}
        self.assertEqual(api.handle("POST", "/pairing/v1/claim?x=1", headers, body).status, 404)
        self.assertEqual(api.handle("POST", "/pairing/v1/claim", headers, b"x" * 2049).status, 413)

    def test_unknown_fields_and_malformed_activation_fail_closed(self) -> None:
        bootstrap = self._bootstrap()
        api = pairing.PairingApi(self.store)
        headers = {"Content-Type": "application/json"}
        claim = {
            "pairing_schema_version": 1,
            "pairing_id": bootstrap.pairing_id,
            "pairing_secret": bootstrap.secret,
            "api_token_sha256": self.verifier,
            "scope": "arbitrary",
        }
        self.assertEqual(
            api.handle("POST", "/pairing/v1/claim", headers, json.dumps(claim).encode()).status,
            400,
        )
        self.assertEqual(
            api.handle("POST", "/pairing/v1/activate", headers, b'{"unknown":true}').status,
            400,
        )
        self.assertEqual(
            api.handle("POST", "/pairing/v1/finalize", headers, b'{"unknown":true}').status,
            400,
        )

    def test_claim_rejects_duplicate_boolean_float_and_malformed_schema(self) -> None:
        bootstrap = self._bootstrap()
        credentials = mock.Mock()
        api = pairing.PairingApi(credentials)
        headers = {"Content-Type": "application/json"}
        common = (
            f'"pairing_id":"{bootstrap.pairing_id}",'
            f'"pairing_secret":"{bootstrap.secret}",'
            f'"api_token_sha256":"{self.verifier}"'
        )
        bodies = (
            (f'{{"pairing_schema_version":1,"pairing_schema_version":1,{common}}}').encode(),
            (f'{{"pairing_schema_version":true,{common}}}').encode(),
            (f'{{"pairing_schema_version":1.0,{common}}}').encode(),
            b'{"pairing_schema_version":',
        )
        for case, body in enumerate(bodies):
            with self.subTest(case=case):
                self.assertEqual(
                    api.handle("POST", "/pairing/v1/claim", headers, body).status,
                    400,
                )
        credentials.claim.assert_not_called()

    def test_activation_does_not_remove_discovery_and_finalize_is_retryable(self) -> None:
        bootstrap = self._bootstrap()
        self.store.claim(bootstrap.pairing_id, bootstrap.secret, self.verifier, now=NOW)
        events: list[dict[str, object]] = []
        finalize = mock.Mock(side_effect=ValueError("private"))
        api = pairing.PairingApi(self.store, on_finalize=finalize, emit=events.append)
        with mock.patch.object(pairing, "_utc_now", return_value=NOW):
            response = api.handle(
                "POST",
                "/pairing/v1/activate",
                {"Content-Type": "application/json", "Authorization": f"Bearer {self.token}"},
                b"{}",
            )
        self.assertEqual(response.status, 200)
        self.assertEqual(response.body["status"], "pairing_activated")
        self.assertTrue(self.store.authorize(f"Bearer {self.token}", "health:read"))
        self.assertEqual(events, [{"event": "pairing_activated"}])
        response = api.handle(
            "POST",
            "/pairing/v1/finalize",
            {"Content-Type": "application/json", "Authorization": f"Bearer {self.token}"},
            b"{}",
        )
        self.assertEqual((response.status, response.body["status"]), (503, "pairing_finalize_unavailable"))
        self.assertTrue(self.store.authorize(f"Bearer {self.token}", "health:read"))
        self.assertNotIn(self.token, json.dumps(events))
        self.assertNotIn(self.verifier, json.dumps(events))

    def test_finalize_removes_discovery_then_clears_recovery_and_is_idempotent(self) -> None:
        bootstrap = self._bootstrap()
        self.store.claim(bootstrap.pairing_id, bootstrap.secret, self.verifier, now=NOW)
        self.store.set_discovery_uuid("safe_uuid")
        self.store.activate(f"Bearer {self.token}", now=NOW)
        supervisor = mock.Mock()
        events: list[dict[str, object]] = []
        worker = pairing.PairingDiscoveryWorker(SimpleNamespace(), self.store, supervisor, events.append)
        api = pairing.PairingApi(self.store, on_finalize=worker.finalize, emit=events.append)
        headers = {"Content-Type": "application/json", "Authorization": f"Bearer {self.token}"}
        first = api.handle("POST", "/pairing/v1/finalize", headers, b"{}")
        second = api.handle("POST", "/pairing/v1/finalize", headers, b"{}")
        self.assertEqual((first.status, second.status), (200, 200))
        supervisor.remove.assert_called_once_with("safe_uuid")
        state = self.store._read()
        self.assertEqual(state["state"], "active")
        self.assertIsNone(state["discovery_uuid"])
        self.assertIsNone(state["pairing_id"])
        self.assertTrue(self.store.authorize(f"Bearer {self.token}", "health:read"))

    def test_finalize_rejects_non_active_token(self) -> None:
        api = pairing.PairingApi(self.store, on_finalize=mock.Mock())
        response = api.handle(
            "POST", "/pairing/v1/finalize",
            {"Content-Type": "application/json", "Authorization": "Bearer " + self.token}, b"{}"
        )
        self.assertEqual((response.status, response.body["status"]), (401, "pairing_active_unauthorized"))



class SupervisorDiscoveryTests(unittest.TestCase):
    def test_exact_endpoint_bearer_service_and_bounded_response(self) -> None:
        response = mock.MagicMock()
        response.status = 200
        response.read.return_value = b'{"result":"ok","data":{"uuid":"safe_uuid"}}'
        opener = mock.MagicMock()
        opener.open.return_value.__enter__.return_value = response
        client = pairing.SupervisorDiscoveryClient("platform-token")
        with mock.patch.object(pairing, "build_opener", return_value=opener) as build:
            payload = {
                "pairing_schema_version": 1,
                "meter_id": SYNTHETIC_METER_ID,
                "ca_certificate": SYNTHETIC_CA,
                "pairing_id": "a" * 32,
                "pairing_secret": "b" * 43,
                "expires_at": "2026-09-12T12:10:00Z",
                "api_port": 8443,
            }
            self.assertEqual(client.publish(payload), "safe_uuid")
        handlers = build.call_args.args
        self.assertTrue(any(isinstance(handler, pairing.ProxyHandler) for handler in handlers))
        proxy_handler = next(handler for handler in handlers if isinstance(handler, pairing.ProxyHandler))
        self.assertEqual(proxy_handler.proxies, {})
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, "http://supervisor/discovery")
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(request.get_header("Authorization"), "Bearer platform-token")
        self.assertEqual(json.loads(request.data)["service"], "cez_pnd")
        self.assertEqual(opener.open.call_args.kwargs["timeout"], 5.0)

    def test_errors_are_fixed_and_do_not_expose_token(self) -> None:
        secret = "platform-secret-token"
        opener = mock.Mock()
        opener.open.side_effect = OSError(secret)
        with mock.patch.object(pairing, "build_opener", return_value=opener), self.assertRaises(ValueError) as raised:
            pairing.SupervisorDiscoveryClient(secret).publish({
                "pairing_schema_version": 1,
                "meter_id": SYNTHETIC_METER_ID,
                "ca_certificate": SYNTHETIC_CA,
                "pairing_id": "a" * 32,
                "pairing_secret": "b" * 43,
                "expires_at": "2026-09-12T12:10:00Z",
                "api_port": 8443,
            })
        self.assertEqual(str(raised.exception), "Supervisor discovery failed")
        self.assertNotIn(secret, str(raised.exception))

    def test_incomplete_supervisor_response_is_normalized(self) -> None:
        response = mock.MagicMock()
        response.status = 200
        response.read.side_effect = IncompleteRead(b"private-response")
        opener = mock.MagicMock()
        opener.open.return_value.__enter__.return_value = response
        with mock.patch.object(pairing, "build_opener", return_value=opener):
            client = pairing.SupervisorDiscoveryClient("platform-token")
            with self.assertRaisesRegex(ValueError, "^Supervisor discovery failed$"):
                client.publish({
                    "pairing_schema_version": 1,
                    "meter_id": SYNTHETIC_METER_ID,
                    "ca_certificate": SYNTHETIC_CA,
                    "pairing_id": "a" * 32,
                    "pairing_secret": "b" * 43,
                    "expires_at": "2026-09-12T12:10:00Z",
                    "api_port": 8443,
                })

    def test_discovery_payload_is_exact_bounded_and_excludes_private_fields(self) -> None:
        base = {
            "pairing_schema_version": 1,
            "meter_id": SYNTHETIC_METER_ID,
            "ca_certificate": SYNTHETIC_CA,
            "pairing_id": "a" * 32,
            "pairing_secret": "b" * 43,
            "expires_at": "2026-09-12T12:10:00Z",
            "api_port": 8443,
        }
        pairing._validate_discovery_payload(base)
        for forbidden in (
            "cez_username", "cez_password", "cez_ean", "cez_elm", "api_token",
            "api_token_sha256", "ca_private_key", "server_private_key", "url", "hostname",
        ):
            with self.subTest(forbidden=forbidden), self.assertRaises(ValueError):
                pairing._validate_discovery_payload({**base, forbidden: "secret"})
        with self.assertRaises(ValueError):
            pairing._validate_discovery_payload({**base, "ca_certificate": pairing.PEM_CERTIFICATE_BEGIN + "x" * 9000})

    def test_worker_persists_returned_uuid_and_emits_no_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "pairing.json"
            with (
                mock.patch.object(pairing, "atomic_write_private", side_effect=lambda target, content, **_: target.write_bytes(content)),
                mock.patch.object(pairing, "read_private_file", side_effect=lambda target, **_: target.read_bytes()),
            ):
                credentials = pairing.ManagedCredentialStore(SYNTHETIC_METER_ID, path)
                supervisor = mock.Mock()
                supervisor.publish.return_value = "safe_uuid"
                events: list[dict[str, object]] = []
                identity = SimpleNamespace(
                    meter_id=SYNTHETIC_METER_ID,
                    ca_certificate_pem=SYNTHETIC_CA,
                )
                worker = pairing.PairingDiscoveryWorker(identity, credentials, supervisor, events.append)
                worker._publish_new()

                self.assertEqual(credentials.discovery_uuid(), "safe_uuid")
                payload = supervisor.publish.call_args.args[0]
                state_text = path.read_text(encoding="utf-8")
                self.assertNotIn(payload["pairing_secret"], state_text)
                self.assertEqual(events, [{"event": "pairing_discovery_published"}])
                self.assertEqual(set(payload), {
                    "pairing_schema_version", "meter_id", "ca_certificate", "pairing_id",
                    "pairing_secret", "expires_at", "api_port",
                })

    def test_worker_retry_is_bounded_and_nonfatal(self) -> None:
        credentials = mock.Mock()
        credentials._lock = threading.RLock()
        credentials._read.return_value = pairing._empty_state()
        credentials.create_bootstrap.return_value = pairing.PairingBootstrap(
            "a" * 32, "b" * 43, "2026-09-12T12:10:00Z"
        )
        supervisor = mock.Mock()
        supervisor.publish.side_effect = ValueError("sensitive detail")
        events: list[dict[str, object]] = []
        identity = SimpleNamespace(
            meter_id=SYNTHETIC_METER_ID,
            ca_certificate_pem=SYNTHETIC_CA,
        )
        worker = pairing.PairingDiscoveryWorker(identity, credentials, supervisor, events.append)
        with mock.patch.object(worker._stop, "wait", return_value=False) as wait:
            worker._publish_new()
        self.assertEqual(supervisor.publish.call_count, 3)
        self.assertEqual([call.args[0] for call in wait.call_args_list], [1, 2])
        self.assertEqual(events, [{"event": "pairing_discovery_failed"}])

    def test_worker_contains_corrupt_local_state_without_reset(self) -> None:
        credentials = mock.Mock()
        credentials._lock = threading.RLock()
        credentials._read.side_effect = ValueError("private state")
        events: list[dict[str, object]] = []
        worker = pairing.PairingDiscoveryWorker(
            SimpleNamespace(), credentials, mock.Mock(), events.append
        )
        worker._publish_new()
        self.assertEqual(events, [{"event": "pairing_state_failed"}])
        credentials.create_bootstrap.assert_not_called()

    def test_worker_restart_preserves_active_pending_and_valid_bootstrap_discovery(self) -> None:
        for state_name in ("active", "pending", "bootstrap_available"):
            with self.subTest(state=state_name), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "pairing.json"
                with (
                    mock.patch.object(pairing, "atomic_write_private", side_effect=lambda target, content, **_: target.write_bytes(content)),
                    mock.patch.object(pairing, "read_private_file", side_effect=lambda target, **_: target.read_bytes()),
                ):
                    credentials = pairing.ManagedCredentialStore(SYNTHETIC_METER_ID, path)
                    bootstrap = credentials.create_bootstrap(now=NOW)
                    token = secrets.token_urlsafe(32)
                    verifier = hashlib.sha256(token.encode("ascii")).hexdigest()
                    if state_name in {"pending", "active"}:
                        credentials.claim(bootstrap.pairing_id, bootstrap.secret, verifier, now=NOW)
                    if state_name == "active":
                        credentials.activate(f"Bearer {token}", now=NOW)
                    credentials.set_discovery_uuid("safe_uuid")
                    supervisor = mock.Mock()
                    worker = pairing.PairingDiscoveryWorker(
                        SimpleNamespace(meter_id=SYNTHETIC_METER_ID, ca_certificate_pem=SYNTHETIC_CA),
                        credentials,
                        supervisor,
                        mock.Mock(),
                    )
                    with mock.patch.object(pairing, "_utc_now", return_value=NOW):
                        worker._publish_new()
                    supervisor.remove.assert_not_called()
                    supervisor.publish.assert_not_called()
                    self.assertEqual(credentials.discovery_uuid(), "safe_uuid")

    def test_worker_active_without_uuid_does_not_publish(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "pairing.json"
            with (
                mock.patch.object(pairing, "atomic_write_private", side_effect=lambda target, content, **_: target.write_bytes(content)),
                mock.patch.object(pairing, "read_private_file", side_effect=lambda target, **_: target.read_bytes()),
            ):
                credentials = pairing.ManagedCredentialStore(SYNTHETIC_METER_ID, path)
                bootstrap = credentials.create_bootstrap(now=NOW)
                token = secrets.token_urlsafe(32)
                verifier = hashlib.sha256(token.encode("ascii")).hexdigest()
                credentials.claim(bootstrap.pairing_id, bootstrap.secret, verifier, now=NOW)
                credentials.activate(f"Bearer {token}", now=NOW)
                supervisor = mock.Mock()
                worker = pairing.PairingDiscoveryWorker(SimpleNamespace(), credentials, supervisor, mock.Mock())
                worker._publish_new()
                supervisor.publish.assert_not_called()

    def test_valid_bootstrap_without_uuid_is_replaced_and_published(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "pairing.json"
            with (
                mock.patch.object(pairing, "atomic_write_private", side_effect=lambda target, content, **_: target.write_bytes(content)),
                mock.patch.object(pairing, "read_private_file", side_effect=lambda target, **_: target.read_bytes()),
            ):
                credentials = pairing.ManagedCredentialStore(SYNTHETIC_METER_ID, path)
                old = credentials.create_bootstrap(now=NOW)
                supervisor = mock.Mock()
                supervisor.publish.return_value = "new_uuid"
                identity = SimpleNamespace(meter_id=SYNTHETIC_METER_ID, ca_certificate_pem=SYNTHETIC_CA)
                worker = pairing.PairingDiscoveryWorker(identity, credentials, supervisor, mock.Mock())
                with mock.patch.object(pairing, "_utc_now", return_value=NOW):
                    worker._publish_new()
                supervisor.remove.assert_not_called()
                supervisor.publish.assert_called_once()
                self.assertNotEqual(credentials._read()["pairing_id"], old.pairing_id)
                self.assertEqual(credentials.discovery_uuid(), "new_uuid")

    def test_expired_pending_replaces_old_discovery(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "pairing.json"
            with (
                mock.patch.object(pairing, "atomic_write_private", side_effect=lambda target, content, **_: target.write_bytes(content)),
                mock.patch.object(pairing, "read_private_file", side_effect=lambda target, **_: target.read_bytes()),
            ):
                credentials = pairing.ManagedCredentialStore(SYNTHETIC_METER_ID, path)
                bootstrap = credentials.create_bootstrap(now=NOW)
                verifier = hashlib.sha256(secrets.token_urlsafe(32).encode("ascii")).hexdigest()
                credentials.claim(bootstrap.pairing_id, bootstrap.secret, verifier, now=NOW)
                credentials.set_discovery_uuid("old_uuid")
                supervisor = mock.Mock()
                supervisor.publish.return_value = "new_uuid"
                identity = SimpleNamespace(meter_id=SYNTHETIC_METER_ID, ca_certificate_pem=SYNTHETIC_CA)
                worker = pairing.PairingDiscoveryWorker(identity, credentials, supervisor, mock.Mock())
                with mock.patch.object(pairing, "_utc_now", return_value=NOW + timedelta(hours=25)):
                    worker._publish_new()
                supervisor.remove.assert_called_once_with("old_uuid")
                supervisor.publish.assert_called_once()
                self.assertEqual(credentials.discovery_uuid(), "new_uuid")

    def test_expired_bootstrap_replaces_old_discovery(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "pairing.json"
            with (
                mock.patch.object(pairing, "atomic_write_private", side_effect=lambda target, content, **_: target.write_bytes(content)),
                mock.patch.object(pairing, "read_private_file", side_effect=lambda target, **_: target.read_bytes()),
            ):
                credentials = pairing.ManagedCredentialStore(SYNTHETIC_METER_ID, path)
                old = credentials.create_bootstrap(now=NOW)
                credentials.set_discovery_uuid("old_uuid")
                supervisor = mock.Mock()
                supervisor.publish.return_value = "new_uuid"
                events: list[dict[str, object]] = []
                identity = SimpleNamespace(
                    meter_id=SYNTHETIC_METER_ID,
                    ca_certificate_pem=SYNTHETIC_CA,
                )
                worker = pairing.PairingDiscoveryWorker(identity, credentials, supervisor, events.append)
                with mock.patch.object(pairing, "_utc_now", return_value=NOW + timedelta(minutes=11)):
                    worker._publish_new()
                supervisor.remove.assert_called_once_with("old_uuid")
                self.assertEqual(credentials.discovery_uuid(), "new_uuid")
                self.assertNotEqual(credentials._read()["pairing_id"], old.pairing_id)

    def test_discovery_delete_failure_does_not_revoke_active(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "pairing.json"
            with (
                mock.patch.object(pairing, "atomic_write_private", side_effect=lambda target, content, **_: target.write_bytes(content)),
                mock.patch.object(pairing, "read_private_file", side_effect=lambda target, **_: target.read_bytes()),
            ):
                credentials = pairing.ManagedCredentialStore(SYNTHETIC_METER_ID, path)
                token = secrets.token_urlsafe(32)
                verifier = hashlib.sha256(token.encode("ascii")).hexdigest()
                bootstrap = credentials.create_bootstrap(now=NOW)
                credentials.claim(bootstrap.pairing_id, bootstrap.secret, verifier, now=NOW)
                credentials.set_discovery_uuid("safe_uuid")
                credentials.activate(f"Bearer {token}", now=NOW)
                supervisor = mock.Mock()
                supervisor.remove.side_effect = OSError("sensitive detail")
                events: list[dict[str, object]] = []
                worker = pairing.PairingDiscoveryWorker(
                    SimpleNamespace(), credentials, supervisor, events.append
                )
                with self.assertRaises(OSError):
                    worker.finalize()
                self.assertTrue(credentials.authorize(f"Bearer {token}", "health:read"))
                self.assertEqual(credentials.discovery_uuid(), "safe_uuid")
                self.assertEqual(events, [])

    def test_supervisor_delete_404_is_idempotent_success(self) -> None:
        opener = mock.MagicMock()
        opener.open.side_effect = pairing.HTTPError(
            "http://supervisor/discovery/safe_uuid", 404, "gone", {}, None
        )
        client = pairing.SupervisorDiscoveryClient("platform-token")
        with mock.patch.object(pairing, "build_opener", return_value=opener):
            client.remove("safe_uuid")

    def test_supervisor_delete_accepts_successful_null_data_envelope(self) -> None:
        response = mock.MagicMock()
        response.status = 200
        response.read.return_value = b'{"result":"ok","data":null}'
        opener = mock.MagicMock()
        opener.open.return_value.__enter__.return_value = response
        client = pairing.SupervisorDiscoveryClient("platform-token")
        with mock.patch.object(pairing, "build_opener", return_value=opener):
            client.remove("safe_uuid")


if __name__ == "__main__":
    unittest.main()
