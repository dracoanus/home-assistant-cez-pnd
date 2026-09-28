# Architecture

The Collector is the CEZ trust boundary. It owns CEZ credentials, authenticates
to CEZ PND through the reviewed browserless HTTP flow, downloads bounded CSV
exports, validates status semantics and stores normalized intervals in SQLite.
It exposes only a narrow local HTTPS API.

Home Assistant Core never receives CEZ credentials, cookies, CEZ HTML, raw CSV
or browser control. It holds a limited bearer token, opaque meter ID and CA
certificate, then reads health, status and measurements from the Collector.

```text
CEZ PND -> Collector private configuration -> normalized SQLite
                                      -> HTTPS + bearer token -> HA integration
                                      -> Recorder statistics -> Energy Dashboard
```

SQLite interval keys make writes idempotent. Valid, missing and invalid quality
remain separate. `data_timestamp` is the latest valid interval end, not a
future missing interval. The Collector refreshes the current Prague day hourly
and historical backfill/completed-day correction every six hours in one
serialized worker.

The App runs non-root with AppArmor and without privileged mode, host network,
Docker socket or broad host mounts. TLS verification, manual redirects,
reviewed destinations and bounded memory-only cookies remain mandatory.

## Managed onboarding

Managed onboarding is implemented and has been validated end to end on Home
Assistant OS. When all four legacy identity options are absent, UID/GID 2000
generates and persists a random opaque meter ID, a private local CA, and an
exact-hostname server certificate under `/data/cez-pnd-identity`. A complete
legacy configuration continues to take precedence; every partial legacy
combination fails closed.

The Collector publishes a short-lived, high-entropy bootstrap authorization
through Supervisor discovery service `cez_pnd`. Supervisor discovery supplies
the trusted App binding; the payload contains no arbitrary URL or hostname and
no long-lived API credential. The pairing API accepts only a verifier generated
by the HA integration. A PENDING verifier cannot read Collector data and
becomes ACTIVE only after an authenticated activation request.

The HA `SOURCE_HASSIO` flow accepts the exact bounded
discovery contract, derives `https://<slug-with-hyphens>:8443` only from the
Supervisor-provided App slug, validates the discovered CA and generates a
256-bit URL-safe API token inside HA. Only its SHA-256 verifier is sent with the
short-lived pairing authorization; the pairing ID and secret remain transient.

Before claim, HA atomically writes a private one-record recovery journal through
the public `homeassistant.helpers.storage.Store` API and verifies it by reading
it back. The journal contains only the generated API token, opaque meter ID,
Collector origin, public CA and a bounded onboarding phase. It contains no CEZ
credential, pairing secret, pairing ID, verifier or private TLS key. A repeated
claim with the same bootstrap authorization and verifier is idempotent, so a
crash after claim can resume from the journal.
Journal ownership decisions are serialized by one Home Assistant-instance
manager. Confirmation reloads the journal while holding that manager's lock;
same-Collector flows reuse its token and a different Collector cannot replace
it.

ConfigEntry setup is not treated as a persistence barrier. Initial setup
activates and verifies the Collector but retains a non-secret finalize marker,
the recovery journal and Supervisor discovery. An in-memory, non-secret marker
prevents finalization for an entry created in the current HA process. When the
persisted entry is loaded in a later HA process, `POST /pairing/v1/finalize`
proves possession of the ACTIVE token, removes discovery and clears Collector
recovery metadata without revoking ACTIVE. HA removes the pending markers but
intentionally retains the journal. Only another HA process that reconstructs
the managed entry with those markers durably absent may delete the journal.
A second in-memory marker records finalization for the rest of that process, so
setup retries, unload/load and option-triggered reloads cannot delete the
journal early. This additional restart is a persistence proof; normal operation
does not wait for journal cleanup. Cleanup acquires the same recovery ownership
lock as confirmation, reloads the journal under that lock and deletes only an
exact meter/origin/CA/token match. Temporary finalization or cleanup failure
leaves operation active and cleanup retryable; no timer or private Core storage
API is used.

Collector startup reconciles pairing state before changing discovery. It keeps
the existing discovery for ACTIVE, unexpired PENDING and unexpired bootstrap
states. Only UNPAIRED or expired bootstrap/PENDING state may publish a fresh
bootstrap, and stale discovery is removed only after that replacement decision.

At flow entry, the framework-provided `addon` metadata is separated from the
exact seven-field Collector payload. The short-lived pairing secret is copied
only into a repr-safe transient object and framework `init_data` is immediately
replaced with a secret-free `HassioServiceInfo`.

The entry unique ID remains the stable opaque `meter_id`, never the Supervisor
discovery UUID, so deletion of the consumed discovery message cannot delete the
working entry. Home Assistant Ingress is not part of this architecture. The
manual URL/token/CA flow remains supported as an advanced recovery path.

Live validation covered managed identity creation, Supervisor discovery,
guided claim and activation, ConfigEntry persistence across a Core restart,
finalization, discovery removal, Collector restart recovery and recovery
journal cleanup in a following Core process. Certificate renewal, CA rotation,
managed-token rotation/revocation and legacy-to-managed migration remain
separate future lifecycle work.
