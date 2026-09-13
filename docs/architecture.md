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

## Managed onboarding foundation

Phase 5B-B1 adds a Collector-side foundation for new installations. When all
four legacy identity options are absent, UID/GID 2000 generates and persists a
random opaque meter ID, a private local CA, and an exact-hostname server
certificate under `/data/cez-pnd-identity`. A complete legacy configuration
continues to take precedence; every partial legacy combination fails closed.

The Collector publishes a short-lived, high-entropy bootstrap authorization
through Supervisor discovery service `cez_pnd`. Supervisor discovery supplies
the trusted App binding; the payload contains no arbitrary URL or hostname and
no long-lived API credential. The pairing API accepts only a verifier generated
by the future HA integration. A PENDING verifier cannot read Collector data and
becomes ACTIVE only after an authenticated activation request.

Home Assistant Ingress is not part of this architecture. The HA-side discovery
config flow and guided user experience remain incomplete until Phase 5B-B2;
current manual integrations remain supported.
