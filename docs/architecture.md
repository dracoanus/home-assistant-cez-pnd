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
