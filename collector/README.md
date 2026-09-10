# Collector service skeleton

This directory contains the Phase 2B synthetic Collector service and the
unreleased Phase 3A one-shot authentication-discovery foundation. Normal
service mode remains synthetic-only. No browser control is exposed through
the Collector API.

The complete Synology/Docker offline smoke profile has passed. See the
[Phase 2B validation evidence](../docs/phase2b-collector-service-validation.md).
The Synology host discarded the requested PID cgroup limit; effective
`pids_limit` enforcement therefore remains **OPEN / NEEDS VERIFICATION on HA
OS** and the intended limit remains required.

The image is a thin child of the exact Debian runtime that passed the HA OS
Collector Runtime Gate. The parent is pinned by tag and OCI index digest, so
ordinary service changes do not reinstall Chromium, ChromeDriver, Python, or
Selenium.

## Runtime boundary

- A minimal root-owned entrypoint initializes only
  `/data/cez-pnd-probe` as UID/GID `2000:2000`, mode `0700`. It never
  recursively changes `/data`. It then drops supplementary groups, GID and
  UID and permanently execs the Collector service as `2000:2000`.
- HTTPS is mandatory. Outside HA OS, startup fails unless
  `/data/tls/server.crt` and the UID-2000-owned mode-0600
  `/data/tls/server.key` are valid. The HA App path is described below.
- The API token is presented only as an `Authorization: Bearer` header. The
  server stores a SHA-256 verifier, not the token, in the UID-2000-owned
  mode-0600 `/data/auth/client.json` file.
- The token must be a base64url value decoding to at least 256 bits and is
  scoped to the single configured opaque meter plus the three read scopes.
- The service binds IPv4 `0.0.0.0:8443` so Home Assistant Core can reach it on
  the isolated internal App network. A future App manifest must not publish
  this port to the host or LAN.
- Logs contain a generated request ID, method, normalized route, and status.
  They do not contain headers, query strings, tokens, measurement values, DOM,
  screenshots, or process details.

Release `0.2.3` retains the experimental HA OS deployment bootstrap and its
authenticated self-info endpoint at the Supervisor v1 App path.
The non-root service retrieves only its own Supervisor-managed App options.
Options hold a token SHA-256 verifier, never the plaintext bearer token, plus
the TLS certificate/private key. TLS material is loaded through mode-0600 files
on `/tmp` and unlinked before the listener starts. The fixed-file mode remains
available to the isolated Synology smoke profile.

Production pairing, rotation/revocation UX, TLS issuance and renewal, and HA
App `/data` ownership/backup behavior remain **OPEN / NEEDS VERIFICATION**.
The complete design and gate are in the
[Collector HA App plan](../docs/phase2b-collector-ha-app.md).

When explicitly enabled through Supervisor options, Phase 3A runs one
temporary browser session and exits. Credentials remain in memory and the
temporary `/tmp` profile only for that run. A local CONNECT proxy permits only
the configured HTTPS origins on port 443, Chromium DNS is disabled, downloads
are denied, and browser/driver logs are discarded. See the
[Phase 3A discovery design](../docs/phase3a-cez-auth-discovery.md).

## API

The only routes are:

- `GET /api/v1/health`
- `GET /api/v1/status?meter_id=<opaque-id>`
- `GET /api/v1/measurements?meter_id=<opaque-id>&start=<UTC>&end=<UTC>`

See [the API contract](../docs/collector-api-contract.md). All routes require
the read-only bearer token. There is no refresh, administration, browser, URL,
file, shell, debug, CEZ, or authentication-flow endpoint.

## Local verification

Run from the repository root:

```bash
PYTHONPATH=collector python3 -m unittest discover -s collector/tests -v
python3 collector/static_verify.py
python3 -m compileall -q collector/collector_service collector/tests
```

Build the thin image after the immutable parent image is available:

```bash
docker build --pull=false --tag cez-pnd-collector-skeleton:dev collector
```

The separate [offline Docker smoke profile](smoke/README.md) generates
short-lived test-only TLS and bearer material, starts this image without a
published host port, exercises the three API routes, and verifies graceful
shutdown. It is not a production configuration or pairing design.

The App manifest references the immutable released `0.2.3` GHCR image and
exposes no host port. Phase 3A remains unreleased source pending review and
offline validation.

The unreleased Phase 4A source also contains an explicit, mutually exclusive
one-shot authenticated data probe. It reuses the active browserless
authentication session, validates bounded dashboard metadata, requests one
day of consumption and production CSV exports, and atomically replaces three
private files under `/data/cez-pnd-probe`. It does not parse or publish those
measurements through the Collector API. See the App documentation for the
manual gate and handling restrictions.
