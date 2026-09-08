# Collector service skeleton

This directory is the initial Phase 2B Collector service and API foundation.
It contains only synthetic offline measurement data and never starts Chromium,
contacts CEZ, accepts CEZ credentials, or exposes browser control.

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

- The container remains UID/GID `2000:2000`.
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

Version `0.2.2` retains the experimental HA OS deployment bootstrap and its
fixed authenticated self-info endpoint at the Supervisor v2 App path. It adds
only allowlisted, non-secret private-configuration failure-stage codes.
The non-root service retrieves only its own Supervisor-managed App options.
Options hold a token SHA-256 verifier, never the plaintext bearer token, plus
the TLS certificate/private key. TLS material is loaded through mode-0600 files
on `/tmp` and unlinked before the listener starts. The fixed-file mode remains
available to the isolated Synology smoke profile.

Production pairing, rotation/revocation UX, TLS issuance and renewal, and HA
App `/data` ownership/backup behavior remain **OPEN / NEEDS VERIFICATION**.
The complete design and gate are in the
[Collector HA App plan](../docs/phase2b-collector-ha-app.md).

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

The prepared production-oriented App manifest references the future immutable
`0.2.2` GHCR image and exposes no host port. This change does not publish the
image; publication requires a separate review.
