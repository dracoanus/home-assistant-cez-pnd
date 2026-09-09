# Phase 2B Home Assistant integration — initial milestone

Status: **IMPLEMENTED LOCALLY / NEEDS MANUAL HA OS VERIFICATION**

This milestone adds a narrow custom integration for the existing Collector
0.2.3 synthetic API. It does not add CEZ access, CEZ credentials, Selenium,
Chromium, browser automation, or undocumented endpoints.

## Architecture

Home Assistant Core stores only four Collector-side values in its config
entry: the Collector HTTPS origin, opaque `meter_id`, limited bearer token,
and the dedicated CA certificate used to verify the Collector TLS identity.
It never requests or stores a CEZ username or password.

The async client uses Home Assistant's shared `aiohttp` session and exposes
only these fixed calls:

- `GET /api/v1/health`
- `GET /api/v1/status?meter_id=...`
- `GET /api/v1/measurements?meter_id=...&start=...&end=...`

Requests have total, connection, and read time limits. Redirects are disabled
and any 3xx response fails closed. Responses must be JSON, fit within 1 MiB,
use schema version `1.0`, contain exactly the expected fields, and satisfy the
meter, timestamp, revision, completeness, and measurement-quality rules.

One `DataUpdateCoordinator` polls the three routes every 15 minutes and checks
that status and measurement metadata describe the same immutable snapshot.
Authentication failures trigger Home Assistant's authentication-failure path;
TLS, network, HTTP, and contract failures leave coordinator entities
unavailable and do not synthesize data.

## TLS trust design

The configured URL must use HTTPS, have no embedded credentials, query,
fragment, or extra path, and use port `8443`. The initial default is
`https://606197c3-cez-pnd-collector:8443`.

The integration constructs a dedicated client TLS context from the configured
PEM CA certificate. It requires certificate verification and hostname
verification, with TLS 1.2 as the minimum protocol. It does not disable TLS
verification and does not use the operating-system CA set as an implicit
fallback. The certificate presented by the Collector must therefore chain to
the configured CA and cover the configured internal hostname.

The CA certificate is trust material, not a private key. Production
provisioning, renewal, rotation, and recovery for the CA and limited API token
remain **OPEN / NEEDS VERIFICATION**.

## Entities

The first milestone creates these sensors:

| Sensor | Source field or meaning |
| --- | --- |
| Collector health | Authenticated `/health` result |
| Source status | `source_status` |
| Data timestamp | `data_timestamp` |
| Last attempt | `last_attempt` |
| Last success | `last_success` |
| Completeness | `completeness.state` |
| Valid count | `completeness.valid_count` |
| Missing count | `completeness.missing_count` |
| Dataset revision | `dataset_revision`; disabled by default |
| Grid import interval | Latest valid synthetic `grid_import` interval in kWh |

Timestamp values remain separate and nullable. If the Collector returns a
missing interval with `value_kwh=null` and `quality=missing`, the parser keeps
the value as `None`; it never converts it to zero. If no valid grid-import
interval exists, the entity state is unknown. A valid zero must arrive as an
explicit valid decimal value under the Collector contract.

The interval sensor represents one interval value. It intentionally has no
Recorder long-term-statistics state class in this milestone; production
statistics import depends on future verified historical/revision semantics.

## Manual HA runtime verification still required

- Install the custom integration files on the target Home Assistant version
  and confirm config-flow and entity-platform compatibility.
- Confirm the dedicated CA validates the actual internal Collector hostname.
- Confirm authenticated polling succeeds against Collector 0.2.3 without
  exposing the token or certificate material in logs or diagnostics.
- Confirm all entities show the synthetic contract fields and `last_success`
  remains unknown while its API value is `null`.
- Confirm a missing-only grid-import response produces unknown/unavailable,
  never zero.
- Confirm update failure and recovery behavior and the 15-minute schedule.
- Define production token and CA provisioning, rotation, revocation, backup,
  and recovery before production use.

No HA OS deployment, release, CEZ request, or browser operation is part of
this local implementation milestone.
