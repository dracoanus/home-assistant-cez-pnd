# Collector API contract — normalized dataset revision 0.3

Status: Phase 4C connects validated CEZ CSV exports to the existing local API
through a normalized transactional SQLite dataset. See the
[validation evidence](phase2b-collector-service-validation.md) for the earlier
service/runtime gate. This contract does not expose CEZ credentials or portal
internals to Home Assistant Core.

## Phase classification

The authoritative specification calls production structure and limited API
foundations **Phase 2B**. This skeleton is therefore a narrowly scoped Phase 2B
artifact explicitly requested after acceptance of the relevant offline runtime
evidence. It is not Phase 2A-2 and it does not start live CEZ feasibility work.

The complete Phase 2A exit condition is not met: CEZ objectives 7–14 remain
open. The skeleton proceeds only where those unknowns have no effect—offline
read-only routing, synthetic schemas, fail-closed private configuration, and
release structure. It must not be promoted to a production Collector until the
remaining Phase 2B entry conditions relevant to authentication, TLS pairing,
storage, destination controls, and operational limits are resolved.

## Boundary and transport

The Collector serves HTTPS on container interface `0.0.0.0`, TCP port `8443`,
which is the minimum binding that permits Home Assistant Core to connect over
the internal Home Assistant App network. The App must not publish this port to
the host/LAN and must not use host networking. Clients verify the dedicated
Collector TLS identity and never follow API redirects.

Every route requires `Authorization: Bearer <token>`. Tokens in query strings,
logs, diagnostics, or response bodies are forbidden. The initial token is
limited to one opaque meter ID and these read scopes:

- `health:read`
- `status:read`
- `measurements:read`

The server stores only the SHA-256 verifier. Verification is constant-time and
requires a base64url token decoding to at least 256 bits. Production generation,
pairing, rotation, revocation, certificate provisioning, renewal, and recovery
remain **OPEN / NEEDS VERIFICATION (O-12)**. The skeleton has no unauthenticated
network health exception.

The `0.2.2` HA OS diagnostic candidate accepts only the token's lowercase
SHA-256 verifier through trusted Supervisor-managed App options. The plaintext
token is never an App option. TLS certificate/private-key options support the
narrow offline deployment gate; they do not close production pairing,
certificate lifecycle, backup, recovery, or integration-side pinning. The
[Collector App validation plan](phase2b-collector-ha-app.md) defines this
experimental bootstrap and its remaining gates.

Startup diagnostics are limited to fixed local codes. They identify the
failed validation stage without including exception text, Supervisor tokens,
bearer material, verifiers, option values, certificates, or private keys.

Successful and error responses are JSON, bounded to 1 MiB, marked
`Cache-Control: no-store`, and carry no permissive CORS header. Errors contain
only `schema_version`, a stable local code, a random request ID, and a
`retryable` boolean. Raw exceptions are never returned.

## Routes

The authoritative project specification requires a versioned `/api/v1`
contract. The three initial operations are therefore exposed only at these
paths.

| Method and path | Required input | Initial behavior |
| --- | --- | --- |
| `GET /api/v1/health` | Bearer token; no query | Reports API-process liveness and schema version only. It does not claim CEZ reachability or fresh data. |
| `GET /api/v1/status` | Bearer token and exact `meter_id` | Reports persisted normalized dataset metadata, independent freshness fields, completeness, and source status. |
| `GET /api/v1/measurements` | Bearer token; `meter_id`; RFC 3339 UTC `start` inclusive and `end` exclusive; optional `limit` and opaque server cursor | Returns a deterministic keyset page ordered by interval start and channel from one dataset revision. |

Unknown routes return `404`. Unsupported methods return `405` only after
authentication for a known route. Unknown or duplicate query fields, absolute
request targets, fragments, malformed UTC timestamps, ranges over 60 days,
limits outside `1..1000`, and unknown, malformed, stale, wrong-range, or
nonexistent-position cursors fail closed. A cursor is bounded, canonical,
contains no EAN/ELM, and is tied to the dataset revision and requested range.

## Normalized persistent model

The status and measurement responses keep these concepts independent:

| Field | Meaning |
| --- | --- |
| `data_timestamp` | Latest end instant of a valid measurement interval; never request time. |
| `last_attempt` | Start of the most recent one-shot collection attempt. |
| `last_success` | Advances only after consumption and production parse and commit together. |
| `completeness` | Requested-range or dataset totals split into valid, missing, and invalid counts. |
| `source_status` | Fixed `ok`, `partial`, or `no_data` state; it contains no raw CEZ error. |
| `dataset_revision` | Bounded opaque revision changed only by a successful atomic dataset commit and shared by every page. |
| `values` | Interval records carrying explicit quality and a decimal-string value only when valid. |
| `missing` | Explicit missing interval/rationale records. |

The database is `/data/cez-pnd-dataset/cez-pnd.sqlite3`, mode `0600`, inside
the Collector-owned `0700` directory `/data/cez-pnd-dataset`. Both are owned
by runtime UID/GID 2000, allowing SQLite to create bounded transaction sidecar
files without changing ownership or permissions on `/data` itself.
It stores no EAN, ELM, username, password, token, or cookie. Consumption maps
to `grid_import`; production maps to `grid_export`. Valid energy is serialized
as an exact decimal string. Missing intervals are returned with
`value_kwh=null` and also listed in `missing[]`. Invalid intervals increment
`invalid_count` and are omitted from `values`. Missing, invalid, or failed data
never becomes zero.

Both channels are UPSERTed in one `BEGIN IMMEDIATE` transaction. A parser,
storage, interruption, or second-channel failure cannot publish a partial new
revision; the previous committed dataset remains readable. Re-import is
idempotent and a corrected interval replaces the prior value.

## Explicitly absent functionality

The service exposes no CEZ credential, cookie, login, refresh, arbitrary URL,
browser command, selector, script, shell, file, DOM, screenshot, raw export,
process-inspection, diagnostics, or administration endpoint. It performs no
outbound request and does not import Selenium in the service process.

## Deferred contract work

The following remain **OPEN / NEEDS VERIFICATION** before affected production
behavior:

- O-12 token pairing, lifecycle, TLS identity, and integration-side pinning;
- O-14 final limits, rate limits, concurrency, retention, and staleness budgets;
- O-09 long-term meter identity/binding beyond the current single-App opaque ID;
- remaining live variants of CEZ CSV schema/status semantics outside the
  validated Phase 4B parser fixtures;
- the future `POST /api/v1/refresh` contract and worker lifecycle;
- HA App `/data` permissions and restart/backup behavior;
- Home Assistant internal DNS identity and end-to-end HTTPS connectivity on the
  selected target.

These unknowns do not permit plaintext fallback, unauthenticated access, secret
logging, broader endpoints, or fabricated CEZ behavior.
