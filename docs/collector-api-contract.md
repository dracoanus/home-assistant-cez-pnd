# Collector API contract — skeleton revision 0.1

Status: initial Phase 2B foundation with a successful offline Synology container
and API smoke test. See the [validation evidence](phase2b-collector-service-validation.md).
This document defines a local Collector contract. It does not define or imply a
CEZ endpoint, login flow, portal schema, or production pairing workflow.

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
| `GET /api/v1/status` | Bearer token and exact `meter_id` | Reports the synthetic dataset revision, independent freshness fields, completeness, and source status. |
| `GET /api/v1/measurements` | Bearer token; `meter_id`; RFC 3339 UTC `start` inclusive and `end` exclusive; optional `limit` and server cursor | Returns a page from one immutable synthetic revision, explicit coverage and explicit missing intervals. |

Unknown routes return `404`. Unsupported methods return `405` only after
authentication for a known route. Unknown or duplicate query fields, absolute
request targets, fragments, malformed UTC timestamps, ranges over 60 days,
limits outside `1..1000`, and unknown cursors fail closed.

## Synthetic status model

The status and measurement responses keep these concepts independent:

| Field | Meaning in the skeleton |
| --- | --- |
| `data_timestamp` | Latest end instant of a valid measurement interval; never request time. |
| `last_attempt` | Synthetic collection-attempt start. |
| `last_success` | `null`, because the synthetic dataset is partial and a partial attempt must not advance global success. |
| `completeness` | Explicit `partial` state with expected, valid, missing, and invalid counts. |
| `source_status` | `synthetic_offline_partial`; it never implies CEZ availability. |
| `dataset_revision` | Immutable revision shared by all pages. |
| `values` | Interval records carrying explicit quality and a decimal-string value only when valid. |
| `missing` | Explicit missing interval/rationale records. |

The fixture contains one valid import interval with `value_kwh="0.125"` and
one missing interval with `value_kwh=null`. Missing or failed data never becomes
zero. A valid measured zero will be representable only as decimal string
`"0"` with `quality="valid"` after its source semantics are verified.

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
- O-09 actual meter identity/binding, while EAN/ELM remain absent here;
- O-10 CEZ CSV channels, units, precision, timezone, DST, quality, and range;
- the future `POST /api/v1/refresh` contract and worker lifecycle;
- HA App `/data` permissions and restart/backup behavior;
- Home Assistant internal DNS identity and end-to-end HTTPS connectivity on the
  selected target.

These unknowns do not permit plaintext fallback, unauthenticated access, secret
logging, broader endpoints, or fabricated CEZ behavior.
