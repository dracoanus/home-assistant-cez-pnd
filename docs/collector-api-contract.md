# Collector API contract — normalized dataset

Status: implemented by Collector/App `0.3.38` and consumed by Home Assistant
integration `0.1.10`. Validated CEZ CSV exports are stored in a normalized
transactional SQLite dataset and served through this narrow local API. This
contract does not expose CEZ credentials or portal internals to Home Assistant
Core. Earlier service/runtime evidence remains in the
[historical validation document](phase2b-collector-service-validation.md).

## Current role

The API is the only data boundary between the Collector App and Home Assistant
Core. The Collector owns CEZ authentication, collection, parsing,
synchronization and persistent storage. Home Assistant holds only a limited API
token, opaque meter ID and public local CA needed for verified HTTPS reads.
Managed pairing provisions those values for normal installations; the manual
URL/token/CA configuration remains a legacy/recovery path.

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
requires a base64url token decoding to at least 256 bits. Managed onboarding
generates the long-lived token in Home Assistant, sends only its verifier to
the Collector, and establishes trust in the Collector's generated local CA and
leaf certificate. There is no unauthenticated network health exception.
Automatic leaf renewal, CA rotation, managed token rotation/revocation and
legacy-to-managed migration remain unimplemented lifecycle work.

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

## Explicitly absent API functionality

The service API exposes no CEZ credential, cookie, login, arbitrary URL,
browser command, selector, script, shell, file, DOM, screenshot, raw export,
process-inspection, diagnostics, or general administration endpoint. Outbound
CEZ work is performed only by the internal scheduled synchronization worker,
outside the Home Assistant API surface.

## Deferred lifecycle and operational work

The current release does not implement automatic certificate renewal, CA
rotation, managed token rotation/revocation, legacy-to-managed migration or a
public refresh endpoint. Long-term retention policy and additional CEZ export
variants also remain future work. These gaps do not permit plaintext fallback,
unauthenticated access, secret logging, broader endpoints or fabricated CEZ
behavior.

## Development: bounded event API and sync producer (Phase 3, not released)

`GET /api/v1/events?meter_id=<opaque-meter-id>&cursor=<opaque-cursor>`
requires the existing bearer credential with `status:read`. `cursor` is optional;
no other query fields are accepted. Authorization precedes waiting and is checked
again immediately before a successful response or timeout response. Neither a
SQLite transaction nor a credential/pairing lock is held during the wait.

A missing cursor, different process generation or future sequence returns HTTP
200 with exactly `schema_version: 1`, `event: state_reset`, and `cursor`. A current
cursor waits at most 25 seconds; no publication yields HTTP 204 with no body.
An older cursor in the same generation receives the latest coalesced event, not a
history of intermediate events. Normal HTTP 200 JSON has exactly `schema_version`,
`event`, `cursor`, `sync_kind`, `sync_result`, and `dataset_revision` (at most 4 KiB).
`event` is `sync_finished`; kinds are `current_day`, `historical_backfill`,
`historical_correction`; results are `succeeded` or `failed`.

The opaque cursor is bounded to 56 ASCII characters: a format prefix, a random
128-bit process generation and a canonical nonnegative signed-64-bit-range
sequence. It is not an authorization credential and is never logged. Malformed
cursors receive 400, authentication failures 401, another meter 404, full waiter
capacity 429, and broker shutdown 503 when the connection is still writable.
All ordinary error responses retain the existing API error envelope.

`dataset_revision` is `string | null`, using exactly the existing opaque dataset
API revision (`ds_` followed by 2-77 lowercase hexadecimal characters). API cursor
validation and event validation share the same pattern. The value is serialized
unchanged, without interpretation, conversion or derivation from the event cursor.
Use null only when no authoritative dataset revision exists; a failed sync with an
existing dataset retains that dataset's revision. SyncWorker reads authoritative
NormalizedDatasetStore status after each completed CEZ collection attempt. If that
read fails, no event or fabricated null revision is published; the original sync
outcome is preserved. No dataset storage or revision generation semantics change.

The broker retains one frozen snapshot in memory, uses a condition variable and
coalesces publications. Restart changes its generation. SyncWorker publishes
sequentially to the same broker used by the server API: one `current_day` event
per current-day attempt (including successful partial data), one
`historical_backfill` event per attempted chunk, and one `historical_correction`
event per correction attempt, including the previous-completed-day operation
without configured backfill. Scheduler wakeups, outer cycle logs and
`backfill_complete` do not publish extra events. Publication precedes backfill
checkpoint advancement; checkpoint failure cannot create a second failed event
for an already successful CEZ attempt.

Notifications are non-durable side effects, not an audit log. Broker shutdown is
expected and silently contained. Unexpected revision-read/publication failures
emit only the fixed `sync_notification_failed` diagnostic and never change sync
outcomes, retry classification or committed data. STOP prevents new attempts and
new notification work. The HA integration is not connected to events yet; its
existing polling remains unchanged.

### Concurrency and shutdown

The server admits at most eight handlers before starting threads. Two may wait
for events, leaving six slots for other traffic when event waits alone consume
capacity. Other slow clients can still exhaust the global eight-slot limit; extra
connections are closed before TLS rather than queued as unbounded work.
TLS handshakes run in admitted handlers, with a five-second socket timeout.
A single monitor enforces a 35-second accepted-connection deadline, including
slow headers; broker waits remain capped at 25 seconds. TLS identity and request
validation are unchanged. Responses use HTTP/1.0 close semantics.

Shutdown stops admission, closes the broker (notifying all waiters), shuts down
active sockets. During service shutdown, handler/monitor joins share the same
eight-second absolute deadline as sync and pairing joins. Standalone server close
retains a five-second handler budget. A socket may close before its shutdown 503
reaches the client. Offline verified-TLS tests require event waiters and
handlers to finish within two seconds, without waiting the 25-second poll.

SQLite connections remain per operation; reads and writes use existing transaction
semantics. Managed credential mutations retain their lock and atomic replacement;
finalization retains its separate lock. Tests cover claim/activate/finalize with
concurrent ordinary API traffic, plus authorization revalidation. All existing
structured emitters share a lock around one complete JSON-line write.

**Phase 2B lifecycle update (not released):** A prestarted daemon watchdog arms
on first SIGTERM and terminates a still-running process after 10 seconds with
fixed exit status 70, using `os._exit` without logging or cleanup. Repeated signals
cannot extend the deadline. All components receive STOP before joins; cooperative
cleanup shares one eight-second monotonic deadline. Successful cleanup returns
normally with status 0; the guard remains armed through process finalization.
This is best-effort graceful cleanup plus forced termination, not requests/DNS
cancellation. The App stop timeout is 15 seconds: the 10-second internal watchdog
plus a five-second Supervisor operational margin. Phase 2B Linux validation passed
on GitHub Actions ubuntu-latest; Windows-only results are insufficient. See
[configuration shutdown details](configuration.md#shutdown-budget).
The event broker remains disconnected from synchronization; HA polling is unchanged.
