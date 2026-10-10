# Configuration

Collector options are private Supervisor-managed configuration. Never paste any
credential, EAN/ELM identifier, token material, certificate or private key into
an issue, log or repository.

The App configuration UI provides Czech labels and descriptions when Home
Assistant is set to Czech. English is included as the fallback translation.

## Normal configuration

For normal installations, managed pairing creates the Collector API identity,
TLS trust and Home Assistant API token automatically. Do not fill the legacy
identity fields unless you are deliberately following a recovery or manual
configuration procedure.

| Option | Required | Purpose | Notes |
| --- | --- | --- | --- |
| `sync_interval_minutes` | Optional | Current-day check interval in minutes. | Default 60; exact integer 15–720. |
| `cez_sync_enabled` | Yes for automation | Enables scheduled CEZ synchronization. | Keep enabled for normal operation. |
| `cez_history_start` | Recommended | First date to backfill. | Use `YYYY-MM-DD`; moving it later does not purge stored data. |
| `cez_username` | Yes for collection | CEZ PND username. | Private and masked; Collector only. |
| `cez_password` | Yes for collection | CEZ PND password. | Private and masked; Collector only. |
| `cez_ean` | One selector | 18-digit supply-point EAN. | Private/masked. |
| `cez_elm` | One selector | Electricity meter identifier. | Private/masked. |

Configure both EAN and ELM when available. The Collector verifies that they
refer to the same meter and never logs either identifier.

## Managed pairing

When `meter_id`, `api_token_sha256`, `tls_certificate_b64` and
`tls_private_key_b64` are all absent, the App uses managed identity and
Supervisor discovery. The Home Assistant integration performs guided pairing
and stores only the material required to authenticate and verify the local
Collector connection.

The four legacy identity options remain in the schema for recovery and
backwards compatibility. They are optional and are not normal user settings.

## Synchronization and data quality

The Collector uses `Europe/Prague` calendar days. Current-day refresh runs
immediately at worker startup and then `sync_interval_minutes` after successful
completion; historical backfill and completed-day correction have an independent
six-hour monotonic deadline. Current day has priority when both are due.
Backfill is chunked and resumable. Normal, spring-DST and autumn-DST days have
96, 92 and 100 quarter-hour intervals.

`VALID` includes real measured zero. `MISSING` means CEZ has not published
the value and is never zero-filled. `INVALID` has no energy value. Unknown CEZ
statuses fail closed. A later valid row replaces a stored missing placeholder.

## Advanced and troubleshooting options

Diagnostic options are intentionally optional. On a clean installation they are
hidden behind **Show unused optional configuration options** in the App
configuration screen. Leave them disabled during normal operation.

An installation upgraded from an older App version may still show stored
`false` or empty diagnostic values. That is expected and does not enable a
diagnostic mode. New clean installations omit unused diagnostic defaults.

| Option | Purpose |
| --- | --- |
| `cez_data_probe_mode` | One bounded collection for `cez_data_probe_date`, then exit. |
| `cez_data_probe_date` | ISO date used only by probe mode. |
| `cez_http_auth_discovery_mode` | One-shot browserless authentication diagnosis. |
| `cez_requests_preauth_compatibility_mode` | Narrow PREAUTH compatibility diagnosis. |
| `cez_discovery_mode` | Legacy Selenium discovery diagnosis. |
| `cez_start_url`, `cez_auth_origin`, `cez_allowed_origins` | Legacy/diagnostic destination controls; leave unchanged normally. |

All diagnostic modes are mutually exclusive with scheduled synchronization.
They must never be used to bypass TLS, redirect, hostname or credential
protections.

## Development: Phase 2 scheduling (not released)

Changing `sync_interval_minutes` requires restarting the Collector; existing saved
options without it default to 60. Current-day and historical operations remain
serial. Missed deadlines coalesce; no catch-up burst is queued. A historical
transaction already running finishes before current-day work; between committed
backfill chunks the worker checks whether current-day work is due. Chunk size,
two-chunk maximum, correction overlap and persistent checkpoints remain unchanged.
History is scheduled six hours after completion, independently of the 15–720 minute
current-day cadence. Retry timing is internal, not another user setting.

Only `auth_connect_failed` and `auth_operation_timeout` are proven transient codes:
recovery waits progress through 5, 15, 30 and then 60 minutes (capped). Every other
fixed failure waits at least 60 minutes. Authentication/security failures and
unclassified transport errors are not treated as proven transient. The existing
collection path maps authentication errors to `data_probe_auth_failed`, and often
maps export HTTP/timeout/validation failures to one export code. Thus real failures
that lose this distinction receive the conservative hourly retry; HTTP 5xx is not
inferred from a generic code. No authentication/export error mapping is changed.

One recovery deadline blocks both schedules until the failed kind is retried,
preventing an immediate equivalent login by the other kind. Success clears the
shared recovery state and resumes that kind's normal cadence from completion;
the other independent deadline is reevaluated. Retry waits, normal waits and history
waits all use the stop event and monotonic clock. Stop prevents the next operation
or backfill chunk; it never interrupts a SQLite transaction already running.

### Shutdown budget

The development shutdown design is best-effort graceful cleanup followed by
bounded forced process termination. A prestarted daemon watchdog is armed on the
first SIGTERM observation: its immutable monotonic deadline is 10 seconds.
Repeated SIGTERM cannot extend it. Sync and pairing receive STOP before any join;
the broker wakes event waiters and HTTPS admission/sockets close. All joins share
one absolute 8-second deadline from that same first observation. No new blocking
cleanup or logging starts after that deadline.

If cleanup completes, the service returns normally with status 0. If cleanup or
Python finalization remains blocked, the guard invokes `os._exit(70)` without
logging, locks shared with application workers, flushing, filesystem/database
access or cleanup callbacks. This intentionally bypasses finally/atexit handlers;
it does not cancel the blocked requests operation cooperatively. The bound assumes
a functioning OS scheduler and that blocked calls release the GIL; it is not a
hard real-time guarantee against kernel stalls or arbitrary GIL-holding native code.

The target App timeout is **15 seconds**, leaving five seconds after the internal
guard. The manifest retains the temporary **162 seconds** until real Linux/POSIX
subprocess tests demonstrate the 10-second forced exit and normal cooperative
shutdown. Windows skips cannot prove that gate; HA OS stop validation remains open.

SQLite network waits remain outside transactions. SQLite alone recovers its
journal/WAL after interruption; startup never deletes those files. Tests interrupt
before BEGIN, during writes and after COMMIT and inspect the actual journal mode.
Startup removes only regular UID-2000 private orphan files matching
`.pairing-state.json.<32 lowercase hex>.tmp` in the verified 0700 managed identity
directory, with at most 64 directory entries examined. Unknown files and SQLite
sidecars remain untouched. Interrupted TLS identity-generation evidence retains
its existing fail-closed behavior and requires operator recovery rather than
silently generating a new identity. TLS loading temp files are removed before
worker startup. Diagnostic raw-export files retain their existing private paths;
this change does not introduce broad filesystem cleanup.
