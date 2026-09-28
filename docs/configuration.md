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
hourly; historical backfill and completed-day correction run every six hours.
Backfill is chunked and resumable. Normal, spring-DST and autumn-DST days have
96, 92 and 100 quarter-hour intervals.

`VALID` includes real measured zero. `MISSING` means CEZ has not published
the value and is never zero-filled. `INVALID` has no energy value. Unknown CEZ
statuses fail closed. A later valid row replaces a stored missing placeholder.

## Advanced and troubleshooting options

Diagnostic options are intentionally optional. On a clean installation they are
hidden behind **Show unused optional configuration options** in the App
configuration screen. Leave them disabled during normal operation.

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
