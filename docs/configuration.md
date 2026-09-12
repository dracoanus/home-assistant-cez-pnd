# Configuration

Collector options are private Supervisor-managed configuration. Never paste any
option value into an issue, log or repository. Examples below are placeholders.

## Normal configuration

| Option | Required | Purpose and safe example | Notes |
| --- | --- | --- | --- |
| `meter_id` | Yes | `mtr_<generated-id>` | Scopes the local API token. |
| `api_token_sha256` | Yes | Lowercase SHA-256 verifier of the separate API token. | Enter only the verifier; plaintext belongs in HA integration. |
| `tls_certificate_b64` | Yes | Base64-encoded PEM certificate for internal hostname. | Use a trusted local CA. |
| `tls_private_key_b64` | Yes | Base64-encoded matching PEM private key. | Private; never share it. |
| `cez_sync_enabled` | Yes for automation | `true` | Enables scheduled CEZ synchronization. |
| `cez_history_start` | Recommended | `YYYY-MM-DD` | Backfill starts here; moving later does not purge data. |
| `cez_username` | Yes for collection | `<CEZ username>` | Private and masked; Collector only. |
| `cez_password` | Yes for collection | `<CEZ password>` | Private and masked; Collector only. |
| `cez_ean` | One selector | `<18-digit-supply-point-id>` | Private/masked; exactly 18 ASCII digits. |
| `cez_elm` | One selector | `<meter-identifier>` | Private/masked bounded meter identifier. |

Configure both EAN and ELM when available. The Collector verifies that they
refer to the same meter and never logs either identifier.

## Synchronization and data quality

The Collector uses `Europe/Prague` calendar days. Current day refresh runs
hourly; historical backfill and completed-day correction run every six hours.
Backfill is chunked and resumable. Normal, spring-DST and autumn-DST days have
96, 92 and 100 quarter-hour intervals.

`VALID` includes real measured zero. `MISSING` means CEZ has not published the
value and is never zero-filled. `INVALID` has no energy value. Unknown CEZ
statuses fail closed. A later valid row replaces a stored missing placeholder.

## Advanced and troubleshooting options

These options are disabled by default and are not normal production settings.
Do not enable multiple modes together.

| Option | Purpose |
| --- | --- |
| `cez_data_probe_mode` | One bounded collection for `cez_data_probe_date`, then exit. |
| `cez_data_probe_date` | ISO date used only by probe mode. |
| `cez_http_auth_discovery_mode` | One-shot browserless authentication diagnosis. |
| `cez_requests_preauth_compatibility_mode` | Narrow PREAUTH compatibility diagnosis. |
| `cez_discovery_mode` | Legacy Selenium discovery diagnosis. |
| `cez_start_url`, `cez_auth_origin`, `cez_allowed_origins` | Legacy Selenium discovery inputs; leave unset normally. |

All diagnostic modes are mutually exclusive with scheduled synchronization.
They must never be used to bypass TLS, redirect, hostname or credential
protections. Certificate issuance, token pairing, rotation and revocation are
currently manual.
