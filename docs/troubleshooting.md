# Troubleshooting

Use only non-secret event names and fixed error codes when diagnosing a
problem. Never include CEZ credentials, API tokens, EAN, ELM, certificates,
private keys or raw CSV exports in an issue.

## Collector does not start

Find `startup_failed` in the App log. The fixed code identifies the
configuration stage without exposing values. Check certificate/key encoding,
the SHA-256 verifier and the CEZ settings required when sync is enabled. A new
managed installation normally creates its own local identity; do not populate
only part of the four legacy identity fields because partial legacy identity
configuration fails closed.

## Managed discovery or pairing is missing

Confirm that the Collector App is running and that the HACS integration was
installed before the latest Home Assistant restart. Open **Settings → Devices
& services** and use the discovered **CEZ PND Collector** card. Do not create a
manual entry while a valid discovery card is present.

An expired invitation is replaced by the Collector according to its bounded
recovery rules. Restarting the Collector or Home Assistant may resume an
interrupted pairing/finalization step. Do not delete the integration entry,
managed identity directory or recovery storage as a first response.

## CEZ authentication or synchronization fails

Inspect `sync_cycle_started`, `current_day_sync_started`,
`current_day_sync_failed` and `data_probe_dataset_committed`. A failed attempt
does not replace the previous dataset. Check CEZ account access separately; do
not lower TLS validation or paste credentials into logs.

## Collector unreachable or TLS fails

Verify the running App, internal HTTPS URL, opaque meter ID, limited API token
and trusted CA certificate. `invalid_tls` means the certificate could not be
verified; correct identity or CA instead of disabling verification.

`invalid_auth` means the limited Collector API token was rejected. For a
managed entry, preserve the Collector identity and dataset while checking the
restart-recovery state and safe error codes. Managed token rotation is not yet
implemented. Manual token and verifier replacement applies only to the
legacy/recovery configuration path; never paste either value into logs.

## Synchronization fails

Compare `last_attempt`, `last_success`, `source_status` and the latest fixed
sync error code. A failed cycle leaves the last committed dataset readable.
Check that automatic synchronization is enabled, the history start is valid
and EAN/ELM still identify the intended meter. Do not remove the SQLite dataset
to force a retry.

## Partial, missing or delayed data

`source_status: partial`, lower completeness or missing intervals can be normal
during the current CEZ day. `MISSING` means unpublished; `INVALID` means CEZ
rejected the value. A genuine valid zero remains zero, but numeric zero with an
unavailable CEZ status remains missing.

## Statistics or Energy Dashboard delayed

Four valid quarter-hour intervals are required for one hourly statistic. Check
last success, data timestamp, completeness and grid interval entities. HACS
updates require a Home Assistant restart before new Python code is loaded.

If the integration is healthy but statistics are absent, verify that Recorder
is enabled and inspect the external statistic IDs
`cez_pnd:grid_import_energy` and `cez_pnd:grid_export_energy`. Missing or
invalid CEZ intervals intentionally prevent creation of the affected hourly
sum; they are never replaced with zero.

## Restart recovery

Managed pairing uses a private recovery journal and process-boundary cleanup.
After an interruption, allow the Collector and Home Assistant to start normally
and verify that the existing ConfigEntry reconnects. Final discovery removal
and journal cleanup can complete on following Home Assistant Core processes.
Do not edit `.storage`, copy pairing secrets or delete the Collector identity.

## Safe events

- `service_started`
- `sync_worker_started`
- `sync_cycle_started`
- `current_day_sync_started`
- `current_day_sync_succeeded`
- `current_day_sync_failed`
- `data_probe_dataset_committed`
- `request_completed`

## Known limitations

- Initial identity, local CA/leaf certificate provisioning and API-token
  pairing are managed automatically and have been validated on Home Assistant
  OS. Automatic leaf renewal, CA rotation and managed API-token
  rotation/revocation are not implemented.
- Automatic migration from a complete legacy manual identity to managed
  identity is not implemented.
- The requests transport validates DNS before each request, then the HTTP client
  resolves again for connection. This DNS TOCTOU limitation is not pinned-
  transport parity.
- CEZ publication delay determines current-day freshness.
