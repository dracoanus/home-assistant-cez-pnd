# Troubleshooting

Use only non-secret event names and fixed error codes when diagnosing a
problem. Never include CEZ credentials, API tokens, EAN, ELM, certificates,
private keys or raw CSV exports in an issue.

## Collector does not start

Find `startup_failed` in the App log. The fixed code identifies the
configuration stage without exposing values. Check certificate/key encoding,
the SHA-256 verifier and the CEZ settings required when sync is enabled.

## CEZ authentication or synchronization fails

Inspect `sync_cycle_started`, `current_day_sync_started`,
`current_day_sync_failed` and `data_probe_dataset_committed`. A failed attempt
does not replace the previous dataset. Check CEZ account access separately; do
not lower TLS validation or paste credentials into logs.

## Collector unreachable or TLS fails

Verify the running App, internal HTTPS URL, opaque meter ID, limited API token
and trusted CA certificate. `invalid_tls` means the certificate could not be
verified; correct identity or CA instead of disabling verification.

`invalid_auth` means the API token was rejected. Replace it through integration
reauthentication after safely updating the Collector verifier.

## Partial, missing or delayed data

`source_status: partial`, lower completeness or missing intervals can be normal
during the current CEZ day. `MISSING` means unpublished; `INVALID` means CEZ
rejected the value. A genuine valid zero remains zero, but numeric zero with an
unavailable CEZ status remains missing.

## Statistics or Energy Dashboard delayed

Four valid quarter-hour intervals are required for one hourly statistic. Check
last success, data timestamp, completeness and grid interval entities. HACS
updates require a Home Assistant restart before new Python code is loaded.

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

- Token pairing, rotation and revocation are manual.
- Local TLS certificate issuance and renewal are manual.
- The requests transport validates DNS before each request, then the HTTP client
  resolves again for connection. This DNS TOCTOU limitation is not pinned-
  transport parity.
- CEZ publication delay determines current-day freshness.
