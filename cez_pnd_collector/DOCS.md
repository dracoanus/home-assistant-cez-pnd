# CEZ PND Collector App

The Collector keeps CEZ credentials, meter selectors and normalized SQLite data
inside its App boundary. It serves Home Assistant through authenticated local
HTTPS. See [configuration](../docs/configuration.md) and
[troubleshooting](../docs/troubleshooting.md).

## Required production settings

Configure `meter_id`, `api_token_sha256`, TLS certificate and private key, CEZ
username/password, at least one of `cez_ean` or `cez_elm`, and set
`cez_sync_enabled` to `true`. All credentials, certificates, EAN and ELM are
private. The plaintext API token is not an App option; retain it only for the
Home Assistant integration or another trusted API client.

The plaintext bearer token must never be entered in App options, logs, command
lines or this repository. The App stores only its SHA-256 verifier.

The current Prague day runs hourly. Historical backfill and completed-day
correction run every six hours. Automatic synchronization writes normalized
SQLite data and does not retain raw CEZ CSV exports.

## Security

The App runs non-root with AppArmor, without host network, privileged mode,
Docker socket or broad host mounts. HTTPS verification is mandatory. Do not
weaken TLS, share App options or post them in support requests.

## Advanced modes

`cez_data_probe_mode`, `cez_http_auth_discovery_mode`,
`cez_requests_preauth_compatibility_mode` and `cez_discovery_mode` are
one-shot diagnostics. They are disabled by default and mutually exclusive with
scheduled sync. Use them only with a specific maintainer troubleshooting plan.
