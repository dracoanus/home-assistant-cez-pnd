# CEZ PND Collector App

The Collector keeps CEZ credentials, meter selectors and normalized SQLite data
inside its App boundary. It serves Home Assistant through authenticated local
HTTPS. See [configuration](../docs/configuration.md) and
[troubleshooting](../docs/troubleshooting.md).

## Normal configuration

For normal operation, configure the CEZ username and password, at least one of
EAN or ELM, choose the history start date, and enable automatic synchronization.

Managed pairing creates the local API identity, TLS trust and Home Assistant API
token automatically. The legacy meter ID, token verifier, TLS certificate and
private-key fields should stay empty unless a recovery procedure explicitly
requires them.

The plaintext bearer token must never be entered in App options, logs, command
lines or this repository.

The current Prague day runs hourly. Historical backfill and completed-day
correction run every six hours. Automatic synchronization writes normalized
SQLite data and does not retain raw CEZ CSV exports.

## Configuration UI

The App ships Czech configuration labels and descriptions with English fallback.
Normal operational settings are shown directly. One-shot diagnostics and legacy
recovery settings are optional and can be revealed with **Show unused optional
configuration options** when troubleshooting requires them.

## Security

The App runs non-root with AppArmor, without host network, privileged mode,
Docker socket or broad host mounts. HTTPS verification is mandatory. Do not
weaken TLS, share App options or post them in support requests.

## Advanced modes

`cez_data_probe_mode`, `cez_http_auth_discovery_mode`,
`cez_requests_preauth_compatibility_mode` and `cez_discovery_mode` are
one-shot diagnostics. They are disabled by default and mutually exclusive with
scheduled sync. Use them only with a specific maintainer troubleshooting plan.
