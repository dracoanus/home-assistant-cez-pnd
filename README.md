# CEZ PND for Home Assistant

CEZ PND Collector brings historical electricity import and export data from
CEZ PND into Home Assistant. It consists of a secure Collector App and a
separate Home Assistant integration for sensors, Recorder statistics and the
Energy Dashboard.

This is an independent community project. It is not affiliated with, endorsed
by or supported by CEZ.

## Status

The current Collector/App release is `0.3.32` and the Home Assistant
integration is `0.1.8`. Real authenticated CEZ PND collection, normalized
SQLite storage, historical backfill, current-day refresh, local HTTPS access,
Recorder external statistics and Energy Dashboard import/export statistics have
been validated. See [known limitations](docs/troubleshooting.md#known-limitations)
before installation.

## What it provides

- CEZ billing-meter-derived grid import and export energy.
- Historical backfill from a user-selected date.
- Current Prague-local-day refresh every hour and historical correction/backfill
  work every six hours.
- Correct handling of unavailable CEZ intervals: missing data is never made
  into zero consumption.
- Home Assistant sensors for Collector health, source state, timestamps,
  completeness and counts.
- Recorder external statistics: `cez_pnd:grid_import_energy` and
  `cez_pnd:grid_export_energy`.

```text
CEZ PND
  -> CEZ PND Collector App
  -> authenticated local HTTPS API
  -> Home Assistant CEZ PND integration
  -> sensors + Recorder statistics
  -> Energy Dashboard
```

The Collector owns CEZ credentials and authenticated CEZ communication. Home
Assistant Core receives only a limited Collector API token, an opaque meter ID
and the CA certificate needed to verify local HTTPS. This keeps Chromium,
browserless authentication and CEZ credentials outside Home Assistant Core.

## Supported environment

- Home Assistant OS with the App/Supervisor model, amd64.
- HACS for installing the custom integration.
- A CEZ PND account with accessible electricity-meter data.
- A trusted local TLS certificate and a separately retained Collector API
  token. Pairing and token rotation are currently manual.

## Install

1. Add this repository in **Settings → Apps → App Store → Repositories** and
   install **CEZ PND Collector**.
2. Configure and start the Collector App.
3. Add this repository as a custom repository in HACS and install
   **CEZ PND Collector**.
4. Restart Home Assistant after the HACS installation, then add the
   integration in **Settings → Devices & services**.

Follow the detailed [installation guide](docs/installation.md) and
[configuration guide](docs/configuration.md). The
[Energy Dashboard guide](docs/energy-dashboard.md) explains the resulting
statistics.

## Synchronization and data quality

The Collector stores 15-minute CEZ intervals in the `Europe/Prague` calendar.
Normal, spring-DST and autumn-DST days contain 96, 92 and 100 intervals.
Completed historical days retain complete-grid validation. The current day also
requires a full structural grid, but unpublished intervals are accepted as
`MISSING`.

- `VALID` means a CEZ measurement is available, including a real measured zero.
- `MISSING` means CEZ has not published the value; it is never zero-filled.
- `INVALID` means CEZ marked the value invalid; it is never used as energy.

CEZ current-day publication can be delayed. Home Assistant creates an hourly
energy statistic only when all four valid quarter-hour intervals for that hour
are available. Later Collector revisions reconcile newly published data.

## Security summary

- CEZ credentials remain in Collector private configuration.
- The local API requires HTTPS with certificate verification and a scoped bearer
  token.
- The App is non-root, AppArmor-confined, without host networking, Docker
  socket, broad mounts or privileged access.
- Automatic synchronization persists normalized data only; it does not retain
  raw CEZ CSV exports.
- Unknown CEZ statuses fail closed.

Never post CEZ credentials, API tokens, EAN/ELM identifiers, certificates,
private keys or raw CEZ exports in an issue.

## Help, updates and removal

- [Troubleshooting](docs/troubleshooting.md)
- [Updating](docs/updating.md)
- [Architecture and security model](docs/architecture.md)
- [Development and maintainer material](docs/development/README.md)

To uninstall, remove the Home Assistant integration and then stop/uninstall
the Collector App. Export or deliberately remove Collector data according to
your own Home Assistant backup policy; removing the App can remove its
persistent dataset.

## License and acknowledgements

This project is licensed under the [MIT License](LICENSE). CEZ CSV parser
semantics are adapted from the MIT-licensed
[HACS_CEZD_PND](https://github.com/igracek/HACS_CEZD_PND) project; attribution
is retained in the relevant Collector source.
