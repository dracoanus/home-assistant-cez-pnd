# Maintainer context

Technical handoff only. Do not store secrets, customer configuration or private
reasoning here.

This document preserves context, not runtime truth. Before changing behavior,
verify every assumption against the current source, tests, release workflow and
fresh deployment evidence. Historical phase documents describe the state at
their recorded time and must not override current implementation contracts.

## Current architecture

Collector/App `0.3.32` uses browserless CEZ HTTP authentication, normalized
SQLite and a narrow local HTTPS API. HA integration `0.1.8` reads that API,
exposes sensors and writes Recorder external statistics. CEZ credentials, EAN
and ELM stay in Collector configuration; HA has only a limited API token,
opaque meter ID and Collector CA certificate.

API routes: `GET /api/v1/health`, `GET /api/v1/status` and
`GET /api/v1/measurements`. There is no browser, shell, debug or arbitrary URL
API.

## Data invariants

- CEZ quarter-hour profiles use 96/92/100 Prague-day grids.
- Valid: `naměřená data OK` and voltage-outage status. Invalid: `neplatná data`.
  Missing: `neznámá hodnota`. Unknown status fails closed.
- For kW profile rows, kWh is `kW × 0.25`.
- SQLite UPSERT is idempotent; later valid data replaces missing placeholders.
- `data_timestamp` is the maximum valid interval end, never a future missing
  interval.
- Current day runs hourly; backfill and correction run every six hours in one
  serialized worker.

## Statistics trap

Current-day SQLite data may contain future `MISSING` rows later than
`data_timestamp`. Full HA reconciliation must not stop at
`ceil_hour(data_timestamp)`. It deliberately extends through the relevant
timezone-aware next `Europe/Prague` midnight. Keep DST calculations aware.
Only four valid quarter-hour intervals form an hourly Recorder statistic.

## Security and technical debt

Keep non-root/AppArmor/no-host-network/no-Docker-socket operation, strict TLS,
manual redirect validation, bounded memory-only cookies and secret-free logs.
The requests compatibility transport validates DNS before a request, then the
HTTP client resolves again when connecting. This DNS TOCTOU limitation is not
pinned-transport security parity.

Fixed regressions include full `Datum` timestamps, +A/-A profile recognition,
voltage-outage validity, private SQLite sidecar ownership, history checkpoint
rebasing, large HA metadata counts, current-day missing bounds and separate
hourly/six-hour cadences.

High-value live validation established browserless CEZ authentication, both CEZ
CSV exports, 92/96/100-interval parsing, transactional SQLite persistence,
authenticated local API reads, Home Assistant sensors, Recorder statistics and
Energy Dashboard grid import/export. The `kW × 0.25` conversion matched CEZ's
60-minute view. Revalidate these observations when CEZ or HA behavior changes.

## Releases and roadmap

Collector versions: `collector/VERSION`, `collector/collector_service/__init__.py`,
`cez_pnd_collector/config.yaml`, `collector/static_verify.py`; tag format:
`collector-service-vX.Y.Z`. HA version: `custom_components/cez_pnd/manifest.json`;
HACS requires a real `vX.Y.Z` GitHub Release. Verify `origin/main` and versions
before tagging; never rewrite public tags.

Future work: automated TLS/token lifecycle, safer DNS connection pinning,
operational monitoring and further CEZ compatibility validation.
