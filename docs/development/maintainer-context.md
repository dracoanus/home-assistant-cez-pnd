# Maintainer context

Technical handoff only. Do not store secrets, customer configuration or private
reasoning here.

This document preserves context, not runtime truth. Before changing behavior,
verify every assumption against the current source, tests, release workflow and
fresh deployment evidence. Historical phase documents describe the state at
their recorded time and must not override current implementation contracts.

## Current architecture

Collector/App `0.3.38` uses browserless CEZ HTTP authentication, normalized
SQLite and a narrow local HTTPS API. HA integration `0.1.10` reads that API,
exposes sensors and writes Recorder external statistics. CEZ credentials, EAN
and ELM stay in Collector configuration; HA has only a limited API token,
opaque meter ID and Collector CA certificate.

Data API routes: `GET /api/v1/health`, `GET /api/v1/status` and
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

## Phase 5B managed pairing implementation

Phase 5B-B1 deliberately uses Supervisor discovery instead of Ingress.
Supervisor binds each discovery message to the requesting App and accepts only
services declared by that App. The `cez_pnd` payload is bounded and carries a
short-lived bootstrap secret plus public trust data; it never contains CEZ
credentials, EAN/ELM, private keys, an arbitrary hostname, or a long-lived API
token. The HA flow derives the internal hostname from the
Supervisor-provided App slug.

New installations with none of the four legacy identity options use an atomic
managed identity in `/data/cez-pnd-identity`. The root entrypoint creates only
that private `0700` directory, then UID/GID 2000 generates the CA and leaf
keys. Complete legacy identity/token options retain exact precedence. A partial
legacy set is always an error and must never trigger silent CA or token
replacement.

Managed credentials have at most one ACTIVE verifier, one PENDING verifier and
one bootstrap authorization. Bootstrap lifetime is ten minutes with eight
attempts; PENDING lifetime is 24 hours and survives restart. Only ACTIVE can
authorize the existing read API. Activation is idempotent and never removes
discovery. Cleanup is a separate retryable finalize step that never revokes a
successfully activated token.

The managed-only pairing surface is exactly `POST /pairing/v1/claim`,
`POST /pairing/v1/activate` and `POST /pairing/v1/finalize`. It is separate from
the three data routes and does not expose credential, browser, file, or
arbitrary command functionality.

Phase 5B-B2 supplies the HA `SOURCE_HASSIO` side. The flow removes and validates
Core's `addon` metadata, then validates the remaining exact seven-field
Collector payload. It derives the internal HTTPS origin exclusively from the
strict Supervisor App slug (`_` becomes `-`); it never accepts a discovered URL
or hostname. The flow immediately replaces framework `init_data` with a
secret-free `HassioServiceInfo`; its transient dataclass hides the pairing
secret from repr. HA generates the long-lived random token and durably stores
it before claim in a private atomic public `Store` journal, together with only
the meter ID, Collector origin, public CA and bounded phase. It then submits
only the token's SHA-256 verifier. Pairing ID, pairing secret, expiry, discovery
UUID and verifier are never ConfigEntry or journal data.
One HA-instance recovery manager owns the Store and an async lock. Confirmation
must reload the journal inside that lock and hold ownership through bounded
claim. Never rely on recovery state cached when discovery first arrived.

The ConfigEntry unique ID must remain `meter_id`, not the Supervisor discovery
UUID. ConfigEntry setup occurs before Core schedules its persistent save, so
initial setup must not finalize discovery. It activates and verifies the API,
then retains the recovery journal, discovery and a non-secret finalize marker.
An in-memory marker identifies entries created in the current process. Only a
later process loading the persisted entry calls finalize; after success HA
removes the pending markers but retains the journal. A further process that
loads the permanent managed marker with both pending markers absent may remove
the journal. A process-lifetime finalized marker prevents same-process setup,
manual reload, unload/load, retry and options reload from being mistaken for
that further process. This process boundary proves marker persistence and means
journal cleanup can legitimately require an additional HA restart. Cleanup
uses the recovery ownership lock, reloads under the lock and deletes only an
exact meter/origin/CA/token match. Cleanup failure does not block ACTIVE
operation. Repeated claim with the same authorization and verifier is
idempotent, covering crashes before ConfigEntry creation. Collector restart
preserves discovery for ACTIVE, unexpired PENDING and unexpired bootstrap
state; only expired/unpaired reconciliation may replace it. The meter identity
prevents discovery deletion from deleting the ConfigEntry. No timer, private
Core persistence API or `.storage/core.config_entries` access is used.
Existing manual entries have no markers and never use the journal, activate or
finalize.

Live Home Assistant OS validation completed the managed flow end to end:
identity creation, Supervisor discovery, guided claim and activation,
ConfigEntry persistence across Core restart, finalize, discovery removal and
recovery-journal cleanup in the following Core process. Guided pairing is the
normal installation path. Automatic leaf renewal, CA rotation, managed-token
rotation and legacy-to-managed migration remain deferred.
