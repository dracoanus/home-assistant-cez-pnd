# CEZ PND Collector App

The Collector service provides the authenticated API from the normalized
dataset in `/data/cez-pnd.sqlite3`. The Phase 3A source adds an explicit
one-shot CEZ authentication-discovery mode. Normal startup performs no CEZ
request and serves only the last successfully committed dataset.

Before starting the App, provide:

- the opaque synthetic meter ID;
- the lowercase SHA-256 verifier of a separately retained, random bearer
  token containing at least 256 bits of entropy;
- a base64-encoded PEM TLS certificate;
- the matching base64-encoded PEM TLS private key.

The plaintext bearer token must be supplied only to the validation client and,
later, to the limited Home Assistant integration. It must not be entered in
the App options, logs, command line, repository, or image. The TLS certificate
must be valid for the App's Supervisor-assigned internal DNS hostname. The
validation client must trust the issuing private CA or an explicitly reviewed
certificate pin; disabling TLS verification is forbidden.

The service reads its own Supervisor-managed options through the authenticated
v1 `/addons/self/info` endpoint because the non-root UID 2000 process cannot
assume direct access to the Supervisor-owned mode-0600 `/data/options.json`.
Earlier deployment failures and their immutable release history remain in the
Phase 2B evidence. Startup reports only allowlisted non-secret configuration
stages; it never reports an option value, token, verifier, certificate, or key.
TLS PEM material
is decoded into UID-2000-owned mode-0600 files on `/tmp`, loaded into OpenSSL,
and immediately unlinked. The App enables Supervisor's `/tmp` tmpfs.

This bootstrap is limited to HA OS deployment validation. Production pairing,
automatic certificate issuance/renewal, token transfer to Home Assistant Core,
rotation UX, backup treatment, and writable `/data` ownership are **OPEN /
NEEDS VERIFICATION**. See the
[complete validation plan](../docs/phase2b-collector-ha-app.md).

## One-shot Phase 3A discovery

The discovery inputs exist only in Supervisor-managed private options. Both
`cez_username` and `cez_password` use the `password` schema and are never
written to `/data`. Actual CEZ URLs and origins are deliberately not supplied
by the project; they require owner review and live verification.

Keep `cez_discovery_mode` disabled for every normal API start. For the first
authorized run, follow the exact preparation, invocation, evidence, and
rollback procedure in the
[Phase 3A discovery document](../docs/phase3a-cez-auth-discovery.md). Discovery
is not exposed through the Collector HTTP API.

## One-shot Phase 3C HTTP authentication discovery

`cez_http_auth_discovery_mode` is disabled by default. It uses a
redirect-disabled, TLS-verifying `requests.Session` with the existing masked
CEZ username and password and the fixed reviewed HTTP destination contract;
the generic Selenium URL/origin settings do not expand this policy.
It performs one bounded attempt, never calls data/export endpoints, reports
only fixed non-secret events, destroys its session, and exits with
`needs_live_verification`. Do not enable it together with
`cez_discovery_mode`; conflicting modes fail before network or browser startup.
Every hop still receives the existing HTTPS/port/hostname/path/method and
all-global DNS validation. `requests` performs a second DNS resolution for the
actual connection, so this active compatibility transport does not provide the
old strict transport's pinned-IP guarantee.

This mode is for a separately authorized HA OS live test only. See the
[Phase 3 document](../docs/phase3a-cez-auth-discovery.md) for its pinned DNS,
TLS, redirect, credential, evidence, and open-verification requirements.

## One-shot authenticated data probe

`cez_data_probe_mode` is disabled by default and is mutually exclusive with
all discovery modes. When explicitly enabled, it uses the same authenticated,
memory-only `requests.Session` for login, bounded dashboard metadata retrieval,
and exactly two raw CSV exports for one configured calendar day. Set
`cez_data_probe_date` to an ISO date such as `2026-09-08`. Configure at least
one private meter selector: `cez_ean` (exactly 18 ASCII digits), `cez_elm`, or
both. Both are masked private options; EAN and ELM remain inside the Collector
and are never written to logs. Normal Collector startup remains offline.

The authenticated meter lookup is best-effort when a validated `cez_elm` is
already configured: an unavailable lookup is recorded structurally and export
continues with that ELM. Usable CEZ meter data that contradicts or ambiguously
matches the configured identity still fails closed. EAN-only selection requires
the lookup because an ELM must be derived before export.

The probe writes only these files under `/data/cez-pnd-probe`:

- `metadata-summary.json`
- `range-consumption.csv`
- `range-production.csv`

At container startup, a root-owned immutable bootstrap creates or repairs only
this probe directory as UID/GID `2000:2000`, mode `0700`, then drops all
supplementary groups and permanently executes the service as UID/GID
`2000:2000`. It does not recursively modify `/data`. The atomically replaced
files are mode `0600`. The CSV files are raw private CEZ exports and may contain account or
meter identifiers and measurements. Do not publish them, attach them to issue
reports, add them to Git, or expose them in logs. The JSON summary contains
only validation booleans and byte counts, never metadata values.

For an owner-authorized manual HA OS probe, keep the App stopped, enable only
`cez_data_probe_mode`, retain the existing private CEZ credentials, set exactly
one probe date, optionally set the masked ELM value, save, and start the App
once. Require the fixed `data_probe_started`, metadata/export receipt,
`data_probe_consumption_parsed`, `data_probe_production_parsed`,
`data_probe_dataset_committed`, `data_probe_complete`, cleanup, and
authenticated result events. The App exits after the one-shot attempt. Then
disable the mode and restart into normal HTTPS service mode to expose the
committed revision. A failed or incomplete event sequence is not a successful
data acquisition result.

After both bounded CSV responses pass HTTP validation, the probe parses the
downloaded bytes directly, preserves valid/missing/invalid quality separately,
and commits consumption plus production atomically to SQLite. Parser or
database failure leaves the previous revision intact. Initial historical
backfill, scheduling, persisted synchronization checkpoints, incremental
fetches, and a bounded correction overlap belong to a later phase.

## Temporary requests PREAUTH compatibility mode

`cez_requests_preauth_compatibility_mode` is disabled by default and is
mutually exclusive with both discovery modes above. When explicitly enabled,
it follows only the reviewed PREAUTH `GET` redirect chain with
`requests.Session`, stops before form parsing or credential submission, clears
its memory-only cookies, and exits. TLS verification and manual per-hop
destination/DNS validation remain mandatory. The library performs its own DNS
lookup for the connection after validation, so this experiment does not have
the strict transport's validated-IP connection guarantee and is not the final
transport architecture.
