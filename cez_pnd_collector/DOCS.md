# CEZ PND Collector App

The released `0.2.3` service provides the authenticated synthetic Collector
API. The unreleased Phase 3A source adds an explicit one-shot CEZ
authentication-discovery mode. Normal startup remains synthetic-only and does
not start a browser or contact CEZ.

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
