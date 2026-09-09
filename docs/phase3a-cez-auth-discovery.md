# Phase 3A — CEZ authentication/discovery foundation

Status: **IMPLEMENTED LOCALLY / LIVE CEZ VERIFICATION NOT STARTED**

This phase prepares one explicitly authorized browser run. It does not
implement production PND collection, change the synthetic Collector API, or
claim any CEZ portal address, selector, redirect, or success behavior.

## Threat boundary and credentials

CEZ credentials enter only the Home Assistant App's Supervisor-managed private
options. `cez_username` and `cez_password` both use the App `password` schema.
They are used by the UID/GID 2000 browser process only when
`cez_discovery_mode` is true. The Collector removes their entries from its
in-memory options mapping immediately after discovery configuration is loaded.
They are not copied into environment variables, command-line arguments,
`/data`, API objects, responses, diagnostics, or log messages.

The discovery configuration dataclass suppresses both credential fields from
its representation. Browser and ChromeDriver output goes to `/dev/null`.
Exceptions are reduced to fixed events without exception text. The Collector
API remains limited to `/api/v1/health`, `/api/v1/status`, and
`/api/v1/measurements`; it has no browser or authentication endpoint.

## Exactly what discovery does

The operator must explicitly configure a start URL, the sole origin where
credentials may be entered, and one to eight allowed HTTPS origins. The
implementation supplies no CEZ URL.

One discovery-mode start performs these bounded steps:

1. Validate all destinations as HTTPS DNS origins on port 443. IP literals,
   embedded credentials, and configured query strings or fragments fail.
2. Start a loopback-only CONNECT proxy. It resolves and connects only an
   allowlisted hostname on port 443 and rejects non-global target addresses.
3. Start packaged Chromium/ChromeDriver as UID/GID 2000 with the existing
   sandbox, new headless mode, Chromium DNS disabled, background networking
   disabled, QUIC disabled, and all traffic directed through the proxy.
4. Deny downloads through the fixed Chrome DevTools command before external
   navigation.
5. Navigate to the configured start URL with a 20-second page timeout.
6. Require exactly one visible enabled password input and exactly one visible
   enabled text/email input in one form. No portal-specific selector is used.
7. Require the current page and form action to match the explicitly configured
   authentication origin before entering credentials.
8. Submit once and observe for at most 30 seconds. A changed URL, allowed
   origin, and disappearance of the unambiguous login form is reported only as
   an apparent authentication success for discovery purposes.
9. Delete browser cookies, quit WebDriver, stop ChromeDriver, remove the
   mode-0700 temporary profile on `/tmp`, report cleanup, and exit.

Observed URLs are reduced to a normalized hostname and one fixed path category:
`root`, `login_like`, `account_like`, or `other`. Query strings, fragments,
DOM text, form values, cookies, authorization data, screenshots, HTML, and
page source are never emitted.

## What discovery does not do

- It does not run during normal Collector startup.
- It does not persist a browser profile, cookie, credential, screenshot, DOM,
  page source, or downloaded file.
- It does not expose arbitrary URLs, selectors, JavaScript, commands, or
  browser actions over HTTP.
- It does not infer undocumented CEZ API endpoints or scrape PND data.
- It does not modify `/status` or `/measurements`; both remain synthetic.
- It does not add privileges, capabilities, mounts, devices, host networking,
  Supervisor permissions, or sandbox-disabling Chromium arguments.

## First manually authorized HA OS procedure

Do not perform these steps until the owner has reviewed the actual CEZ
destinations and explicitly authorized the live run.

1. Stop the App and confirm normal synthetic API operation has already been
   recorded independently.
2. In App configuration, keep all existing Collector API/TLS options. Set the
   reviewed `cez_start_url`, exact `cez_auth_origin`, and the minimal reviewed
   `cez_allowed_origins` list. Do not add speculative origins.
3. Enter the CEZ username and password in their masked fields.
4. Set `cez_discovery_mode` to true, save, and start the App once.
5. The App runs discovery instead of the HTTPS API and exits after success or
   failure. Do not configure automatic restart or watchdog behavior for this
   run.
6. Review only the allowlisted events below. Stop if any unexpected origin,
   configuration error, cleanup failure, or non-allowlisted output appears.
7. Immediately set `cez_discovery_mode` back to false and clear the CEZ
   username, password, URL, authentication origin, and allowed-origin list.
8. Save and start normal mode. Verify the unchanged authenticated synthetic
   API. No secret reinjection is needed for that API.

## Expected safe events

Only these discovery events are permitted:

- `browser_started`
- `login_page_reached`
- `credentials_submitted`
- `authentication_succeeded`
- `authentication_failed`
- `unexpected_origin`
- `timeout`
- `browser_cleanup_complete`

An event may include only a sanitized hostname and fixed path category. A
successful run must end with `browser_cleanup_complete`. The word
`authentication_succeeded` is a discovery heuristic, not proof that the CEZ
session is suitable for PND collection.

Configuration can fail before the browser starts. In that case the existing
`startup_failed` envelope contains only one fixed `discovery_config_*` code for
invalid mode, start URL, authentication origin, allowed origins, username, or
password. It never contains the invalid value or underlying exception text.

## Rollback

Stop the App, disable discovery mode, clear all discovery destination and
credential fields, and save. Restarting then follows the unchanged synthetic
API path. If the source build is under test, reinstall the immutable Collector
0.2.3 image. Do not reuse or export the temporary browser state.

## OPEN / NEEDS VERIFICATION

- Actual CEZ start URL, credential origin, allowed redirect origins, and final
  authenticated path category.
- Whether the portal's form is represented by the conservative generic form
  rule or requires a reviewed portal-specific change.
- Whether submission causes a changed URL and removes the login form, and how
  an authentication rejection can be distinguished safely.
- Whether all intermediate top-level redirect origins can be observed without
  retaining sensitive URLs. The current evidence reports only safely observed
  locations and proxy rejections; it does not claim a complete redirect chain.
- HA OS confirmation that the local proxy is the only Chromium egress path for
  the tested browser configuration.
- HA OS confirmation of renderer UID/GID, seccomp, NoNewPrivs, namespace and
  capability evidence for the discovery build. Existing runtime evidence is
  positive, but this new invocation still requires its gate.
- Confirmation that download denial succeeds before external navigation on the
  target Chromium/ChromeDriver build.
- Supervisor backup behavior for masked CEZ options and the operator process
  for immediate credential removal after the one-shot run.

No live CEZ request or authentication was performed while implementing this
foundation.

## Phase 3B — browserless HTTP authentication foundation

Status: **IMPLEMENTED LOCALLY / NOT WIRED TO STARTUP / NEEDS LIVE
VERIFICATION**

The preferred future path is a direct HTTPS authentication state machine in
the Collector. Selenium remains the explicit Phase 3A fallback and diagnostic
tool; an HTTP failure never starts Selenium automatically. Home Assistant Core
continues to receive only the limited Collector API credential.

The new `cez_http_auth.py` foundation models these states:

1. `PREAUTH`: GET the reference PND landing page.
2. `CREDENTIAL_FORM`: follow individually approved redirects and require one
   unambiguous POST login form.
3. `CREDENTIAL_SUBMISSION`: revalidate the form action immediately before
   encoding the username and password, then POST only to an approved IdP.
4. `AUTH_REDIRECTS`: inspect, resolve, and validate every redirect before the
   next GET.
5. `AUTHENTICATED`: reserved for a future positively verified success
   condition. The present implementation returns
   `needs_live_verification`, never authenticated success.

The version-controlled candidate contract comes from protocol evidence in
[`http_client.py`](https://github.com/igracek/HACS_CEZD_PND/blob/main/custom_components/cez_pnd/http_client.py)
and
[`const.py`](https://github.com/igracek/HACS_CEZD_PND/blob/main/custom_components/cez_pnd/const.py).
Those files declare `pnd.cezdistribuce.cz`, `mepas.cez.cz`, and
`dip.cezdistribuce.cz`, with candidate `/cezpnd2`, `/cas`, `/idp`, and
`/login` paths. Their current runtime behavior is not established by source
presence.

Every prospective request is checked for HTTPS, effective port 443, exact
state-specific hostname, path prefix, method, absence of URL userinfo, and
globally routable resolved addresses. Credential POST destinations also reject
queries until a safe live contract proves one necessary. Automatic redirects
and proxy-environment inheritance are forbidden by the transport contract.
Redirect count, operation/connect/read time, response bodies and headers, HTML,
form controls and values, and memory-only cookies are bounded.

The standard-library parser rejects malformed or ambiguous form structure,
non-POST credential forms, duplicate critical fields, excessive controls and
values, and an unapproved action. Hidden inputs are preserved without assuming
that `execution`, `_eventId`, or `lt` must always occur. The username and
password are injected only after the last action validation.

Credentials are held in representation-suppressed objects. Results and errors
contain fixed codes only. Cookies are exact-host, memory-only values; they are
cleared and the supplied transport is closed on every result. No HTML, URL,
cookie, credential, exception text, or session data is logged or exposed by
the module.

No production transport is connected yet. Normal Collector startup and the
synthetic `/health`, `/status`, and `/measurements` API are unchanged. No CEZ
request, Chromium execution, data endpoint, download, or export is part of
Phase 3B.

The upstream project uses the MIT License. This implementation adapts the
documented protocol concepts independently rather than copying its client.
Any future substantial copied portion must retain the upstream copyright and
permission notice required by its
[`LICENSE`](https://github.com/igracek/HACS_CEZD_PND/blob/main/LICENSE).

### Phase 3B OPEN / NEEDS LIVE VERIFICATION

- The exact current redirect sequence, status codes, and necessary query
  parameters.
- Which candidate IdP hostname and path receive credentials.
- Login-form method, action, encoding, field names, hidden inputs, CSRF state,
  and HTML character encoding.
- Required cookies, their attributes, host/path scope, expiry, renewal, and
  logout behavior.
- A positive, bounded proof of authenticated PND application state.
- MFA, CAPTCHA, account lock, maintenance, retry, and rate-limit behavior.
- Whether a production transport can connect to the already validated address
  without a second DNS resolution and while preserving hostname-based TLS
  verification.
- All PND metadata, meter, data, and export endpoints and response schemas.

## Phase 3C — pinned-resolution TLS transport

Status: **IMPLEMENTED LOCALLY / EXPLICIT ONE-SHOT MODE / LIVE RUN NOT
PERFORMED**

Phase 3C closes the DNS time-of-check/time-of-use gap in the Phase 3B
foundation. For each request, the strict transport resolves the reviewed
hostname exactly once, rejects the complete result if any address is
non-global, sorts and bounds the approved address set, and passes that frozen
set into the request. TCP connects directly to a selected numeric address; it
does not resolve the hostname again.

The original reviewed hostname remains distinct from the numeric peer. It is
used as TLS SNI, as the certificate hostname with `check_hostname=true`, and
as the HTTP `Host` header. The TLS context uses system trust, requires
`CERT_REQUIRED`, and enforces TLS 1.2 or newer. Neither proxy environment
variables nor redirects are supported. GET and POST over HTTPS port 443 are
the only operations. Multiple IPs use deterministic IPv4/IPv6 numeric order,
at most four already-validated TCP attempts, and no new DNS result. A TLS
verification failure is never retried against another address.

Headers and bodies are read with fixed limits. Connect, TLS handshake, read,
and total-operation deadlines remain bounded. Transport failures are reduced
to fixed codes; raw exception strings, headers, HTML, cookies, form fields,
queries, and complete URLs are not emitted.

The new Supervisor option `cez_http_auth_discovery_mode` defaults to false.
When explicitly enabled it performs one HTTP authentication discovery attempt
and exits after cleanup. It uses the existing masked `cez_username` and
`cez_password` options and the fixed code-owned destination contract. It does
not use the generic Selenium URL/origin options. Enabling both HTTP and
Selenium discovery fails during configuration loading before either network
or browser operation. There is no retry loop or automatic fallback.

Normal startup remains the synthetic HTTPS Collector API. The HTTP one-shot
flow still ends in `auth_state_needs_live_verification`; this is a completed
discovery result, not proof of authentication. No meter, data, or export
endpoint is called.

### Phase 3C OPEN / NEEDS LIVE VERIFICATION

- Real HA OS DNS results and IPv4/IPv6 reachability for each required host.
- TLS chain, hostname, SNI, protocol-version, and certificate-rotation behavior
  on the actual CEZ endpoints.
- Whether strict rejection of a mixed safe/unsafe DNS answer is compatible
  with the real deployment while preserving fail-closed policy.
- Current redirect, form, query, cookie, CSRF, MFA/CAPTCHA, and positive
  authenticated-state contracts listed for Phase 3B.
- Safe interpretation of the first one-shot result; no success condition may
  be added from assumptions or source-only evidence.

## Later data-acquisition requirement

Phase 3C does not download or persist CEZ measurements. In the later
data-acquisition phase, initial setup will accept an owner-selected history
start date and backfill from that date through the latest available CEZ
measurement. The Collector will persist a synchronization checkpoint and then
request only newer measurements. A bounded overlap window may subsequently
re-read recent intervals so corrected CEZ values can be applied through
idempotent upsert and deduplication. Exact endpoints, availability limits,
checkpoint schema, overlap duration, correction semantics, and retention are
**OPEN / NEEDS LIVE VERIFICATION**.
