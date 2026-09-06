# Secure CEZ PND — Project Specification

Status: authoritative target specification revised according to owner decisions; revision awaits review. No Phase 2A execution or production implementation is authorized. Version: 0.2. Date: 2026-09-06. Repository: `dracoanus/home-assistant-cez-pnd`.

This document defines the intended product and its acceptance requirements. It does not assert that the product exists, that a security control has passed, or that Phase 2 has started. Owner decisions and verification gates remain open where explicitly identified.

The immutable evidence baseline is [Phase 1 analysis](phase1-analysis.md), based on reference commit `747e755cad1517079f96b86a27d2ae425df5b903`. Its conclusions, including **NOT READY**, remain unchanged. This specification resolves the previously missing specification artifact, but does not resolve the other blockers by declaration. Findings in the analysis describe the reference; requirements here describe the new product. Reference implementation details are not automatically valid CEZ contracts.

## Normative language and evidence

| Classification | Meaning |
|---|---|
| REQUIRED | Mandatory acceptance condition; MUST has the same meaning. |
| RECOMMENDED | Preferred design; departure requires a documented rationale and review. |
| OPTIONAL | Explicitly outside the mandatory first release unless selected. |
| FORBIDDEN | Prohibited behavior; MUST NOT has the same meaning. |
| OPEN / NEEDS VERIFICATION | Not established or not approved; never an implicit permission or a working default for security-sensitive behavior. |

Security-critical requirements have stable IDs and a requirement, rationale, threat, and acceptance method. The detailed rules in each section are part of the referenced requirement. Acceptance methods are future tests or reviews, not claims of completed verification. All open issues are enumerated in section 47; no unrecorded assumption may close one.

Evidence references used throughout:

| ID | Evidence |
|---|---|
| E1 | [Phase 1](phase1-analysis.md), sections 1–5: structure, authentication, credentials and security findings. |
| E2 | [Phase 1](phase1-analysis.md), sections 6–9: retrieval, identifiers, statistics and failures. |
| E3 | [Phase 1](phase1-analysis.md), sections 10–11: licensing and dependencies. |
| E4 | [Phase 1](phase1-analysis.md), sections 12–16: target boundaries, Supervisor, networking, API and threats. |
| E5 | [Phase 1](phase1-analysis.md), sections 17–18: migration and entry blockers. |
| E6 | [Reference source tree](https://github.com/igracek/HACS_CEZD_PND/tree/747e755cad1517079f96b86a27d2ae425df5b903). |
| E7 | [Reference origin constants](https://github.com/igracek/HACS_CEZD_PND/blob/747e755cad1517079f96b86a27d2ae425df5b903/custom_components/cez_pnd/const.py) and [login code at L938](https://github.com/igracek/HACS_CEZD_PND/blob/747e755cad1517079f96b86a27d2ae425df5b903/custom_components/cez_pnd/client.py#L938). |
| E8 | [Reference download flow at L1307](https://github.com/igracek/HACS_CEZD_PND/blob/747e755cad1517079f96b86a27d2ae425df5b903/custom_components/cez_pnd/client.py#L1307), [parser](https://github.com/igracek/HACS_CEZD_PND/blob/747e755cad1517079f96b86a27d2ae425df5b903/custom_components/cez_pnd/parser.py), [statistics](https://github.com/igracek/HACS_CEZD_PND/blob/747e755cad1517079f96b86a27d2ae425df5b903/custom_components/cez_pnd/statistics.py). |
| E9 | [App configuration](https://developers.home-assistant.io/docs/apps/configuration/), [communication](https://developers.home-assistant.io/docs/apps/communication/), [security](https://developers.home-assistant.io/docs/apps/security/), [Ingress](https://developers.home-assistant.io/docs/apps/presentation/#ingress), as considered in Phase 1. |
| E10 | [Reference LICENSE](https://github.com/igracek/HACS_CEZD_PND/blob/747e755cad1517079f96b86a27d2ae425df5b903/LICENSE), [manifest](https://github.com/igracek/HACS_CEZD_PND/blob/747e755cad1517079f96b86a27d2ae425df5b903/custom_components/cez_pnd/manifest.json), [SBOM](https://github.com/igracek/HACS_CEZD_PND/blob/747e755cad1517079f96b86a27d2ae425df5b903/custom_components/cez_pnd/sbom.json). |

External documentation links provide provenance for Phase 1, not an assertion of newly verified deployment support. Owner decisions in revision 0.2 govern the v1 design where they change earlier recommendations; they do not alter Phase 1 evidence. CLOSED means the owner decision or v1 scope disposition is settled, not that runtime tests have passed. Exact tested versions will be recorded during Phase 2A; minimum supported HA Core/Supervisor versions remain OPEN pending compatibility testing (O-01).

## 1. Project goals

**REQUIRED:** Build two separately deployed components: a Home Assistant App containing the CEZ PND Collector, and a minimal Home Assistant custom integration consuming its authenticated local data API. Retrieve historical electricity import/export measurements through the verified portal export workflow, normalize and validate them, and expose sensors and Recorder statistics without CEZ credentials or browser automation in Core.

The approved first-release target is Home Assistant OS in the Supervisor/App environment, **amd64 only**, running as a VM on Synology VMM, with **one CEZ account and one measurement point**. Scheduled daily updates, bounded manual backfill and deterministic corrections remain in scope. aarch64, multi-account and multi-meter support are outside initial v1. O-01 scope is CLOSED; exact minimum supported HA Core/Supervisor versions and the tested runtime matrix remain OPEN / NEEDS VERIFICATION.

**REQUIRED:** Prefer unavailable or explicitly incomplete data over invented values. Keep security failures visible and fail closed.

## 2. Non-goals

**FORBIDDEN:** Implement application code, Dockerfiles, deployment configuration, or start Phase 2 as part of preparing this document.

The first release does not provide arbitrary browsing, remote desktop, generic scraping, CAPTCHA bypass, automated MFA circumvention, CEZ account administration, or a credential export facility. It does not promise real-time consumption, billing-grade accuracy, generation/self-consumption inference from grid import/export alone, or immunity to a compromised trusted host.

Direct undocumented CEZ internal API use, Firefox/GeckoDriver fallback, public/LAN exposure of the data API, aarch64, multi-account and multi-meter operation are outside the first release. O-11 is **CLOSED FOR V1: excluded**. Existence and usability of `POST /cezpnd2/external/data` remain unverified facts; neither may be assumed. V1 uses the verified portal workflow and CSV export. A future direct API adapter requires new evidence and an explicit specification revision.

## 3. Security objectives

| ID | Requirement | Rationale | Threat mitigated | Verification / acceptance |
|---|---|---|---|---|
| SEC-01 | REQUIRED: CEZ username/password belong only to the Collector App configuration/security boundary, including its trusted Supervisor-managed configuration path; session secrets remain in the Collector runtime. Necessary owner input and verified CEZ submission are explicit external endpoints. Credentials MUST NOT exist in Core, ConfigEntry, custom integration configuration, Core services, Core logs or Core diagnostics. | E1 identifies ConfigEntry exposure; approved O-02/O-05 trust Supervisor-managed App configuration, not the integration. | Secret dissemination through the Core data/integration boundary. | Trace the supported App configuration path and effective storage using synthetic credentials; inspect Core ConfigEntry, integration, services, logs and diagnostics for zero copies. Record Supervisor-managed copies separately under SEC-04/SEC-37. |
| SEC-02 | REQUIRED: the integration possesses only a limited Collector API credential and non-secret configuration/data. | E4 separates collection from presentation. | Theft of integration credentials escalating to CEZ account access. | Exercise every API route with the HA credential; no administration, secrets or browser operations are reachable. |
| SEC-03 | REQUIRED: incomplete/failed data, freshness and verified runtime security are explicit; uncertain security blocks collection. | E1/E2 show misleading success and sandbox claims. | Silent integrity failure and false security assurance. | Fault injection demonstrates no valid-zero substitution, no false successful collection and no browser launch after failed security checks. |

## 4. Trust model

The **approved trusted computing base** includes the host OS/kernel, Home Assistant OS, Supervisor, administrator/owner, and approved Collector image/update mechanism. The owner input endpoint is trusted for credential entry. CEZ page content, downloaded data, LAN peers, other Apps and the Core data client remain untrusted inputs. The Collector processes secrets; its complete compromise exposes them despite containment.

The primary objective is that CEZ credentials do not exist in Core, ConfigEntry, the custom integration, Core logs or Core diagnostics. The project does **not** claim protection against full compromise of the HA host, Supervisor, root administrator or a malicious approved Collector image. Management authority reaching that trusted layer is outside the promised credential-isolation guarantee. This does not grant the HA data integration access to App secrets.

| ID | Requirement | Rationale | Threat mitigated | Verification / acceptance |
|---|---|---|---|---|
| SEC-04 | REQUIRED: document Supervisor-managed App configuration and approved image/update administration within the trusted boundary; preserve SEC-01 at the Core integration boundary. Do not claim resistance to compromise of the trusted host/Supervisor/root/image. | E4 identifies management paths; owner O-02 explicitly settles their trust status. | False isolation claims and accidental leakage into Core components. | Review credential/configuration/backup data flow against the approved trust model and test absence from Core surfaces. Inventory management access without treating trusted-layer compromise as a requirement for an external host. |

**O-02 — CLOSED / APPROVED.** An external Collector host is not required merely to protect against full Supervisor/root compromise. Local file encryption does not change this trust decision. Runtime inspection of configuration paths remains a verification obligation, not a reopening of owner approval.

## 5. Threat model

| Asset / adversary | Attack path | Required controls | Residual risk |
|---|---|---|---|
| CEZ password/session; compromised portal or redirect | Exfiltration through forms, JS, navigation and background requests. | SEC-01, SEC-16–SEC-20. | A compromised allowed IdP receives credentials legitimately. |
| Secrets; compromised Chromium | Read files, attack driver/API, escape browser. | SEC-08–SEC-16, SEC-20. | Browser/OS sandbox vulnerabilities. |
| Secrets; malicious dependency or Collector | Read memory/storage, bypass application filters or abuse allowed egress. | SEC-10, SEC-16, SEC-33–SEC-37. | Full secret-process compromise exposes secrets; v1 application filtering is not containment against arbitrary sockets from a compromised process. Independent egress is conditional hardening. |
| API token/measurements; compromised Core | Query data, flood refresh, exploit API or management paths. | SEC-02, SEC-04, SEC-21–SEC-24. | Authorized data disclosure and bounded disruption; compromise of trusted Supervisor/root is outside the isolation claim. |
| API traffic; network attacker | Sniff, spoof DNS, replay stolen credentials. | SEC-16, SEC-22, SEC-23. | Endpoint compromise defeats transport confidentiality. |
| Historical data; malformed/changed exports | Wrong meter, invalid zeros, duplicate/DST corruption. | SEC-25–SEC-30. | Plausible but incorrect source data may pass validation. |
| All assets; malicious App update | Signed but malicious code reads existing storage. | SEC-33–SEC-37. | Trusted publisher compromise remains a risk. |
| Secrets; administrator error | Exposed ports, permissive mounts, uploaded artifacts or restored old backups. | SEC-12–SEC-15, SEC-31, SEC-32, SEC-37–SEC-39. | Deliberate privileged override cannot be prevented by the App alone. |

Trust boundaries are owner endpoint → trusted Supervisor App configuration → Collector; Core integration → data API; controller → browser worker; browser → CEZ; process → storage; build system → deployed image; and storage → backup/restore. App configuration remains inside the approved administrative trust boundary and must not be copied to Core integration surfaces. Each flow must be included in the threat review. Evidence: E1, E4; owner O-02/O-05.

## 6. Target architecture

The deployment consists of Core and the Collector App on the approved HA OS amd64 VM, with required application/browser destination controls. Independently enforced host/network egress is RECOMMENDED hardening, conditionally REQUIRED under section 17. Within the Collector boundary, the controller consumes trusted App configuration, manages a disposable browser worker and publishes a validated measurement store. The data API serves only that store and bounded job requests. It must not relay live browser commands.

| Component | Owns | Does not own |
|---|---|---|
| Collector controller | CEZ credentials from its App configuration, jobs, verified account/meter mapping. | Core ConfigEntry/Recorder administration. |
| Disposable browser worker | Current login session, portal navigation, temporary export files. | Long-lived credential database or Core API token. |
| Parser/store | Validated measurements, coverage, revisions and provenance. | Unrestricted network access or credentials. |
| Collector data API | Scoped authentication, measurement/status reads, bounded refresh requests. | Secret export, DOM, screenshots, raw browser methods. |
| HA integration | Collector credential, sensors, durable import checkpoint and statistics. | CEZ credentials, cookies, Selenium, Chromium. |
| Browser/network destination controls | Approved application/browser destinations and blocked private/unapproved targets; interception coverage is verified in Phase 2A. | Proof of arbitrary-socket containment after full Collector compromise. |
| Independent egress hardening | Additional host/network enforcement if feasible without weakening isolation. | Requirement to add NET_ADMIN, privileged mode or host networking. |

**REQUIRED:** logical responsibilities must remain separated even if some Collector services share a process. Browser process/UID isolation and strict destination validation remain mandatory. Independent egress must not block Phase 2A or become a production coding prerequisite unless the feasible non-privileged mechanism in section 17 is demonstrated. Concrete runtime mechanisms are O-03/O-04.

## 7. Collector App responsibilities

**REQUIRED:** consume CEZ credentials only from the Collector's supported App configuration mechanism; own disposable sessions, sandbox checks, portal collection, download validation, normalization, durable measurement revisions, coverage tracking, scheduling, typed errors and authenticated data API. V1 handles the single approved measurement point. Revalidate meter binding before publishing data for a changed device selection.

**FORBIDDEN:** installing dependencies into Core, changing HA configuration, querying Core with a broadly privileged HA token, or requiring a Supervisor management token for normal collection. The data API serves one immutable snapshot/revision per paginated read.

**RECOMMENDED:** keep tariff classification based on HA history in the integration, so the Collector does not require Core history privileges. Evidence: E2/E4.

## 8. Home Assistant custom integration responsibilities

**REQUIRED:** configure Collector endpoint, trusted TLS identity, scoped API credential and opaque meter ID; validate all API payloads independently; poll status and revisions; expose correctly labelled entities; perform idempotent Recorder imports with a durable checkpoint.

| ID | Requirement | Rationale | Threat mitigated | Verification / acceptance |
|---|---|---|---|---|
| SEC-05 | FORBIDDEN: Selenium, Chromium, WebDriver, CEZ login fields or a CEZ HTTP adapter in Core. No browser fallback if Collector fails. | E1: executor threads are not security boundaries. | Browser/dependency access to Core secrets and reintroduction of CEZ credentials. | Dependency/import/process inventory and config-flow review on installed Core; Collector outage yields unavailable/stale state only. |
| SEC-06 | REQUIRED: treat Collector data as untrusted; bound response size, cardinality, timestamps and numeric values before processing. | A Collector compromise must not become arbitrary Core execution. | Parser exploits, resource exhaustion, malicious statistics. | Contract/fuzz tests with excessive, unknown, contradictory and malformed fields. |

## 9. Credential lifecycle

Credentials enter through the supported Home Assistant App/Add-on configuration mechanism and belong to the Collector's App configuration boundary, including trusted Supervisor-managed persistence. Do not create a second credential source in Core. Validate them only against approved CEZ destinations. Supply them to the browser worker only for the current job, never through command-line arguments or ordinary environment variables. The worker must not read the persistent App credential configuration directly.

Rotation is an owner update of the App configuration followed by safe validation/reload; the Collector never echoes or prefills the old credential through its API, logs or diagnostics. Do not trim or normalize passwords. Stop active jobs when credentials change, invalidate local sessions, and do not silently restore an older password if the replacement fails. Report a bounded configuration/authentication error. CEZ-side revocation remains O-07. Removal clears the active credential configuration and local sessions; deletion cannot promise forensic erasure from Supervisor backups, flash or snapshots. Exact supported option-file permissions, reload behavior and removal behavior are Phase 2A verification obligations under O-05/O-13.

| ID | Requirement | Rationale | Threat mitigated | Verification / acceptance |
|---|---|---|---|---|
| SEC-07 | REQUIRED: minimal secret lifetime and copies; no Collector password echo/prefill, argv/environment transport or Core-side credential management; explicit App-configuration rotation/removal; crash dumps disabled. | E1 records persistent objects and prefilling; O-05 selects App configuration. | Process listing, diagnostic, memory and old-copy exposure. | Synthetic credential lifecycle tests inspect App persistence, reload/removal, process arguments, outputs and failure paths; worker cannot reopen credential configuration. |

## 10. Credential onboarding design

**REQUIRED — owner O-05:** use the supported Home Assistant App/Add-on configuration mechanism for initial CEZ username/password configuration. Supervisor-managed options are permitted for the Collector App and belong to its configuration/security boundary. Use the supported password-sensitive presentation for the password option; actual masking, storage, permission and reload behavior must be verified in Phase 2A. This is App administration, not the custom integration's configuration flow or a Core service.

A separate custom HTTPS credential onboarding service, enrollment token and independent custom administrative UI are **not required for v1**. A separate Collector administrative UI is OPTIONAL future hardening requiring its own reviewed authentication/CSRF design. The existing HA administrative presentation and Supervisor configuration path are trusted under O-02; do not describe them as a newly proven physical process-isolation boundary. Credentials must not be copied to ConfigEntry, custom integration configuration, Core services, Core logs or Core diagnostics. Pairing the limited Collector API credential is a distinct design under O-12; it does not transmit the CEZ password to the integration.

| ID | Requirement | Rationale | Threat mitigated | Verification / acceptance |
|---|---|---|---|---|
| SEC-08 | REQUIRED: CEZ onboarding through the authenticated supported Collector App configuration mechanism only for v1. FORBIDDEN: copies in ConfigEntry, custom integration configuration, Core services, Core diagnostics or Core logs; no credential onboarding through the data API. | O-05 approves supported App configuration within trusted Supervisor while preserving E1's Core separation goal. | Accidental credential propagation, integration/API exposure and unauthorized configuration access. | Trace a synthetic credential from App configuration to Collector and browser; inspect Core surfaces for zero copies and verify App configuration access restrictions. Record supported-framework behavior instead of inventing a custom enrollment service. |

**O-05 — CLOSED / APPROVED design:** supported App/Add-on configuration replaces the custom HTTPS onboarding requirement. **OPEN / NEEDS VERIFICATION:** effective App option storage/access, masking, reload/removal and absence from Core surfaces. Those implementation checks do not reopen the selected mechanism. Backups may contain Supervisor-managed options; O-13 must resolve handling using actual evidence, not assumed exclusions.

## 11. Session and cookie handling

**REQUIRED:** use a fresh private browser profile per job; retain session cookies only in the job's controlled ephemeral space. No cookie export/import, persistent browser profile or cross-account reuse in the first release. Browser cookie scoping must not be manually broadened. Do not log cookies, tokens or authorization redirects. Destroy the worker/profile after completion, cancellation or security failure.

| ID | Requirement | Rationale | Threat mitigated | Verification / acceptance |
|---|---|---|---|---|
| SEC-09 | REQUIRED: job-local sessions; reject auth expiry as a typed failure instead of continuing with an unknown login state. Do not assert server logout from browser exit. | E1/E2 do not establish CEZ expiry/revocation behavior. | Session leakage, mixed-account collection, false revocation assurance. | Two-job isolation test; inspect temporary/persistent stores; simulate expiry and confirm no unverified data publication. |

**OPEN / NEEDS VERIFICATION — O-07:** cookie/token names, attributes, CSRF requirements, expiry, logout, MFA and account-lock behavior. Session persistence may only be considered later through a security-reviewed change.

## 12. Chromium and Selenium isolation

| ID | Requirement | Rationale | Threat mitigated | Verification / acceptance |
|---|---|---|---|---|
| SEC-10 | REQUIRED: browser and driver run in a disposable process group under a dedicated non-root worker identity with no persistent secret-store access; controller is also non-root. | E1/E4 require a real boundary beyond executor threads. | Browser compromise and cross-job leakage. | Inspect effective UID/GID, descriptors, mounts, environment and accessible files; worker cannot read controller secrets or the API credential. |
| SEC-11 | REQUIRED: WebDriver/CDP control is accessible only to the authorized controller; no LAN/Core exposure or HTTP forwarding. Job deadline includes queueing and enforces termination of the whole worker group. | E1 found cleanup and semaphore risks. | Browser remote control and indefinite denial of service. | Attempt connections from Core, another App and LAN; hang/crash tests show bounded termination, cleanup and recovery of the next job. |

The required security boundary includes controller-to-driver authentication/access restriction; merely binding a port to loopback does not establish process identity. **OPEN / NEEDS VERIFICATION — O-04:** select effective worker identity, IPC/control isolation and resource-limit mechanisms supported by the chosen deployment.

## 13. Chromium sandbox requirements

**FORBIDDEN:** `--no-sandbox`, `--disable-setuid-sandbox`, `--disable-seccomp-filter-sandbox`, `--disable-gpu-sandbox`, or equivalent switches/configuration that disable required sandbox layers. This prohibition applies to wrappers, inherited environment, image configuration and effective process arguments. No automatic Firefox or insecure browser fallback.

| ID | Requirement | Rationale | Threat mitigated | Verification / acceptance |
|---|---|---|---|---|
| SEC-12 | REQUIRED: Chromium runs non-root with its required Linux sandbox mechanisms enabled and positively verified. Inability to verify fails closed before credentials are released. | E1 shows that flag absence and a boolean diagnostic are insufficient proof. | Browser escape impact and false sandbox attestation. | Version-specific inspection of actual browser/renderer processes, UID, namespace and seccomp state plus negative tests for each forbidden configuration. Record evidence against the exact image/kernel/AppArmor matrix. |

**OPEN / NEEDS VERIFICATION — O-03:** experimentally demonstrate non-root Chromium and positive verification of the required sandbox layers in the actual HA OS amd64 App environment running on Synology VMM during Phase 2A. This proof is required before Phase 2B/production implementation proceeds, not before the feasibility experiment that establishes it. Container seccomp alone is not proof of Chromium renderer sandboxing. If incompatible, stop the production gate; do not grant broad privileges or disable protection to proceed. All four forbidden flags remain prohibited in experiments as well as production.

## 14. Container privilege requirements

| ID | Requirement | Rationale | Threat mitigated | Verification / acceptance |
|---|---|---|---|---|
| SEC-13 | FORBIDDEN: privileged/full-access mode, host networking, host PID/IPC namespaces, Docker socket, broad host devices, SYS_ADMIN/NET_ADMIN escalation, or disabling App protection/AppArmor to make Chromium work. REQUIRED: minimum capabilities and non-root long-running services. | E4 identifies privilege conflicts. | Container escape and host takeover. | Inspect effective deployed container settings, not only source metadata; negative deployment tests reject forbidden settings. |

**REQUIRED:** no unnecessary Supervisor, Home Assistant, auth, Docker, audio/video or hardware API access. Trusted Supervisor management of App options is permitted under O-05 and does not require broad Collector API privileges. Default runtime API access and any startup helper privileges must be inventoried during Phase 2A under O-04. A privileged startup workaround is not permitted by this specification.

## 15. Filesystem and persistent storage model

**REQUIRED:** Collector-managed persistent application data lives only under its own `/data`. CEZ credential options additionally have trusted Supervisor-managed configuration persistence under O-05; this is permitted App configuration, not Core ConfigEntry and not a reason to mount Supervisor or host storage. Verify the effective options location/ownership rather than inventing it. Logical Collector data categories are API authentication verifier/TLS material, normalized measurements, meter mappings, revisions/checkpoints and job configuration. Avoid redundant CEZ secret copies. Paths below `/data` are implementation choices; the categories are not API-visible paths.

Browser profiles/downloads use isolated per-job ephemeral storage, preferably tmpfs, with cleanup on success, failure, restart and cancellation. Raw downloads are deleted after validated publication or failure. Bounded retention of normalized data is O-14. No `/config`, `/ssl`, host home directory, shared HA data or arbitrary user-selected output mount.

| ID | Requirement | Rationale | Threat mitigated | Verification / acceptance |
|---|---|---|---|---|
| SEC-14 | REQUIRED: private directories (normally 0700) and secret files (normally 0600); a narrowly scoped group may be used only for required controller/worker exchange. FORBIDDEN: world-writable or world-readable sensitive storage, including download/temp directories. | E1 identifies 0777 downloads. | Local tampering and information disclosure. | Inspect effective permissions/ownership; another UID cannot list/read/write job and secret data. |
| SEC-15 | REQUIRED: fixed application-controlled paths, race-resistant file opening, rejection of symlinks/non-regular files and path traversal, bounded downloads, atomic writes and crash-consistent publication. No fallback from rejected paths. | E1 identifies check/use races and parser fallback. | Symlink/traversal attack and partial-state corruption. | Symlink replacement, traversal, concurrent access, interrupted write and disk-full tests show no escape or false publication. |

A read-only root filesystem is RECOMMENDED; writable runtime exceptions must be enumerated and bounded. Encryption with a key accessible to the same compromised process is not a replacement for permissions or isolation (O-13).

## 16. Network architecture

**REQUIRED:** Core initiates authenticated HTTPS data requests to the Collector over an internal network. The data API has no host/LAN published port. The Collector does not push through the broadly privileged Core API. Core must use a configured/approved Collector peer identity, not blindly trust discovered addresses or follow API redirects.

External CEZ traffic is separate from API/control traffic. Browser page requests cannot reach Core, Supervisor, Collector administration/data endpoints, host services, arbitrary LAN destinations or cloud metadata endpoints. Controller-to-driver communication is a distinct tightly constrained local exception, not permission for page content to access loopback.

Internal networking is transport reachability, not authentication. **OPEN / NEEDS VERIFICATION — O-01/O-04/O-12:** actual interfaces, DNS/service identity, port allocation and enforcement topology. Evidence: E4/E9.

## 17. Outbound egress policy

| ID | Requirement | Rationale | Threat mitigated | Verification / acceptance |
|---|---|---|---|---|
| SEC-16 | REQUIRED for v1: strict application/browser destination control using exact approved hostnames, HTTPS, explicit ports, navigation/redirect checks and reliable request filtering. Block loopback, RFC1918/private LAN, IPv6 private/local, link-local/metadata and direct unapproved IP destinations. No caller-controlled URLs, runtime telemetry or dependency downloads. Independent host/network enforcement is RECOMMENDED, conditionally REQUIRED only after the non-privileged feasibility condition below is demonstrated. | E1/E4 identify missing request coverage; owner O-04 narrows the mandatory v1 enforcement boundary without allowing arbitrary application browsing. | Browser-driven SSRF, accidental outbound disclosure and unapproved destinations; not arbitrary sockets after full Collector compromise. | Phase 2A tests actual browser/navigation/request paths against denied hosts, addresses, ports, redirect and DNS-rebinding cases; record interception coverage and limitations. If independent hardening is feasible, separately test direct-socket bypass denial from worker/controller identities. |

The v1 policy must account for DNS resolution/rebinding, IPv4/IPv6, redirects and browser background requests. An allowed hostname resolving to a denied address must not bypass private-address protection. Document necessary infrastructure such as resolution separately; do not classify it as a credential destination. Runtime telemetry, dependency installation and browser/driver downloads are FORBIDDEN. Controlled preparation/build of disposable Phase 2A test artifacts may acquire versioned packages; the running browser must not self-download binaries. DNS resolver confinement and protections against arbitrary socket traffic from a fully compromised process belong to independent hardening and must not be claimed when absent.

A browser interceptor is not equivalent to an independently enforced firewall. **RECOMMENDED:** evaluate independent host/network egress hardening. It becomes **REQUIRED only if Phase 2A demonstrates a practical HA OS mechanism without privileged mode, NET_ADMIN, host-network access or weakened container isolation**, and records the feasible configuration for review. Do not make that proof a prerequisite for Phase 2A experimentation or an unconditional prerequisite for Phase 2B coding. Do not silently request additional privileges. If no such mechanism exists, document that result and the residual risk; v1 may proceed only with the mandatory destination controls verified and reviewed.

**OPEN / NEEDS VERIFICATION — O-04/O-08:** technical reliability and coverage of browser filtering, address checks and the optional independent mechanism. Unknown request classes must be disabled or blocked where possible. Any unsupported path that defeats mandatory v1 destination blocking is a reviewed feasibility blocker, not permission to claim full enforcement. Failure of a required installed control fails closed. The absence of optional independent hardening alone is not such a failure.

## 18. Allowed CEZ hosts and origins

There is **no approved production allowlist yet**. The following is an evidence inventory only; every row remains **OPEN / NEEDS VERIFICATION — O-06/O-08** for runtime use.

| Host / origin | Phase 1 evidence | Reference role | Production credential permission |
|---|---|---|---|
| `https://pnd.cezdistribuce.cz` | E7; source constant and configuration URL. | Dashboard/application; entry path `/cezpnd2/external/dashboard/view`. | Not authorized by this specification pending live verification; reference excludes it from credential-entry hosts. |
| `https://mepas.cez.cz` | E7; source allowlist. | Candidate identity provider; reference prefixes `/cas`, `/idp`, `/login`. | Not authorized pending verification of exact form and destination. |
| `https://dip.cezdistribuce.cz` | E7; source allowlist. | Candidate identity provider; reference prefixes `/login`, `/cezpnd2`, `/idp`. | Not authorized pending verification of exact form and destination. |

| ID | Requirement | Rationale | Threat mitigated | Verification / acceptance |
|---|---|---|---|---|
| SEC-17 | REQUIRED: reviewed, versioned exact-host HTTPS allowlist with explicit standard port 443, phase/path/method constraints and separate credential versus resource permissions. FORBIDDEN: suffix/substring/wildcard approval of CEZ-like names. | E1/E4 distinguish exact host validation from trust in all content. | Hostname confusion, phishing and overbroad secret submission. | URL parser tests including userinfo, suffix tricks, encoding, trailing-dot/IDN ambiguity, unusual ports and path boundaries; live evidence attached to each allowed transition. |

Do not infer endpoint existence from a path prefix. The initial dashboard URL is a source-confirmed candidate, not proof of the current login contract.

## 19. Redirect validation policy

| ID | Requirement | Rationale | Threat mitigated | Verification / acceptance |
|---|---|---|---|---|
| SEC-18 | REQUIRED: validate every HTTP redirect and script/navigation transition before following it; reject unknown scheme/host/port/path/state or excessive loops. Revalidate before every credential submission. | E1 finds post-navigation checks too late. | Open-redirect exploitation, SSRF and credentials reaching unexpected origins. | Controlled redirect chains cover cross-origin, downgrade, script navigation, form redirect and loops; denied destinations receive no request or credential. |

Reject ambiguous URL parsing, embedded userinfo and unsupported encodings rather than trying multiple interpretations. Query values containing tokens must remain in memory only; validation/logging must not disclose them. Redirect limits and the permitted CEZ state machine remain O-06/O-14.

## 20. Browser request restrictions

| ID | Requirement | Rationale | Threat mitigated | Verification / acceptance |
|---|---|---|---|---|
| SEC-19 | REQUIRED: identify the verified login document, frame, form and submit destination; validate the resolved action and any JS-driven submission before credentials leave. A generic text/password field match is insufficient. | E1 shows broad selectors and missing form-target proof. | Credential injection into unrelated forms and JS exfiltration. | Malicious forms, frames, DOM replacement and action changes cause abort; network capture shows no secret at denied destinations. |
| SEC-20 | REQUIRED: determine and restrict navigation, subframes, fetch/XHR, scripts, images, beacon, websocket, workers/service workers and downloads using interception/filtering where technically reliable; disable or block unsupported classes, and document coverage gaps for review. Do not silently treat an unfiltered class as validated. | E4: top-level origin checks miss background traffic; O-04 requires verified v1 coverage rather than an assumed host firewall. | Exfiltration and browser-mediated SSRF. | Phase 2A negative request-class matrix, including startup/background behavior, proves mandatory destination blocks on enabled paths. Test independent interceptor-bypass containment only when the hardening condition in SEC-16 applies. |

Same-origin malicious CEZ JS is a residual risk. The approved state machine may require verified JS submission rather than a static form action; its actual mechanism is O-06. Local control endpoints remain inaccessible to page-initiated requests even while the controller can use them.

## 21. Local Collector API design

**REQUIRED:** a versioned JSON data contract under `/api/v1`, separate from administration. Responses are bounded, use opaque IDs, carry API schema version and immutable dataset revision where relevant, and never embed raw CEZ responses. No server-side fetching of client-supplied URLs. No caller-controlled file paths, selectors, scripts or browser commands.

| ID | Requirement | Rationale | Threat mitigated | Verification / acceptance |
|---|---|---|---|---|
| SEC-21 | FORBIDDEN: exposing CEZ username/password, cookies, tokens, DOM, screenshots, raw exports, arbitrary browser functions or secret-changing administration via the data API. REQUIRED: explicit response-field allowlists. | SEC-02 and E4 require a limited Core capability. | Compromised Core extracting CEZ credentials or controlling browser. | Route/schema inventory plus synthetic-secret and unknown-field tests; every endpoint is exercised with each credential scope. |

## 22. Collector API authentication

**REQUIRED:** Collector-generated cryptographically random bearer credential with at least 256 bits of entropy; never derived from CEZ credentials or EAN. Bind it to an explicit meter scope and read/refresh operations. No administration capability. Store only a secure verifier server-side where possible; Core stores the token as a redacted sensitive integration field. Initial pairing uses the trusted administration channel, not unauthenticated discovery.

Token generation, rotation, revocation and constant-time verification are mandatory. Rotation may allow an explicitly bounded overlap, never indefinite acceptance of old tokens. Expired/revoked credentials are refused. An optional future read-only token must not implicitly acquire refresh permission.

| ID | Requirement | Rationale | Threat mitigated | Verification / acceptance |
|---|---|---|---|---|
| SEC-22 | REQUIRED: per-client scoped authentication on every data route; FORBIDDEN: tokens in URL, logs, diagnostics, browser query history or cleartext transport. | E4 identifies token compromise as a limited but meaningful capability. | Unauthorized data access, replay after revocation and account enumeration. | Missing/wrong/revoked/wrong-meter token tests; rotation/restart persistence tests; outputs contain no token marker. |

## 23. API transport security

**REQUIRED:** HTTPS with verified server identity for Core → Collector. No plaintext fallback, disabled certificate checking or automatic trust-on-first-use from discovery. Provision a dedicated pinned identity/private CA through authenticated pairing; Collector owns its TLS keys in private storage, without mounting host `/ssl`. Certificate renewal and recovery must not silently replace trust.

| ID | Requirement | Rationale | Threat mitigated | Verification / acceptance |
|---|---|---|---|---|
| SEC-23 | REQUIRED: protect API confidentiality/integrity and verify the peer even on the internal network; FORBIDDEN: following API redirects with credentials. | E4 distinguishes internal networking from encrypted transport. | LAN/App interception, DNS spoofing and token forwarding. | Wrong/expired/untrusted certificate and redirected endpoint tests fail; authorized rotation succeeds only via approved trust update. |

mTLS is OPTIONAL future hardening; bearer token plus verified TLS is the selected baseline, subject to owner review O-12. Ingress and Supervisor proxy are not substitutes for this Core-to-Collector contract. API token replay remains possible after endpoint theft until revocation; refresh deduplication and rate limits bound its effect.

## 24. API endpoint specification

These are **new local API definitions**, not CEZ endpoints. REQUIRED routes are authenticated with SEC-22. Process-local liveness for a container watchdog may use a separate non-network check; it is not an unauthenticated exception to the data API.

| Method / path | Classification | Inputs | Successful response / semantics |
|---|---|---|---|
| `GET /api/v1/health` | REQUIRED | No parameters. | 200 for live API process, 503 when unable to serve safely; minimal schema version and liveness only. Does not mean CEZ is reachable or data is fresh. |
| `GET /api/v1/status` | REQUIRED | Authorized opaque `meter_id`. | 200 with collection state, last_attempt, last_success, data_timestamp, completeness, revision and bounded last error; never credentials or raw portal text. |
| `GET /api/v1/measurements` | REQUIRED | `meter_id`, UTC `start` inclusive, `end` exclusive; bounded `limit`; opaque `cursor` for continuation. | 200 with records, coverage, revision and optional next_cursor. Empty data is explicit missing coverage, not zero consumption. Pagination stays on one snapshot. |
| `POST /api/v1/refresh` | REQUIRED | JSON body with `meter_id`; optional both `start` and `end`; no range means previous complete local calendar day. | 202 with opaque job_id and queued/running state. Equivalent in-flight work is coalesced. Status reports the latest job_id/outcome; older acceptance does not promise retained job history. |
| `GET /api/v1/consumption/latest` | OPTIONAL, excluded from first release | No implemented contract in v1. | Clients derive latest valid interval from measurements; unavailable route returns 404. |

Status timestamps are nullable until an event exists; timestamps use RFC 3339 UTC. Error bodies contain stable local code, request correlation ID and retryable flag, never underlying exceptions. 400 covers malformed/unknown input; 401 missing/invalid credentials; 403 missing operation permission; 404 unknown or unauthorized meter without existence disclosure; 405 unsupported method; 409 incompatible revision/state; 413 oversized input; 429 rate/queue limit; 503 unavailable service. Responses containing measurements or operational details use no-store cache policy.

Initial project limits, not CEZ limits: 16 KiB request body; 1,000 records/page; 1 MiB response ceiling; date ranges at most 60 local calendar days using exclusive end; one executing collection job; bounded queue and explicit 429 when full. Exact queue/rate/time budgets require O-14 before implementing the relevant production mechanism, not before Phase 2A measurements; pagination must satisfy both record and byte limits. V1 accepts only its single configured meter; meter scoping is not multi-meter support.

| ID | Requirement | Rationale | Threat mitigated | Verification / acceptance |
|---|---|---|---|---|
| SEC-24 | REQUIRED: reject unknown fields, excessive ranges/sizes, invalid dates, unauthorized meters and non-JSON refresh requests; authenticate before revealing meter state; disable permissive CORS. | E1/E4 identify arbitrary-input and resource risks. | DoS, CSRF, enumeration and API abuse. | Boundary/authorization tests for every route; browser-origin requests cannot initiate refresh without an authorized explicit token. |

## 25. Measurement data model

The local normalized model is REQUIRED; it is not a claim about the CEZ response format. Schema changes incompatible with this model require an API version change.

| Field / concept | Required semantics |
|---|---|
| `meter_id` | Stable random opaque local identity, not EAN/ELM or an unsalted hash of them. |
| `channel` | `grid_import` or `grid_export`; tariff/register channels are explicitly separate if later supported. |
| `interval_start`, `interval_end` | Unambiguous UTC instants; half-open interval; positive duration. |
| `value_kwh` | Non-negative finite decimal energy, serialized as a canonical decimal string; null unless quality permits a measured value. |
| `quality` | `valid`, `missing`, `invalid`, `not_applicable` or `unverified`; source semantics documented separately. |
| `source_timezone` | Verified source timezone; retain source offset/fold provenance where needed. |
| `source_profile` | Reviewed semantic profile identifier, not raw headers or arbitrary text. |
| `collected_at` | UTC time the validated observation was acquired, not measurement time. |
| `revision` | Immutable dataset version identifying corrections; stable across pagination. |
| Identity key | meter_id + channel + interval_start + interval_end; conflicting duplicates require explicit correction provenance. |
| Coverage | Requested interval, expected/valid/missing/invalid counts, gaps and completeness per channel. |

**REQUIRED:** use exact decimal arithmetic or a documented fixed-point representation until conversion required by HA; define precision and rounding once under O-10. Preserve import/export independently; do not net them. Source bytes are transient; normalized provenance must not retain secrets.

## 26. EAN and ELM handling

| ID | Requirement | Rationale | Threat mitigated | Verification / acceptance |
|---|---|---|---|---|
| SEC-25 | REQUIRED: keep EAN/ELM mapping in Collector private storage; verify relationship and selected meter before publication. Use opaque IDs in new API/entity/statistic identities. Never select the first available meter silently. | E2 finds no proven EAN/ELM binding in the reference. | Cross-meter data attribution and identifier leakage. | Wrong-pair, duplicate-name and changed-meter tests fail closed; API/log inspection has no full identifiers for new installations. |

**OPEN / NEEDS VERIFICATION — O-09:** exact identifier formats, relationship, replacement of ELM while EAN stays stable, and proof available from portal/export. Phase 1 regexes are not authoritative validation rules. Meter replacement preserves identity only after explicit verified mapping. Legacy EAN-based HA identities are a narrowly scoped migration decision (O-15), never a reason to log full identifiers.

## 27. CSV validation rules

**REQUIRED:** ingest only job-attributed regular completed files; validate size during download as well as before parsing. Start with a 5 MiB file ceiling, 10,000 rows, 50 columns and 128 characters per cell as conservative project limits, subject to fixture-based review O-10. Reject overflow explicitly; no truncation into a successful dataset.

Determine supported encoding and delimiter before emitting records; do not restart decoding after partly publishing rows. Verify known headers, date/status/value columns, profile, units, meter attribution, interval duration and requested range. Do not accept arbitrary unrecognized status as valid. Identical duplicate records may be deduplicated; conflicting duplicates reject the affected dataset revision unless an explicit correction protocol resolves them.

| ID | Requirement | Rationale | Threat mitigated | Verification / acceptance |
|---|---|---|---|---|
| SEC-26 | REQUIRED: bounded, schema-driven, atomic CSV validation; no evaluation of formula-like cells, scripts or content; no partial valid publication on parse failure. | E2/E8 document malformed export and profile fallback hazards. | Resource exhaustion, injection and silent data corruption. | Fixtures/fuzzing cover HTML disguised as CSV, encodings, oversized cells, bad profiles/units/statuses, non-finite numbers and conflicts. |

`kW` may be converted to kWh only if the source is verified interval-average power, using actual interval duration. Cumulative `+E/-E` registers must not be summed as daily energy. **OPEN / NEEDS VERIFICATION — O-10:** accepted CSV schemas, profile semantics, precision and range bounds; reference names `01`, `02`, `07`, `08`, `17` are evidence candidates only.

## 28. Missing and incomplete data semantics

| Input condition | Required output |
|---|---|
| Explicit valid measured zero | `quality=valid`, zero value. |
| Missing interval/file or unavailable export | `missing` coverage and null value; never valid zero. |
| Malformed/unrecognized profile | `invalid` or `unverified`; collection failure for that stream, no zero substitute. |
| Verified meter has no export channel | `not_applicable`; do not fabricate a zero time series. |
| One channel valid, another failed | Publish independently validated channel with explicit per-channel failure/completeness; never report whole request complete. |
| Failed refresh after earlier valid data | Preserve prior committed data with its original timestamps; record failure separately. |

| ID | Requirement | Rationale | Threat mitigated | Verification / acceptance |
|---|---|---|---|---|
| SEC-27 | FORBIDDEN: missing/failed data silently becoming valid zero, or stale data receiving a fresh measurement timestamp. REQUIRED: per-channel coverage and separate freshness fields. | E2 identifies zero substitution and last_sync ambiguity. | False consumption/statistics and misleading operational state. | Fault injection for every table row; no zero can be published without a valid measured source. |

`last_attempt` records job start, even if it fails. `last_success` records the most recent completed, validated publication for the requested scope/channels; a partial job does not advance global last_success. Per-channel last_success may advance independently. `data_timestamp` is the latest valid interval end, not request time. `completeness` describes explicit requested coverage, not age. HA additionally tracks `last_import_success` after Recorder work, distinct from Collector success.

## 29. Timezone and DST requirements

| ID | Requirement | Rationale | Threat mitigated | Verification / acceptance |
|---|---|---|---|---|
| SEC-28 | REQUIRED: normalize to timezone-aware UTC without guessing the repeated/nonexistent local hour; reject unresolved ambiguity. | E2 identifies naive datetime/deduplication risks. | Loss or duplication of energy during DST and host-timezone changes. | Fixtures for both DST transitions, midnight/24:00, timezone changes and duplicate local timestamps preserve exact interval identity and sums. |

**OPEN / NEEDS VERIFICATION — O-10:** actual CEZ timezone, interval start/end meaning, offset/fold representation and DST exports. Europe/Prague is the proposed business calendar, not a source-confirmed CSV encoding. Do not use OS-local timezone as an implicit parser setting. Once 15-minute cadence is verified, expected local-day counts derive from timezone transitions, not a constant 96. Time synchronization failure must be detectable, and implausibly future measurements quarantined rather than silently accepted.

## 30. Home Assistant sensors

| Entity concept | Classification | Semantics / unit |
|---|---|---|
| Previous calendar day import/export | REQUIRED for applicable channels | Complete previous business-calendar day only, kWh, energy device class, no total/total_increasing state class. Incomplete day is unavailable with coverage metadata. |
| Latest valid interval import/export | REQUIRED for applicable channels | Exactly one latest valid interval, kWh, energy device class, no total/total_increasing state class; start/end and age shown. |
| Collection running | REQUIRED | Running flag independent of CEZ success and data age. |
| Collection problem / data stale | REQUIRED | Separate error and stale status; never inferred merely from a recent attempt. |
| Last attempt / last success / data timestamp | REQUIRED | Distinct timestamp entities or documented attributes. |
| Data completeness | REQUIRED | Per-channel requested coverage, gaps and revision. |
| Sync duration / Collector version | RECOMMENDED | Operational diagnostics without source DOM text. |
| Self-consumption or production coverage ratio | FORBIDDEN without additional verified measurements | Grid export/import is not equivalent to generation or self-consumption. |

**REQUIRED:** backfill does not redefine a previous-day sensor as the entire backfill sum. Retained stale values keep their actual time and stale flag; once the approved stale threshold is exceeded, current/previous-day presentation is unavailable. Historical data remain queryable. Thresholds are O-14.

## 31. Home Assistant Recorder statistics

**REQUIRED:** import external energy statistics, with separate grid import/export channels. Aggregate only complete validated coverage of a UTC hour. If cadence is confirmed as 15 minutes, this means four distinct correctly aligned intervals, not merely four records. State represents hourly energy and sum cumulative energy. Do not duplicate these with total-class state sensors.

| ID | Requirement | Rationale | Threat mitigated | Verification / acceptance |
|---|---|---|---|---|
| SEC-29 | REQUIRED: idempotent revision-aware imports, deterministic baseline and correction propagation; checkpoint only after validated Recorder completion/reconciliation. Never assume enqueuing equals durable success. | E2 identifies partial imports and fallback success. | Duplicated/shifted history and false import success. | Repeated batch, restart mid-import, backfill before/within history and correction tests compare final database results with expected sums. |
| SEC-30 | REQUIRED: skip incomplete hours and preserve known gaps; negative/non-finite energy and decreasing within-series sums are rejected. Tariff unknown must not become verified VT. | E2 identifies gap and tariff errors. | False energy and tariff statistics. | Missing interval, conflicting duplicates, DST and unavailable tariff-history tests; no fabricated zero or tariff certainty. |

Across revisions a corrected total may be lower than the superseded total; this is permitted if the recomputed chronological series is valid and monotonic. Four streams are not assumed to be one HA database transaction: use replay/reconciliation and separate channel checkpoints. Exact supported Recorder API/version matrix is O-01/O-16.

VT/NT statistics are OPTIONAL first-release extension, disabled unless explicitly selected with a verified source or documented estimation policy (O-16). Total import/export is the required baseline. No use of `+E/-E` as interval deltas without verification.

## 32. Scheduling and refresh behavior

**REQUIRED:** Collector owns scheduling; Core polls local status/data without initiating CEZ login every poll. Provide one configurable daily collection time and bounded manual backfill. Proposed default is 06:00 business local time, inherited as a usability choice from Phase 1, not a guarantee of CEZ publication. First startup collects the previous completed local day only after all security checks and onboarding pass.

Coalesce equivalent refreshes, use one active browser worker, cap waiting jobs, include queue time in the user-visible job budget, and terminate stalled workers. Maintain missing-range tracking and bounded catch-up; no unbounded historical startup sweep. Retry transient failures with bounded backoff/jitter. Authentication, CAPTCHA, lock and security failures suppress automatic retries pending a deliberate recovery decision. An absent daily schedule opportunity must not trigger a login storm after restart.

**OPEN / NEEDS VERIFICATION — O-14:** queue length, API rate limits, job deadlines, retry caps, catch-up horizon, stale threshold and source-publication assumptions. Phase 2A uses explicit conservative experimental limits to measure practical behavior; numeric production budgets must be reviewed before implementing the relevant production mechanism. Full production budgets are not a prerequisite for the experiment that determines them. There is no silent fallback to unbounded defaults.

## 33. Error handling

**REQUIRED:** stable local categories distinguish authentication failure, human challenge, account lock, maintenance, network timeout, browser/driver crash, forbidden origin/request, sandbox failure, meter mismatch, schema/parse error, incomplete data, storage failure and Recorder import failure. Categories are local product semantics; matching actual CEZ states is O-07/O-10.

On security failure terminate collection before further secret use; retain prior validated measurements, do not advance last_success, expose a bounded error and require explicit recovery. On CEZ authentication failure do not ask for CEZ credentials in the integration's HA reauth flow; direct the owner to the Collector App configuration mechanism. API credential failure uses the HA pairing flow only.

**REQUIRED:** do not swallow mandatory-stage exceptions; no mocked/test compatibility fallback in production that reports success without work. Worker cleanup failure is observable and blocks unsafe reuse. SEC-03, SEC-11 and SEC-27 govern acceptance.

## 34. Logging and redaction

| ID | Requirement | Rationale | Threat mitigated | Verification / acceptance |
|---|---|---|---|---|
| SEC-31 | FORBIDDEN: credentials, session cookies, tokens, raw headers/query/body, DOM, raw CSV and sensitive exception chains in logs at any level. REQUIRED: opaque correlation IDs and redacted EAN/ELM, including library logs. | E1/E2 find log bypasses through statistics IDs and exceptions. | Support/log aggregation leakage and log injection. | Synthetic secrets and identifiers through success, failure, parser, TLS and dependency paths produce zero unredacted occurrences in all captured logs. |

Prefer eliminating EAN/ELM from logs over partial masking. Legacy statistic identifiers containing EAN must be mapped to safe logging IDs. Validate bounded structured fields, strip control characters and prevent multiline injection. Do not claim regex replacement of a known password covers all secret-bearing content. Unknown raw input is excluded rather than logged and then heuristically sanitized.

## 35. Diagnostics requirements

| ID | Requirement | Rationale | Threat mitigated | Verification / acceptance |
|---|---|---|---|---|
| SEC-32 | REQUIRED: allowlisted structured diagnostics only, containing versions/digests, actual security-check result, bounded errors, timing/coverage counts and configuration booleans. FORBIDDEN: passwords, tokens, cookies, DOM, screenshots, raw exports and full meter IDs. | E1 shows sanitization and attestation overclaims. | Diagnostic leakage and misleading security reports. | Schema audit and synthetic-secret export tests; missing security evidence is reported unverified, never passed. |

Production raw-artifact capture is excluded even with a debug flag. Any later live-verification material must be collected through a separately approved procedure, kept outside the repository and minimized/redacted before review. Detailed household measurements are omitted from default support exports. File paths and untrusted portal version strings are not automatically safe diagnostics.

## 36. Dependency management

| ID | Requirement | Rationale | Threat mitigated | Verification / acceptance |
|---|---|---|---|---|
| SEC-33 | REQUIRED: lock exact direct/transitive Python and OS dependencies with verifiable artifacts; package Chromium/ChromeDriver in the image with explicit paths and compatibility. FORBIDDEN: runtime Selenium Manager/browser/driver downloads or runtime package installs. | E3 identifies floating ranges and hidden downloads. | Supply-chain substitution and non-repeatable runtime. | Fresh offline-start test; deny vendor/package egress and verify no download attempt; compare installed inventory to lock. |

BeautifulSoup is included only if the verified DOM workflow needs it. No Firefox fallback in v1. HA integration requirements remain minimal and exclude the browser stack. Minimum HA/Python versions must be consistent across package metadata, documentation and tests (O-01). Unknown packages must not be silently accepted through broad version constraints.

## 37. SBOM requirements

| ID | Requirement | Rationale | Threat mitigated | Verification / acceptance |
|---|---|---|---|---|
| SEC-34 | REQUIRED: generate SBOM from each actual built artifact, covering OS, Python transitive dependencies, browser, driver and bundled executables, with versions, origin, licenses and real hashes where applicable. | E3 finds incomplete and inconsistent reference SBOM metadata. | Hidden components, mistaken provenance and false vulnerability claims. | Validate schema, reconcile SBOM against installed inventory and check project identity/license; unmatched executable/dependency blocks release. |

Do not copy reference SBOM values, hashes, claimed advisory minima or license identity. SBOM is inventory, not proof of vulnerability freedom or runtime sandbox enforcement. Record artifact digest and associated scan date/results separately.

## 38. Build reproducibility

| ID | Requirement | Rationale | Threat mitigated | Verification / acceptance |
|---|---|---|---|---|
| SEC-35 | REQUIRED: pin source commit, base image digest, dependency artifacts, architecture and toolchain; build in isolated controlled environments without CEZ secrets. | E3 calls for reproducible builds rather than a version list. | Build substitution, drift and secret contamination. | Two clean builds produce matching runtime filesystem content and inventory; any container-envelope metadata differences are explained and cannot conceal changed executables. |

**REQUIRED:** produce provenance linking source, inputs, SBOM, test results and image digest. No `latest` base/tag resolution as a release input. Hermetic/offline dependency installation from verified artifacts is RECOMMENDED. Registry, signing identity, CI trust and chosen reproducibility tooling are O-17.

## 39. Update and security policy

| ID | Requirement | Rationale | Threat mitigated | Verification / acceptance |
|---|---|---|---|---|
| SEC-36 | REQUIRED: verified signed release provenance, vulnerability review of the exact stack, supported-version policy and explicit security regression tests before updates. Runtime must not self-update its browser/dependencies. | E3/E4 identify malicious/future dependency and App update risk. | Supply-chain compromise and silent security weakening. | Tampered/unsigned release rejected by the approved deployment path; sandbox/egress/schema tests rerun on every relevant upgrade. |

**REQUIRED:** no unresolved exploitable critical/high security finding in the shipped configuration. False positives require documented applicability review; mandatory security invariants cannot be waived as ordinary compatibility fixes. Changed origins, mounts, privileges or secret handling require explicit specification review, not automatic expansion.

**OPEN / NEEDS VERIFICATION — O-17:** image-signature verification support, authorized publisher, maintenance owner, advisory monitoring cadence, response targets and unsupported-version behavior. A signed malicious update remains a trusted-signer compromise, not a solved threat.

## 40. Backup and secret handling

The proposed conservative baseline for Collector-managed backup payloads remains exclusion of CEZ secrets, cookies/browser profiles, API tokens/verifiers and TLS private keys. Normalized measurements, opaque identities and non-secret configuration may be retained for continuity. Sensitive EAN/ELM mappings are excluded by default and must be reverified on recovery. **Supervisor-managed App options may also be included by the platform's backup mechanism; their exclusion has not been demonstrated and must not be claimed.** Owner O-05 approves that configuration mechanism, not an assumption that its backups are secret-free.

| ID | Requirement | Rationale | Threat mitigated | Verification / acceptance |
|---|---|---|---|---|
| SEC-37 | REQUIRED: inventory Collector payloads and Supervisor-managed option backups; exclude secrets where supported, otherwise classify the archive as secret-bearing and require an owner-approved encrypted/restricted-access recovery policy before release. No secrets in Core integration backups. FORBIDDEN: claiming exclusions or historical erasure without proof. | E1/E5 identify old-copy exposure; O-05 selects App options whose backup behavior needs verification. | Backup theft and reintroduction of obsolete credentials. | Inspect a synthetic-credential App/full backup and restore; document every secret-bearing copy, exclusion capability and required protection/re-enrollment/rotation. Confirm Core ConfigEntry remains secret-free. |

**OPEN / NEEDS VERIFICATION — O-13:** actual Supervisor options inclusion/exclusion, encrypted-backup/key access, retention, at-rest protection and owner approval of restore/re-enrollment policy. If options cannot be excluded, resolve the secret-bearing backup policy explicitly rather than rejecting approved O-05 or falsely promising secret-free backups. Recovery keys must not be bundled with archives or stored in the custom integration. A key stored beside encrypted secrets does not protect against compromise of the approved trusted host.

## 41. Migration strategy

**REQUIRED:** inventory old ConfigEntry, entities/devices and statistic IDs; validate EAN/ELM; stage Collector with newly entered credentials through its approved App configuration mechanism; compare data without writing the same Recorder series concurrently. Stop the old scraper before enabling the new writer. Initial migration scope is the single approved CEZ account and measurement point.

Remove CEZ username/password from old Core data/options using a reviewed migration procedure, stop old workers, remove the browser integration dependencies as appropriate, and restart Core to clear old credential objects. Address historical backups separately; rotate the CEZ password after cutover. Never automatically extract an old password from Core and forward it as the onboarding method.

| ID | Requirement | Rationale | Threat mitigated | Verification / acceptance |
|---|---|---|---|---|
| SEC-38 | REQUIRED: migration preserves intended statistics while removing active Core CEZ credentials; exactly one writer owns each statistic series. | E5 identifies credential remnants and continuity conflict. | Duplicate energy, identity reassignment and persistent secret exposure. | Dry-run identity mapping, controlled cutover, Core synthetic-secret scan and historical sum comparison; failed migration cannot re-enable the old scraper silently. |

**OPEN / NEEDS VERIFICATION — O-15:** approve preserving legacy `cez_pnd:<ean>_*` IDs (sensitive identifier remains in Core) versus migrating to opaque IDs. New installations use opaque IDs. Reusing integration domain/entity IDs requires a supported HA migration path, not direct unreviewed database edits. Old backups remain a documented owner action.

## 42. Rollback strategy

| ID | Requirement | Rationale | Threat mitigated | Verification / acceptance |
|---|---|---|---|---|
| SEC-39 | REQUIRED: rollback only to a compatible previously verified version of the separated architecture, or stop collection while preserving validated data. FORBIDDEN: restoring CEZ credentials/browser execution to Core as automatic rollback. | E5: legacy rollback violates the target boundary. | Security regression and secret resurrection. | Restore/replay tests across supported schema versions; incompatible or revoked-vulnerable versions are refused, previous data remain recoverable. |

Storage/API compatibility, minimum allowed secure release and reversible schema migration must be documented before release. Recovering an old complete HA backup must include credential-removal/rotation steps before normal operation. Owner approves legacy identity treatment under O-15; emergency security stop does not need permission to silently weaken invariants.

## 43. Testing strategy

**REQUIRED:** tests exercise behavior and boundaries, not just mirror helper implementations. Real credentials never enter source fixtures, CI variables, recorded HTTP fixtures or public bug reports. Phase 2A may contain disposable proof-of-concept code only after explicit authorization; it is not production implementation or an automatically reusable production foundation. Use synthetic data and controlled local hostile-server fixtures before separately authorized live observation. Sandbox and privilege prohibitions apply to experiments too.

| Test layer | Required coverage |
|---|---|
| Static/dependency | No browser stack or CEZ secret fields in Core; exact locks; routes and privileges audited. |
| Parser/property/fuzz | Malformed exports, encoding, limits, profiles, decimal precision, duplicate/conflicting records, missing values, units. |
| Time/statistics | Both DST transitions, 24:00, source/host timezone differences, corrections, backfill, replays and interrupted imports. |
| Authentication/transport | App configuration access and no Core credential copies; limited API pairing, wrong scope/meter, token revocation, TLS mismatch, API redirect and CSRF as applicable. |
| Browser/network adversarial | Malicious redirects/form actions, background requests, SSRF, direct-IP/IPv6/proxy bypass, unexpected IdP state. |
| Runtime containment | Effective UID, sandbox layers, mount/permissions, driver exposure, forbidden flags and dependency download attempts. |
| Fault/recovery | Browser/driver hangs, queue saturation, disk full, partial writes, restart, cancellation, expired session and Collector outage. |
| Secret hygiene | Marked secrets/identifiers through all logs, diagnostics, API errors, backups and Core persistence. |
| Migration/rollback | Identity continuity, single writer, sum conservation, removal of credentials and recovery without insecure fallback. |

Coverage evidence must map back to SEC IDs. Runtime feasibility evidence must come from the actual HA OS amd64 Supervisor/App VM on Synology VMM, not a developer laptop. Final product acceptance still requires the full test matrix in Phase 5. Phase 2A must never commit real credentials, cookies, tokens, authenticated DOM dumps, screenshots containing account information or raw personally identifying meter data; only minimized/redacted fixtures and findings may enter review artifacts.

## 44. Security acceptance criteria

**REQUIRED:** all SEC-01 through SEC-39 controls pass their specified acceptance methods. Release evidence includes a boundary diagram, deployed privilege/mount/process inventory, sandbox proof, egress denial tests, secret-path audit, API authorization/TLS tests and artifact/SBOM provenance. No unsupported environment is labelled secure.

Specific non-negotiable outcomes: no CEZ secrets in Core; App options confined to the approved configuration boundary; no Chromium/Selenium in Core; only limited data credentials in the custom integration; no exposed browser interface; all four forbidden sandbox flags absent with positive sandbox verification; no privileged/host-network container; no forbidden mounts; no world-writable downloads; verified mandatory v1 destination controls; no valid-zero substitution; and separate attempt/success/data/completeness fields. Independent egress proof is required only if the feasibility condition of SEC-16 is met; otherwise its absence and residual risk are documented, not hidden.

Acceptance is not satisfied by a security boolean, README claim, static SBOM or absence of a known flag. Security-control failure stops collection and secret release, preserving a minimal bounded status path where safe.

## 45. Runtime acceptance criteria

**REQUIRED:** on the approved matrix, a clean offline-start (except permitted CEZ/network infrastructure) works with bundled binaries; non-root browser starts with verified sandbox; a complete verified fixture imports correct energy; an actual authorized CEZ run validates the selected meter/profile; the next run after an injected crash succeeds without leaked processes or secrets.

Each of queue time, active job time, memory/process count, temporary/persistent disk, API response size, refresh frequency, catch-up horizon and stale threshold must have a documented numeric budget and an observed pass/fail measurement (O-14). Proving source staleness requires actual data timestamps, not last attempt.

**REQUIRED:** production startup on an incompatible kernel, missing browser, mismatched driver, invalid TLS trust or failed mandatory destination-control/sandbox verification fails safely without downloading binaries or enabling insecure flags. Absence of optional independent egress alone is not a runtime failure. Unsupported Recorder behavior must fail integration setup/import visibly, not return mock-mode success. These are final runtime acceptance conditions, not prerequisites for Phase 2A experiments intended to establish feasibility.

## 46. Items requiring live CEZ portal verification

The in-scope observations below are **OPEN / NEEDS VERIFICATION** and belong to Phase 2A. Source presence in E7/E8 is not live verification. Live work requires explicit authorization, access to the approved App configuration path and a minimized evidence procedure; this revision does not authorize a login. Discovering the actual redirect chain may use controlled owner observation; do not automatically submit credentials to unverified destinations to discover whether they are legitimate.

| Issue | Required evidence |
|---|---|
| O-06 | Initial navigation, each redirect/status, exact login document/form/frame/action, submission method, successful state, path/method/query contracts and stable selectors. |
| O-07 | Session/cookie/CSRF behavior, expiry, logout/revocation, MFA/CAPTCHA, lockout, maintenance and safe retry behavior. |
| O-08 | All necessary resource/API/download hosts and request classes; separate credential destinations from non-secret resources. |
| O-09 | Verified EAN/ELM mapping, selected-meter proof, replacement scenarios and export attribution. |
| O-10 | Real minimized CSV samples, encoding, delimiter, headers, validity meanings, units, interval semantics, timezone/DST, daily versus cumulative registers and missing/non-applicable channels. |
| O-11 | CLOSED FOR V1: direct undocumented API use is excluded; no investigation of `POST /cezpnd2/external/data` is required by Phase 2A or v1. Its existence/usability remain unverified and cannot be assumed. |
| O-14 | Observed publication delays, practical collection duration and permissible load for choosing conservative scheduling budgets. |

No credential values, session tokens or raw authenticated DOM may be committed as verification evidence. Record reviewed contracts and redacted observations instead. Unknown behavior must cause explicit unsupported/failure handling until a contract is approved.

## 47. Blocking unknowns and owner decisions

Owner decisions are recorded below. A CLOSED policy/scope decision is distinct from an OPEN runtime obligation under the same ID. The actual environment and CEZ behavior remain unverified until evidence is collected. Mandatory sandbox, Core separation, privilege and v1 destination-control requirements remain binding. Independent egress follows the conditional requirement in section 17.

| ID | Decision status | Remaining evidence or decision | Required stage / approval |
|---|---|---|---|
| O-01 | CLOSED: approved v1 scope; PARTIAL overall. | OPEN / NEEDS VERIFICATION: exact minimum Core/Supervisor versions and compatible kernel/Python/browser matrix. Approved target is HA OS amd64 App on Synology VMM VM, one account/one point; no aarch64 or multi-meter/account. | Record actual runtime during 2A; review compatibility for 2B and finalize supported minimums before release. Scope approval already given. |
| O-02 | CLOSED / APPROVED. | No open trust-model decision. Host OS/kernel, HA OS, Supervisor, owner and approved image/update mechanism are trusted. No guarantee against their full compromise. | Verify implementation against that boundary; no external-host approval needed solely for root/Supervisor compromise. |
| O-03 | OPEN / NEEDS VERIFICATION; strict policy reaffirmed. | Positive sandbox proof and non-root operation in the actual approved App environment; all four forbidden flags remain forbidden. | Mandatory Phase 2A experiment; review before Phase 2B/production. |
| O-04 | CLOSED: revised policy; OPEN / NEEDS VERIFICATION: mechanisms. | Verify exact-host/HTTPS/port/navigation/redirect/private-address controls and reliable request filtering, worker isolation and cleanup. Evaluate practical non-privileged independent egress as RECOMMENDED hardening; require it only if feasibility is demonstrated. | Phase 2A findings reviewed before relevant 2B foundations; no unconditional host-firewall prerequisite and no isolation weakening. |
| O-05 | CLOSED / APPROVED: App/Add-on configuration. | OPEN / NEEDS VERIFICATION: supported options storage, masking, permissions, reload/removal and absence from Core integration/log/diagnostic surfaces. No custom HTTPS onboarding service needed. | Phase 2A uses/validates approved mechanism; review results before 2B credential foundation. Backup implications also O-13. |
| O-06 | OPEN / NEEDS VERIFICATION. | Actual CEZ login/redirect/form/state/path/method contract and credential destination. | Authorized Phase 2A live observation; review before production login code. |
| O-07 | OPEN / NEEDS VERIFICATION. | Session/cookie/CSRF, challenge/expiry/lock/maintenance behavior and safe recovery. | Phase 2A observation; review supported flow and explicitly exclude unsupported variants before production use. |
| O-08 | OPEN / NEEDS VERIFICATION. | Minimal actual CEZ host/resource allowlist and request-filter coverage. | Phase 2A observation/tests; review before production collection. |
| O-09 | OPEN / NEEDS VERIFICATION. | EAN/ELM/source binding for the single measurement point; identifier semantics. | Phase 2A verification; review before production data publication. |
| O-10 | OPEN / NEEDS VERIFICATION. | Minimized CSV fixtures; channel, units, precision/range, validity, timezone/DST contracts. | Phase 2A findings reviewed before relevant production parser; unresolved DST must remain explicit unsupported/rejection behavior until verified. |
| O-11 | CLOSED FOR V1: excluded. | Existence/usability of `POST /cezpnd2/external/data` remain unknown facts, not a v1 blocker or research requirement. Portal workflow plus CSV only. | Any alternative needs later evidence and explicit specification revision. |
| O-12 | OPEN / NEEDS VERIFICATION. | Limited API token provisioning, TLS pairing/identity lifecycle, rotation and internal binding; mTLS optional. | Decide before implementing relevant Phase 2B API/security foundations; not a prerequisite for browser-only 2A experiments. Owner workflow approval remains needed. |
| O-13 | OPEN / NEEDS VERIFICATION. | Supervisor-managed option backup behavior, exclusions or protected secret-bearing backups, at-rest handling and restore policy. | Inspect relevant effects in 2A; approve before production secret persistence/backup features and prove before release. |
| O-14 | OPEN / NEEDS VERIFICATION. | Numeric runtime/API/retention/retry/staleness budgets and practical portal timing. | Conservative experiment limits before 2A work; measure in 2A, approve production budgets before affected mechanisms. |
| O-15 | OPEN / NEEDS VERIFICATION. | Legacy EAN-based identity retention versus opaque identity migration; supported single-point migration/rollback. | Owner decision before Phase 4 migration-dependent identities; validate migration/rollback in Phase 5. Not a 2A entry blocker. |
| O-16 | OPEN / NEEDS VERIFICATION. | Recorder semantics/checkpoints/reconciliation; optional VT/NT source/estimation decision. | Resolve before relevant Phase 4 integration; acceptance in Phase 5. Not a 2A entry blocker. |
| O-17 | OPEN / NEEDS VERIFICATION. | Build/signing/verification mechanism, publisher, maintenance owner, response/support policy. | Versioned disposable inputs in 2A; production build design for 2B, final reproducibility/SBOM/signature/security proof before Phase 5 release. |
| O-18 | CLOSED / APPROVED: MIT and independent implementation. | No open license choice. Reference code is not copied by default; intentional later reuse requires explicit provenance and MIT attribution review. | Apply MIT to production artifacts when that work is authorized. This document revision does not create code or a LICENSE file. |

**REQUIRED — owner O-18:** target project license is MIT. Implement independently using the reference for behavior/architecture evidence. No default source copying. Intentional future reuse must preserve applicable MIT notices and documented provenance; do not import the reference's conflicting SBOM Apache metadata as the target license.

Fully closed O-items: **O-02, O-11 and O-18**. **O-01, O-04 and O-05 have closed owner decisions but retain open technical verification portions**. O-03 remains open despite the approved strict policy. O-06–O-10 and O-12–O-17 remain open as listed. This distinction prevents treating policy approval as a successful experiment.

The owner has authorized this specification revision only. Do not request reapproval of settled scope/trust/onboarding/license decisions. Review of the revised document, authorization to start Phase 2A, live account access and review of subsequent findings remain separate. No phase starts automatically from writing this file.

## 48. Phase model and entry criteria

| Phase | Scope | Exit / next-stage condition |
|---|---|---|
| Phase 2A — Runtime and CEZ feasibility verification | Disposable tests/proof-of-concept code and authorized observations in the actual HA OS amd64 App environment. Not production implementation. | Reviewed runtime, sandbox, destination-control, credential-flow and CEZ evidence; explicit approval of next scope. |
| Phase 2B — Collector skeleton and security foundations | Production structure, controlled configuration, worker lifecycle/isolation, security checks and limited API foundations. | Relevant 2A findings reviewed; unresolved feature-specific decisions resolved before their implementation; foundation checks pass. |
| Phase 3 — Collector implementation | Verified portal/CSV retrieval, parser, normalized store, scheduling and error handling for one account/point. | Verified contracts and collector behavior; no fabricated API, zero substitution or weakened security. |
| Phase 4 — Home Assistant custom integration | Limited API client, entities, Recorder imports and migration-aware identities; no CEZ credentials/browser stack. | Relevant API/Recorder/identity decisions resolved; integration validation passes. |
| Phase 5 — Testing, security review, migration and release | Full acceptance matrix, reproducible signed artifacts/SBOM, operational recovery and approved migration/release. | Sections 43–45 and all applicable release requirements pass; explicit release/commit/push authorization where required. |

### Phase 2A objectives

All fourteen objectives are REQUIRED within the authorized feasibility scope. An inability to establish one must be recorded as OPEN / NEEDS VERIFICATION, not replaced by an assumption.

1. Verify Chromium and ChromeDriver availability on HA OS amd64 and record exact versions/provenance.
2. Verify non-root Chromium operation in the actual App environment.
3. Positively verify Chromium sandbox without any of the four forbidden flags.
4. Determine required container permissions without privileged mode, NET_ADMIN or weakened isolation.
5. Determine browser filesystem, private temporary-directory and tmpfs requirements.
6. Verify browser cleanup and termination of the full worker process group on completion, failure and timeout.
7. Perform explicitly authorized live CEZ login-flow observation using the approved App configuration boundary.
8. Determine actual redirect chain and credential submission destination.
9. Determine required CEZ hosts/resources and reliable browser request-filter coverage; evaluate independent hardening feasibility separately.
10. Determine session/cookie behavior and supported recovery semantics.
11. Verify EAN/ELM mapping for the single approved measurement point.
12. Obtain minimized/redacted CSV samples suitable for review without personally identifying raw meter data.
13. Determine CSV, timezone and DST semantics; unresolved cases remain explicit blockers for affected production behavior.
14. Measure practical collection duration and portal behavior to propose bounded production operation.

### Phase 2A experiment rules

Disposable test/proof-of-concept code is permitted **only after explicit Phase 2A authorization**, not during this documentation revision. Keep it clearly labelled and separate from production components; do not promote it into production without the Phase 2B review. It may use controlled versioned test preparation artifacts, but never runtime dependency/browser downloads. Experiments do not need the completed production API, final minimum-version support policy, full Recorder/migration design, release SBOM/signatures or all release tests before they begin.

Use synthetic credentials/local fixtures for runtime and hostile-destination tests first. Before actual credential submission, confirm the effective non-root sandbox and an observed/validated credential destination; do not guess a CEZ URL or submit credentials to learn whether an unknown target is valid. Sequentially expand only reviewed resource permissions. Keep credentials in the approved App configuration path, never hardcoded or entered in Core services.

**FORBIDDEN to commit:** real CEZ credentials, cookies, tokens, authenticated DOM dumps, screenshots containing account information, or raw personally identifying meter data. Transient material necessary for authorized observation stays within the controlled experiment/Collector boundary with restricted access and short retention; review artifacts must be minimized/redacted. No commit or push is authorized by Phase 2A permission alone.

### Phase 2B and production entry review

- [ ] Phase 2A findings relevant to the proposed production work are reviewed and accepted by the owner; unresolved items have an explicit effect on scope.
- [ ] Actual HA OS amd64 runtime demonstrates Chromium/ChromeDriver availability, non-root operation, positive sandbox verification, acceptable permissions and private filesystem/tmpfs behavior.
- [ ] Cleanup/termination and mandatory v1 destination controls have evidence-backed mechanisms; material filtering gaps are resolved before affected production work.
- [ ] Independent egress feasibility is recorded. If a practical mechanism meeting section 17 constraints is demonstrated, it is included as REQUIRED; otherwise its absence alone does not block production coding.
- [ ] App configuration credential flow is verified against Core separation; relevant backup/permission effects are documented and decisions affecting production secret handling are resolved.
- [ ] Relevant login/redirect/host/session/meter/CSV/time contracts from Phase 2A are reviewed before corresponding production code; no unknown CEZ behavior becomes a default implementation assumption.
- [ ] O-12/O-13/O-14/O-17 decisions are resolved before affected security foundations; O-15/O-16 are resolved before affected Phase 4 work, rather than blocking unrelated 2A experiments.
- [ ] Owner explicitly authorizes Phase 2B or the next production phase. Experiment completion alone is not authorization.

Current state: owner design decisions are recorded; **Phase 2A NOT STARTED / awaiting review and explicit authorization**. **Phase 2B/production NOT READY** pending relevant 2A findings. Phase 1's historical NOT READY assessment is unchanged. The full production release requirements are not a prerequisite for Phase 2A experimentation.

## Phase 2 Entry Gate

### Phase 2A entry checklist

- [x] Approved target recorded: HA OS Supervisor/App, amd64 VM on Synology VMM, one CEZ account and one measurement point; aarch64 and multi-account/multi-meter excluded.
- [x] Approved trust model recorded: host/HA OS/Supervisor/owner/approved Collector image are trusted; no full-root/Supervisor-compromise guarantee.
- [x] Approved onboarding recorded: supported Collector App configuration; no CEZ copies in Core ConfigEntry, integration configuration, services, logs or diagnostics; no custom HTTPS onboarding prerequisite.
- [x] Strict sandbox/non-root policy and all four forbidden flags recorded; experiment must stop rather than weaken isolation when verification fails.
- [x] Revised v1 destination controls recorded; independent host/network egress is conditional hardening, not an unconditional experiment prerequisite.
- [x] Direct undocumented CEZ API excluded; MIT and independent implementation approved; evidence-preservation and no-secret-commit rules recorded.
- [ ] Owner reviews this revised specification and explicitly authorizes Phase 2A disposable experimentation. No production implementation is included in that authorization.
- [ ] Access to the actual approved HA OS amd64 App test environment is available; record installed versions, bounded experimental resource/time limits and a cleanup/recovery plan.
- [ ] A controlled workspace/storage and evidence-handling procedure is ready: no secrets in source/Core, no secret-bearing commits, minimized/redacted review outputs, restricted transient artifacts.
- [ ] Before the live-observation subset only: owner authorizes use of the CEZ account/point through approved App configuration; synthetic runtime checks establish non-root/sandbox safety and credential destination is observed/validated before automated submission. Offline feasibility tests do not need completed live contracts in advance.
- [ ] Phase 2A deliverables are agreed: results for all fourteen objectives, exact tested runtime, candidate verified CEZ contracts, filtering limitations and independent-hardening feasibility, remaining unknowns and a Phase 2B review recommendation.

Unmet final production/release requirements do not prevent safe, explicitly authorized Phase 2A work. An unmet live-subset condition blocks live access, not unrelated offline runtime tests. No Phase 2A, Phase 2B, commit or push is authorized by this revision request. Stop for owner review.
