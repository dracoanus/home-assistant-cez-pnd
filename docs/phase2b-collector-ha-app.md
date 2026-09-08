# Phase 2B Collector Home Assistant App

Status: **0.2.0 HA OS DEPLOYMENT GATE FAILED CLOSED / 0.2.1 HOTFIX UNDER
REVIEW**. The `0.2.0` image was installed and given synthetic offline
configuration on the target, but its first start failed before the HTTPS
listener because the Collector used the wrong Supervisor self-info API path.
Candidate `0.2.1` changes only that endpoint. This document defines the
production-oriented App wrapper and records the CEZ-independent deployment
gate. It does not authorize CEZ access or implement a Home Assistant
integration.

## Selected release candidate

The hotfix candidate is Collector service version `0.2.1`. It retains the Home
Assistant-specific configuration bootstrap and API schema `1.0`. The App
manifest `version` and immutable GHCR tag must match. A future reviewed release
workflow run must publish only:

- `ghcr.io/dracoanus/home-assistant-cez-pnd-collector:0.2.1`; and
- `ghcr.io/dracoanus/home-assistant-cez-pnd-collector:sha-<commit>`.

The release workflow retains amd64-only Buildx output, cache reuse, SBOM,
`provenance: mode=max`, immutable-tag refusal, and a digest artifact. It never
publishes `latest`. The immutable `0.2.0` image remains at manifest digest
`sha256:70015c4f5d649bb3a44ff67ced7e9f4eeeb558186e012c515e58746337e1cd82`.
Candidate `0.2.1` is not yet published. The App has no Dockerfile, so
Supervisor must pull the prebuilt image and cannot build Chromium or Python
during installation.

## Architecture and trust boundaries

```text
owner configuration endpoint
        |
        | Supervisor-managed App options
        v
Supervisor ---- authenticated self-info ----> Collector App (UID/GID 2000)
                                                |
Home Assistant internal App network -------- HTTPS :8443
                                                |
                                                v
                              GET /api/v1/health|status|measurements
```

The host, HA OS, Supervisor, owner, and approved image remain trusted according
to the project specification. The future Home Assistant integration receives
only a limited Collector bearer token and public TLS trust data. It never
receives CEZ credentials. The service exposes no unauthenticated bootstrap,
pairing, administration, arbitrary URL, browser, shell, DOM, screenshot, or
debug endpoint.

## Bootstrap and private state

The deployment-validation bootstrap uses the supported Supervisor App
configuration boundary. App options contain:

| Option | Stored value | Security role |
| --- | --- | --- |
| `meter_id` | Opaque synthetic `mtr_` identifier | Selects the one authorized synthetic meter. |
| `api_token_sha256` | Lowercase SHA-256 verifier | Lets the Collector authenticate a token without persisting its plaintext. |
| `tls_certificate_b64` | Base64 PEM leaf certificate | Supplies the internal HTTPS identity. |
| `tls_private_key_b64` | Base64 PEM private key, masked as a password option | Supplies the TLS private key inside the trusted Supervisor boundary. |

The owner generates a random bearer token with at least 256 bits of entropy,
keeps its plaintext outside App options, and enters only its verifier in the
App. For the deployment gate, the token is held transiently by the validation
client. A future integration configuration flow will receive this limited API
token and TLS trust material through an owner-mediated pairing flow; that flow
is deliberately not implemented here.

On HA OS, the UID-2000 service is intended to retrieve only its own options
with the platform-provided Supervisor token. Release `0.2.0` incorrectly calls
`http://supervisor/apps/self/info`. Supervisor `2026.08.0` rejected that path
because the unversioned v1 policy permits `/addons/self/...`, while the v2
policy permits `/v2/apps/self/...`. The narrow corrective path is therefore
`http://supervisor/v2/apps/self/info`; enabling `hassio_api`, `full_access`, a
broader role, or root is neither required nor acceptable. This finding is
supported by the target Supervisor log and the current Supervisor security
middleware at
<https://github.com/home-assistant/supervisor/blob/main/supervisor/api/middleware/security.py>.
Redirects, oversized responses, malformed JSON, missing options, invalid token
verifiers, and invalid TLS material must continue to fail closed. The
Supervisor token and option values must never be logged.

TLS PEM values are written only to random mode-0600 files in `/tmp`, loaded
into the TLS context, and unlinked before the HTTPS listener starts. `tmpfs:
true` maps `/tmp` as tmpfs. Outside HA OS, including the existing Synology
smoke profile, the reviewed fixed-file configuration remains available; smoke
TLS and tokens remain test-only and do not define production pairing.

### Rotation and revocation

Token rotation is atomic from the Collector's perspective: generate a new
token, configure the new verifier, update the future integration credential,
and restart the App. Replacing the verifier revokes the old token. There is no
overlap or recovery endpoint in this release candidate. TLS rotation replaces
the certificate and key options together, followed by restart and renewed
trust/pin validation. Production UX, recovery, renewal, and rollback are
**OPEN / NEEDS VERIFICATION**.

## `/data` persistence and ownership

Home Assistant documents `/data` as the App's always-mounted writable
persistent volume and `/data/options.json` as Supervisor-managed configuration.
Current Supervisor source creates the App data directory without assigning UID
2000 and writes `options.json` mode `0600`. Historical and source evidence
therefore does not justify direct non-root access to that file or permission to
create sibling state. The service does not run as root and does not attempt to
change `/data` ownership.

For this gate, persistent state is limited to Supervisor-managed options. The
service obtains them through its authenticated self-info endpoint. Persistence
across stop/start and image update, backup inclusion, restore behavior, actual
ownership/mode, and the ability of UID 2000 to create a controlled private
subdirectory must be measured on HA OS. Direct UID-2000 writable `/data` state
for later measurement storage remains **OPEN / NEEDS VERIFICATION**.

## Internal hostname and TLS trust

Supervisor generates an installed App slug as `{REPO}_{SLUG}` and converts
underscores to hyphens for its internal DNS hostname. For the exact repository
URL `https://github.com/dracoanus/home-assistant-cez-pnd`, current Supervisor's
documented SHA-1-derived repository ID is `606197c3`; the expected hostname is
`606197c3-cez-pnd-collector`. The actual `hostname` and `dns` values returned by
Supervisor are authoritative and must be recorded before certificate issuance.
A different repository URL or local installation changes the prefix.

The leaf certificate must contain the observed hostname in its DNS SAN. The
validation client connects to `https://<observed-hostname>:8443`, validates the
chain against the test private CA, and verifies the hostname. `-k`,
`--insecure`, disabled verification, HTTP fallback, and redirects are
forbidden. The future integration will store only the Collector token and
reviewed CA/certificate pin. Exact pin format and renewal behavior remain
**OPEN / NEEDS VERIFICATION**.

No host port is published. Core-to-App traffic uses the internal App network.
Until the custom integration exists, an isolated validation client on that
network can prove DNS, routing, TLS, and authentication. A request originating
inside Home Assistant Core cannot be claimed until the future limited
integration performs the same check without copying CEZ credentials.

## Effective runtime controls

| Control | Manifest/image setting | Status |
| --- | --- | --- |
| Runtime identity | Image `USER 2000:2000`; startup fails on mismatch | REQUIRED; verify on HA OS |
| Prebuilt image | Generic GHCR image plus manifest version `0.2.1` | REQUIRED; image must exist before install |
| AppArmor | `apparmor: true`, protected mode retained | REQUIRED; effective profile verify on HA OS |
| Host namespaces | all host network/PID/IPC/UTS/D-Bus flags false | REQUIRED |
| Privilege/API | no privileged list; `full_access`, API, Docker, ingress and hardware flags false | REQUIRED |
| Host mounts/ports/devices | none requested; only Supervisor's mandatory private `/data` mount | REQUIRED |
| Temporary storage | `tmpfs: true` for `/tmp`; Supervisor also provides private `/dev/shm` tmpfs | REQUIRED; effective size is OPEN |
| Init/cleanup | inherited pinned `tini`; `init: false` avoids a second init | REQUIRED; verify clean stop |
| Chromium flags | image baseline unchanged; all forbidden sandbox flags remain forbidden | REQUIRED |
| Read-only root filesystem | no current documented App manifest key | OPEN / NEEDS VERIFICATION; do not invent a field |
| `no-new-privileges` | no current documented App manifest key | OPEN / NEEDS VERIFICATION at outer-container level |
| PID limit | no current documented App manifest key | OPEN / NEEDS VERIFICATION on HA OS |
| tmpfs size bound | `tmpfs` schema accepts only boolean | OPEN / NEEDS VERIFICATION |

Current Supervisor source sets the outer App container seccomp profile to
`unconfined`; that is platform behavior, not a requested manifest relaxation.
The already accepted HA OS Runtime Gate evidence positively established the
Chromium renderer's own `Seccomp=2`, `NoNewPrivs=1`, empty effective
capabilities, and separate user/PID/network namespaces. This wrapper neither
changes Chromium arguments nor adds capabilities. Effective controls must be
reconfirmed for the future `0.2.1` image.

## HA OS deployment and connectivity gate

Use the approved HA OS amd64 target and only synthetic/offline values.

1. Record HA OS, Supervisor, Core, kernel and architecture versions. Confirm
   branch contents include one `cez_pnd_collector` App entry and no Dockerfile
   in that directory.
2. Review and publish `collector-service-v0.2.1` separately. Record the commit,
   tag, version tag, SHA tag, image digest, SBOM and provenance. Confirm no
   `latest` tag is created.
3. Add or refresh the repository using its exact GitHub URL. Confirm Supervisor
   discovers **CEZ PND Collector**, reports amd64, version `0.2.1`, experimental
   stage, and a registry image. Capture the authoritative installed slug,
   hostname and DNS values.
4. Confirm installation pulls the recorded GHCR digest. Reject any local build
   or runtime package download.
5. Generate a temporary private CA and leaf certificate offline with a DNS SAN
   equal to the observed hostname. Generate a separate random bearer token of
   at least 256 bits and calculate its lowercase SHA-256 verifier. Put the
   verifier, opaque synthetic meter ID, base64 certificate and base64 key in App
   options. Never put the plaintext bearer token in App options or command
   arguments.
6. Start the App. Confirm the service reports only its bounded startup event,
   uses configuration source `supervisor_self_info`, and exposes no option,
   token, Supervisor token, certificate private key, header, or query value.
7. Inspect effective container state. Confirm PID 1 is the inherited `tini`,
   the service runs UID/GID `2000:2000`, there is no host network/PID/IPC/UTS
   sharing, no host port, no added capabilities, no devices or extra mounts,
   protection mode and AppArmor are active, and `/tmp` is tmpfs. Record the
   effective PID limit, root-filesystem writability, outer no-new-privileges,
   `/data` ownership/mode and tmpfs sizes without changing them to force PASS.
8. From a temporary isolated client on the Home Assistant internal App network,
   resolve the observed hostname. With the private CA and hostname validation
   enabled, assert unauthenticated and wrong-token `GET /api/v1/health` return
   `401`, and the correct transient token returns `200` with exactly API schema
   `1.0` and `service_status=ok`. Follow no redirects.
9. Stop and restart the App without re-entering options. Repeat TLS and all
   three authentication checks. Confirm the same TLS certificate fingerprint
   and token verifier remain effective, proving Supervisor-managed option
   persistence for restart.
10. Perform an image-update rehearsal only after a separately reviewed next
    image exists. Confirm options survive and the old image can be selected for
    rollback. Record backup/restore behavior separately; do not assume it from
    restart success.
11. Stop the App normally. Confirm the service emits `service_stopped`, exits
    within the configured timeout, and leaves no service/Chromium processes.
12. When the limited custom integration is later authorized, repeat the
    authenticated health request from Core with only the Collector credential
    and TLS trust material. Until then, Core-origin connectivity remains OPEN.

The gate passes only if image pull, non-root identity, HTTPS trust, negative and
positive authentication, restart persistence, clean shutdown, and every
expressible isolation control pass without deviations. Static CI validates
structure and policy only; it cannot substitute for this HA OS evidence.

## Collector 0.2.1 hotfix scope

Collector `0.2.1` changes only the Supervisor self-info endpoint from the
rejected unversioned URL to exactly
`http://supervisor/v2/apps/self/info`. It provides no fallback to
`http://supervisor/apps/self/info`. Token handling, redirect rejection, the
256-KiB response bound, strict response validation, TLS material handling,
bearer verifier bootstrap, non-root identity, manifest permissions, API
surface, and fail-closed behavior remain unchanged. Release `0.2.0`, its tag,
and its published images remain immutable.

## HA OS 0.2.0 deployment result

The first-start gate was executed on 8 September 2026 with Home Assistant OS
`18.2`, Supervisor `2026.08.0`, Home Assistant Core `2026.9.0`, and amd64
`qemux86-64`. It used only synthetic offline configuration. No CEZ host was
contacted and no CEZ credential was present.

Supervisor recorded that it downloaded
`ghcr.io/dracoanus/home-assistant-cez-pnd-collector:0.2.0`, attached that image,
and successfully installed App `606197c3_cez_pnd_collector`. The observed
internal hostname was `606197c3-cez-pnd-collector`. The four App options passed
the manifest schema and were saved before start. The meter identifier and token
verifier remained populated after a page reload; Home Assistant redacted the
two password-class TLS fields, so their persisted values could be established
only by the fail-closed runtime bootstrap.

The first start produced this sequence:

1. Supervisor started the prebuilt `0.2.0` image.
2. Supervisor rejected the App's request to `/apps/self/info`, recording
   `missing API permission for /apps/self/info` and then
   `Invalid token for access /apps/self/info`.
3. The Collector emitted only its bounded
   `startup_failed`/`invalid_private_configuration` event and exited with code
   `1`.
4. Supervisor left the App stopped with an error state.

This is a **CONFIRMED application bootstrap defect**. It is not evidence that
the App needs Supervisor API permission. The current Supervisor middleware
defines the unprivileged v2 App self-info bypass under
`/v2/apps/self/...`; the Collector omitted the `/v2` prefix. The service failed
closed before creating its TLS context or HTTPS listener, and the available App
and Supervisor records exposed no option values, bearer token, TLS key, or
Supervisor token.

| Gate item | Result | Evidence / limitation |
| --- | --- | --- |
| Repository discovery and manifest acceptance | **PASS** | Supervisor discovered and installed CEZ PND Collector `0.2.0`. |
| Prebuilt image use | **PASS** | Supervisor downloaded and attached the GHCR `0.2.0` image; the App has no Dockerfile. |
| Exact immutable pulled digest | **OPEN / NEEDS VERIFICATION** | The UI/Supervisor records observed in this run identified the tag, not the resolved manifest digest. |
| Installed slug and internal hostname | **PASS** | `606197c3_cez_pnd_collector` and `606197c3-cez-pnd-collector` were observed. |
| Option schema and save | **PASS** | Save succeeded and no schema error was shown. |
| Option persistence | **PARTIAL** | Meter ID and verifier survived reload; TLS password fields were intentionally redacted and bootstrap did not read them. |
| Runtime UID/GID check | **PASS BY APPLICATION CHECK** | Startup passed the fail-closed UID/GID `2000:2000` check before configuration failed; independent container inspection was not completed. |
| Supervisor self-info bootstrap | **FAIL** | The unversioned `/apps/self/info` path was rejected by Supervisor. |
| HTTPS and bearer authentication | **BLOCKED / NOT RUN** | The service exited before listener creation. |
| Status and measurement endpoints | **BLOCKED / NOT RUN** | No HTTPS listener existed. |
| Effective AppArmor, namespaces, capabilities, mounts, tmpfs and PID controls | **OPEN / NOT OBSERVED** | The process exited before the planned container-state inspection. |
| Restart persistence and clean normal shutdown | **BLOCKED / NOT RUN** | A second start was intentionally avoided after the deterministic bootstrap failure. |
| Secret-safe failure logging | **PASS FOR OBSERVED RECORDS** | Only bounded error codes and request paths were present; no configured value or plaintext secret was emitted. |

The deployment gate result is **FAIL / BLOCKED** for Collector `0.2.0`.
Release `0.2.0` must not be promoted for HA OS use. A reviewed fix must change
only the self-info URL to the v2 App path, retain the existing bounded parsing
and fail-closed behavior, add a regression test for the exact URL, publish a
new immutable image version, and repeat this gate from first start. The test
App remains stopped. The temporary offline token and TLS material are retained
outside the repository under restricted local access solely for the controlled
repeat; they are not production pairing material.

## OPEN / NEEDS VERIFICATION

- The exact immutable manifest digest resolved by Supervisor during the
  observed tagged-image pull.
- Successful option retrieval from `/v2/apps/self/info` without `hassio_api`
  after a reviewed corrective release.
- Persistence of the two redacted TLS options across restart.
- Actual `/data` owner/mode, UID-2000 access, controlled file creation, restart,
  update, backup and restore behavior.
- Effective outer-container read-only-root, no-new-privileges, PID limit,
  default capability set and tmpfs size controls; the current schema does not
  expose all of them.
- Certificate SAN validation and internal HTTPS connectivity to the observed
  hostname on the target.
- Successful restart behavior and continued absence of option values from
  logs/diagnostics after the bootstrap fix.
- Production certificate authority, issuance, renewal, pin format, recovery,
  token pairing, rotation, revocation and owner UX.
- A Core-origin HTTPS request through the future limited custom integration.
- Production measurement persistence and bounded `/data` storage.
- All CEZ-specific behavior, which remains outside this step.

## Specification alignment

The wrapper preserves the approved Collector/Core boundary, limited API
credential, HTTPS-only internal API, non-root runtime, sandbox baseline,
prebuilt reproducible image, private App configuration, and absence of CEZ
behavior. The unresolved O-12 pairing/TLS design and O-13 backup behavior mean
this bootstrap remains experimental. No conflict requires weakening the
authoritative specification; unresolved production requirements fail closed
and block promotion beyond the deployment gate.
