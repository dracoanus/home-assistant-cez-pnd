# Phase 2B Collector Home Assistant App

Status: **PREPARED / HA OS RUNTIME VERIFICATION REQUIRED**. This document
defines the production-oriented App wrapper and a CEZ-independent deployment
gate. It does not record a runtime PASS, publish an image, implement a Home
Assistant integration, or authorize CEZ access.

## Selected release candidate

The next Collector service version is `0.2.0`. This is a minor release because
it adds a Home Assistant-specific configuration bootstrap while retaining API
schema `1.0`. The App manifest `version` and immutable GHCR tag must match.
The workflow must publish only:

- `ghcr.io/dracoanus/home-assistant-cez-pnd-collector:0.2.0`; and
- `ghcr.io/dracoanus/home-assistant-cez-pnd-collector:sha-<commit>`.

The workflow retains amd64-only Buildx output, cache reuse, SBOM,
`provenance: mode=max`, immutable-tag refusal, and a digest artifact. It never
publishes `latest`. No tag, image, or release is created by this change. The App
has no Dockerfile, so Supervisor must pull the prebuilt image and cannot build
Chromium or Python during installation.

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

On HA OS, the UID-2000 service retrieves only its own options from the fixed
`http://supervisor/apps/self/info` endpoint with the platform-provided
Supervisor token. Current Supervisor source explicitly allows self-info without
`hassio_api: true`; the App therefore requests neither Supervisor API nor Home
Assistant API permission. Redirects, oversized responses, malformed JSON,
missing options, invalid token verifiers, and invalid TLS material fail closed.
The Supervisor token and option values are never logged.

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
| Prebuilt image | Generic GHCR image plus manifest version `0.2.0` | REQUIRED; image must exist before install |
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
reconfirmed for the `0.2.0` image.

## HA OS deployment and connectivity gate

Use the approved HA OS amd64 target and only synthetic/offline values.

1. Record HA OS, Supervisor, Core, kernel and architecture versions. Confirm
   branch contents include one `cez_pnd_collector` App entry and no Dockerfile
   in that directory.
2. Review and publish `collector-service-v0.2.0` separately. Record the commit,
   tag, version tag, SHA tag, image digest, SBOM and provenance. Confirm no
   `latest` tag is created.
3. Add or refresh the repository using its exact GitHub URL. Confirm Supervisor
   discovers **CEZ PND Collector**, reports amd64, version `0.2.0`, experimental
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

## OPEN / NEEDS VERIFICATION

- This change does not publish the `0.2.0` image; the recorded immutable image
  must exist before installation.
- Supervisor 2026.08+ acceptance of this exact manifest and options schema.
- Actual `/data` owner/mode, UID-2000 access, controlled file creation, restart,
  update, backup and restore behavior.
- Effective outer-container read-only-root, no-new-privileges, PID limit,
  default capability set and tmpfs size controls; the current schema does not
  expose all of them.
- Exact installed hostname/DNS and certificate SAN validation on the target.
- Security and usability of Supervisor self-info bootstrap on the target,
  including restart behavior and absence of values from logs/diagnostics.
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
