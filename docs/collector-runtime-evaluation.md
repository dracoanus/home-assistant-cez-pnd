# Debian Collector runtime evaluation

## Current decision

The Synology Container Manager host remains useful for deterministic image
builds but is no longer an authoritative Chromium sandbox runtime. The
production-oriented Debian image will be built once in GitHub Actions,
published to GHCR, and pulled by Home Assistant OS for the authoritative
runtime gate. No CEZ behavior is included.

## Synology control result

**CONFIRMED:** ChromeDriver and Chromium `152.0.7977.82` entered the browser
launch sequence. Chromium then reported that PID and network namespaces were
supported but namespace creation failed with `EPERM`. The zygote exited with
status 1, after which Selenium raised `SessionNotCreatedException`.

This establishes an outer-container policy denial on that Synology runtime. It
does not demonstrate a Chromium package, ChromeDriver, GPU or application-code
failure. No additional capability or sandbox-disabling argument is acceptable
as a compatibility workaround. Further Synology runtime compatibility work is
stopped.

## Relationship to HA OS evidence

The Synology result does not invalidate the prior HA OS result. The HA OS
runtime positively observed Chromium renderers running as UID/GID 2000 with
`NoNewPrivs=1`, seccomp filter mode 2, separate user/PID/network namespaces and
no forbidden sandbox arguments. Container engines and their seccomp, LSM and
namespace policies are distinct. The Synology `EPERM` describes only the
Synology outer runtime policy; HA OS remains the authoritative target.

## Prebuilt image model

Home Assistant's supported `config.yaml` model uses a generic registry image
name and the App `version` as its active image tag. The experimental wrapper
therefore references
`ghcr.io/dracoanus/home-assistant-cez-pnd-collector-runtime` with version
`0.1.0`. It intentionally contains no Dockerfile.

The GitHub Actions workflow runs only for tags matching
`collector-runtime-vMAJOR.MINOR.PATCH`, requires the tag to match the App
version, refuses to overwrite an existing version or commit-SHA tag, builds
only `linux/amd64`, and publishes no `latest` tag. BuildKit attaches an SBOM and
maximum provenance. The workflow records the resulting digest in its summary
and a retained artifact. The GHCR package must be public before Supervisor can
pull it without registry credentials.

The Supervisor schema uses the version tag rather than an image digest in
`config.yaml`. Immutability is consequently enforced by the publish workflow,
while the digest is recorded and checked independently on the target.

## Runtime gate

The image retains the ordered offline smoke sequence: WebDriver creation,
`about:blank`, trivial JavaScript, a `data:` document and DOM read, a loopback
HTTP document and DOM read, then cleanup. A compact `/proc` check follows the
functional operations and fails closed unless live renderers positively show
UID/GID 2000, `NoNewPrivs=1`, `Seccomp=2`, zero effective capabilities,
separate user/PID/network namespaces and no forbidden sandbox arguments.
Cleanup fails if a Chromium process remains after the bounded wait.

This check is intentionally limited to the HA OS entry gate. It does not copy
the frozen Phase 2A diagnostic framework or reopen the sandbox findings already
established there.

## Expected installation effect

The old local App build pulled a base image and ran APT and hash-locked pip
installation on HA OS. The wrapper now performs a registry pull and container
creation only. Installation should therefore be governed by GHCR download and
local unpack speed and should avoid repeated package installation entirely.
Exact cold-pull and cached-pull times remain **OPEN / NEEDS VERIFICATION** until
measured on the target.

## Security statement

No sandbox control was weakened. The design still forbids `--no-sandbox`,
`--disable-setuid-sandbox`, `--disable-gpu-sandbox`, `SYS_ADMIN`, `NET_ADMIN`,
privileged/full-access mode, unconfined seccomp, host networking, broad
capabilities, broad mounts/devices and AppArmor weakening. Runtime identity
remains UID/GID 2000:2000.
