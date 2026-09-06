# Phase 2A-1 disposable runtime probe

This directory contains an experimental Home Assistant App/add-on used only to
verify the Phase 2A-1 runtime assumptions. It is not Collector production code
and must not be promoted without a separate design and review.

The probe uses a loopback-only synthetic page. It neither requests credentials
nor contacts CEZ. It prints one JSON evidence document to the App log and exits
non-zero unless the mandatory sandbox and cleanup checks pass.

## Configuration authority

`config.yaml` is the authoritative Home Assistant OS/Supervisor runtime
manifest. `config.json` is an internal Phase 2A static-verification fixture and
reference only. It must never be installed as a runtime manifest or override
`config.yaml`.

Current Supervisor versions recognize JSON, YAML and YML files named
`config.*` and scan app repositories recursively. Do not copy this source
directory verbatim into the target local apps directory while `config.json` is
present. Build the target directory from this explicit runtime allowlist:

- `config.yaml`
- `Dockerfile`
- `requirements.lock`
- `runtime_probe.py`

After copying, verify that the target app directory contains `config.yaml` and
does not contain `config.json` or any other `config.*` file. The static verifier
compares security-relevant effective values in both source representations and
fails closed on divergence, but that comparison does not make `config.json` a
valid runtime input.

## Target build observation

The first target build on Home Assistant OS 18.2 with Supervisor 2026.08.0
accepted the local App manifest and installed the pinned Chromium,
ChromeDriver, Python and Selenium packages. It then failed in the original
`apk info -v` package-version assertion because `apk add --no-cache` had not
retained a repository `APKINDEX` cache. The version check now uses `apk info
-e` with networking disabled and `/dev/null` as the repositories file. This
checks exact constraints against installed package records and still fails if a
package is absent or has another version.

The image did not finish building in that attempt. Chromium runtime and sandbox
behavior therefore remain untested.

## Target execution

1. Create a single app folder in the target Home Assistant OS local apps
   directory and copy only the four runtime allowlist files above into it.
2. In **Settings > Apps**, refresh the local app list and build the experimental
   app.
3. Before starting it, record the exact Home Assistant OS and Supervisor
   versions shown by **Settings > System > Repairs > System information**.
4. Start the app once and retain the complete JSON log output as evidence.
5. Inspect the deployed App configuration and confirm protection mode remains
   enabled, no extra capabilities or mounts are present, and no host/LAN port is
   published.
6. Treat an exit code other than zero, `sandbox.verified: false`, any security
   deviation, or incomplete evidence as failure.

The default run covers normal Selenium completion, an expected Selenium
exception and a Selenium timeout. Forced Collector termination must be tested
separately on the target: start an instrumented browser-hold variant only after
owner review, stop the App through Supervisor, and inspect the host process list
before and after. This repository does not include that variant because the
current environment cannot validate host-side process visibility safely.

## Local static verification

Run:

```text
python poc/phase2a-runtime/static_verify.py
python -m py_compile poc/phase2a-runtime/runtime_probe.py
```

Container build and runtime tests require a Linux/amd64 Docker environment or
the approved Home Assistant OS target. They were not available on the authoring
host when this artifact was created.
