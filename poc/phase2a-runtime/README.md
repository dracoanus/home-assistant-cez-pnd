# Phase 2A-1 disposable runtime probe

This directory contains an experimental Home Assistant App/add-on used only to
verify the Phase 2A-1 runtime assumptions. It is not Collector production code
and must not be promoted without a separate design and review.

The probe uses a loopback-only synthetic page. It neither requests credentials
nor contacts CEZ. It prints one JSON evidence document to the App log and exits
non-zero unless the mandatory sandbox and cleanup checks pass.

## Target execution

1. Copy `poc/phase2a-runtime` into the target Home Assistant OS local apps
   directory as a single app folder.
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
