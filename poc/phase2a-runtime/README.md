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

The corrected image subsequently built and started on the same target. The
first runtime returned failure because two Selenium sessions disconnected and
Chromium processes remained after cleanup. Its final sandbox summary also read
only the failed normal case, even though the timeout case captured renderers
with `NoNewPrivs: 1`, `Seccomp: 2` and additional namespaces.

The probe now retains process snapshots on success and failure, evaluates the
strongest internally consistent snapshot across every case, and uses renderer
namespace separation plus `/proc` seccomp and no-new-privileges state as the
authoritative sandbox evidence. It no longer navigates to `chrome://sandbox`.
Overall PASS still requires positive sandbox evidence, all three functional
cases and complete cleanup.

Cleanup now follows normal WebDriver/service shutdown with same-UID SIGTERM,
bounded waiting, same-UID SIGKILL when required, and PID 1 child reaping. No
privilege or capability is added. Aggregate PSS is reported alongside summed
RSS to reduce shared-page double counting.

The next HA OS run verified that cleanup succeeds: `cleanup_verified` was true
and every case reported an empty `orphan_pids_after_cleanup` list. It also
captured renderer processes with UID/GID `2000:2000`, `NoNewPrivs: 1`,
`Seccomp: 2` and separate user, PID and network namespaces. Peak aggregate PSS
was approximately `394489 KiB`. Functional execution still failed after the
browser lost its DevTools connection.

That run exposed a command-line classification defect. Chromium deliberately
rewrites its Linux process title as one space-separated string, so
`/proc/<pid>/cmdline` can contain a single NUL-terminated field such as
`/usr/lib/chromium/chromium --type=renderer ...`. The old classifier searched
for a separate list item equal to `--type=renderer` and therefore reported zero
renderers. The probe now preserves the actual NUL fields, records whether the
read was NUL terminated, extracts switches from Chromium's single process-title
field, and applies renderer, zygote and forbidden-argument policy through one
classifier. Truncated, lossy or non-authoritative command-line evidence cannot
satisfy the sandbox gate. A `renderer_discovery_timeout` means only that
classification did not observe a renderer during the bounded discovery window;
WebDriver startup is recorded separately and the action is still attempted.

The following HA OS run resolved that classification issue and returned
`sandbox.verified: true` with three classified renderers,
`cleanup_verified: true`, and no security deviation. Functional execution
still failed, so the overall result correctly remained false. The retained
aggregate result does not identify which case failed or its final action
milestone. The probe now emits a compact `functional_failures` list containing
the case, last milestone, Selenium error, renderer discovery state, browser and
renderer PIDs present at the error snapshot, ChromeDriver return code before
cleanup, and cleanup result. This adds diagnostics only and does not alter a
functional or security gate.

The latest HA OS run identified the functional boundary. The `normal` and
`selenium_exception` cases both started WebDriver and observed a renderer, then
failed on their first `driver.get()` call between the
`before_synthetic_navigation` and `after_synthetic_navigation` milestones.
The timeout case did not navigate; it remained operational while executing its
intentional asynchronous-script timeout and supplied four usable renderers.
The navigation command is therefore the confirmed trigger boundary. The
retained evidence still does not establish whether Chromium, a renderer or the
DevTools connection failed underneath that command.

That run also caught two process identities with evidence consistent with an
exit race. Linux returns an empty `/proc/<pid>/cmdline` for zombies, so an empty
command line is not automatically evidence of a malformed live Chromium
process. The probe now
rechecks each PID plus `/proc/<pid>/stat` start time after collecting evidence.
It excludes an identity from the live-process completeness verdict only after
positively observing a zombie/dead state, disappearance of that same identity,
or PID reuse after its exit. A still-live or ambiguously readable process with
incomplete command-line or security evidence continues to fail closed. The
full snapshot retains every excluded PID and its lifecycle reason.

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
