# Phase 2A-1 — Offline Runtime Feasibility Verification

- Date: 2026-09-06
- Branch: `phase2a/runtime-verification`
- Scope: disposable runtime proof of concept only
- Authoritative requirements: [`project-specification.md`](project-specification.md)
- Prior evidence: [`phase1-analysis.md`](phase1-analysis.md)

## Result classification

This report uses the required classifications as follows:

- **DESIGN VERIFIED** — the proposed mechanism is defined and reviewed against
  the specification, but has not executed.
- **STATICALLY VERIFIED** — files or authoritative package metadata were
  inspected without executing the Linux container.
- **LOCALLY TESTED** — a check executed on the Windows authoring host; this does
  not establish Linux or Home Assistant OS behavior.
- **HA OS VERIFIED** — the check executed inside the approved Home Assistant OS
  and Supervisor App environment.
- **NOT VERIFIED** — evidence was not obtained.
- **BLOCKED** — the required environment or evidence was unavailable and the
  conclusion cannot be advanced safely.

The first target build now provides limited **HA OS VERIFIED** evidence for App
discovery, manifest acceptance, image-base retrieval and dependency
installation. The image did not finish building, so Chromium execution,
sandboxing and all other runtime properties remain **NOT VERIFIED**.

## Target build attempt 1

The first real build was run on this target:

| Item | Observed value |
| --- | --- |
| Home Assistant OS | `18.2` |
| Supervisor | `2026.08.0` |
| Home Assistant | `2026.9.0` |
| Architecture / machine | `amd64` / `qemux86-64` |

The target discovered the local App and Supervisor accepted the authoritative
`config.yaml` manifest. The pinned Home Assistant base image was pulled. The
build then installed Chromium `152.0.7977.82-r0`, ChromeDriver
`152.0.7977.82-r0`, Python `3.14.7-r1`, Selenium `4.48.0` and every locked
Python dependency.

The build failed only in the final Dockerfile package-version assertions. The
original assertions used `apk info -v` after `apk add --no-cache`; on the target,
`apk info` attempted to open an `APKINDEX.tar.gz` cache that had deliberately
not been retained. This is classified as a **Phase 2A-1 build-verification
defect**, not a Chromium runtime failure.

The replacement uses `apk --no-network --repositories-file /dev/null info -e`
with exact `name=version` constraints. The `info -e` operation evaluates only
installed package providers, while the global options remove network and
repository-index inputs. It fails when either package is absent or its
installed version does not satisfy the exact constraint. This correction is
**STATICALLY VERIFIED** and requires a repeat target build.

Alpine `apk-tools` implements `info -e` by parsing each argument as a package
dependency, ignoring providers without an installed-package record (`ipkg`),
and returning a non-zero count for unsatisfied dependencies. Evidence:
<https://gitlab.alpinelinux.org/alpine/apk-tools/-/blob/v2.14.10/src/app_info.c>
and
<https://gitlab.alpinelinux.org/alpine/apk-tools/-/blob/v2.14.10/doc/apk-info.8.scd>.

Because the failed RUN layer prevented image completion, Chromium never
started. Chromium runtime, Selenium operation and sandbox enforcement remain
**NOT VERIFIED**.

## 1. Environment tested

| Item | Observed value | Classification | Evidence |
| --- | --- | --- | --- |
| Authoring OS | Microsoft Windows 11 Pro, version `10.0.26100`, x64 | LOCALLY TESTED | PowerShell `Win32_OperatingSystem` and .NET `OSArchitecture` output on 2026-09-06 |
| Docker CLI/engine | Not installed or available in `PATH` | LOCALLY TESTED | `Get-Command docker` returned `NOT FOUND` |
| Podman / nerdctl | Not installed or available in `PATH` | LOCALLY TESTED | `Get-Command podman, nerdctl` returned `NOT FOUND` |
| WSL Linux distribution | WSL reported that Windows Subsystem for Linux is not installed | LOCALLY TESTED | `wsl --list --verbose` and `wsl --status` |
| Approved HA OS target | HA OS `18.2`, Supervisor `2026.08.0`, Home Assistant `2026.9.0`, `amd64` / `qemux86-64` | HA OS VERIFIED for build attempt | Operator-provided build result from target attempt 1 |
| Synthetic target | Loopback HTTP server created by the probe | DESIGN VERIFIED | `poc/phase2a-runtime/runtime_probe.py`, `SyntheticHandler` |

The local checks prove only that the disposable artifact is structurally
consistent and syntactically valid Python. They do not approximate the HA OS
kernel, Docker, AppArmor, seccomp or namespace behavior. Target attempt 1 adds
build-path evidence only; it did not start the container.

## 2. Home Assistant OS version

**HA OS VERIFIED for target build attempt 1:** `18.2`. The PoC still does not
request Supervisor API access merely to discover this value; it was recorded by
the target operator.

The public release list was consulted only to avoid treating an old release as
the target; it is not evidence of the installed VM version:
<https://github.com/home-assistant/operating-system/releases>.

## 3. Supervisor version

**HA OS VERIFIED for target build attempt 1:** `2026.08.0`. Home Assistant was
`2026.9.0`. The App requests no Supervisor API capability; the versions were
recorded outside the App by the target operator.

Reference release history, not target evidence:
<https://github.com/home-assistant/supervisor/releases>.

## 4. Architecture

The approved target architecture is `amd64`. The disposable App declares only
`amd64` in the authoritative `poc/phase2a-runtime/config.yaml`. The Home Assistant documentation
maps App `amd64` to Docker platform `linux/amd64`:
<https://developers.home-assistant.io/docs/apps/testing/>.

- App declaration: **STATICALLY VERIFIED**.
- Alpine package metadata architecture `x86_64`: **STATICALLY VERIFIED**.
- Supervisor build execution on `amd64` / `qemux86-64`: **HA OS VERIFIED**.
- Chromium runtime execution on that target: **NOT VERIFIED**.

## 5. Chromium version and availability

| Property | Finding | Classification |
| --- | --- | --- |
| Package | Alpine `chromium` | STATICALLY VERIFIED |
| Version pinned in PoC | `152.0.7977.82-r0` | STATICALLY VERIFIED |
| Repository | Alpine 3.24 `community` | STATICALLY VERIFIED |
| Architecture | `x86_64` | STATICALLY VERIFIED |
| Alpine source commit | `73650098eb2aa1baf6fe7b09586838990466235c` | STATICALLY VERIFIED |
| Package installation in target build layer | `152.0.7977.82-r0` installed | HA OS VERIFIED for build attempt 1 |
| Completed image / executable runtime | Image did not complete; executable was not run | NOT VERIFIED |

Evidence: official Alpine package record checked directly on 2026-09-06:
<https://pkgs.alpinelinux.org/package/v3.24/community/x86_64/chromium>.

The image base is pinned to Home Assistant base 3.24 manifest digest
`sha256:93ef607824e3f27e868f11b10938283a98bf880ed57bcf8eaa81c6c2d521f6f5`.
The anonymous GHCR registry API returned an OCI index containing the
`linux/amd64` child manifest
`sha256:59c99f645cd5bc2e20ca8acac0a6a6163749720e1a1fcdd49bcb5702b5db9688`.
The referenced GHCR package page associated that digest with the Home Assistant
3.24 image when inspected:
<https://github.com/home-assistant/docker-base/pkgs/container/base>.

Target installation advances package availability beyond metadata evidence,
but the failed final assertion means no completed image or runtime evidence
exists yet.

## 6. ChromeDriver version and compatibility

| Property | Finding | Classification |
| --- | --- | --- |
| Package | Alpine `chromium-chromedriver` | STATICALLY VERIFIED |
| Version pinned in PoC | `152.0.7977.82-r0` | STATICALLY VERIFIED |
| Repository / architecture | Alpine 3.24 `community` / `x86_64` | STATICALLY VERIFIED |
| Origin / source commit | `chromium` / `73650098eb2aa1baf6fe7b09586838990466235c` | STATICALLY VERIFIED |
| Installation in target build layer | Exact pinned ChromeDriver package installed | HA OS VERIFIED for build attempt 1 |
| Browser/driver compatibility | Exact upstream version and source commit match | STATICALLY VERIFIED; runtime handshake NOT VERIFIED |

Evidence: <https://pkgs.alpinelinux.org/package/v3.24/community/x86_64/chromium-chromedriver>.

The Docker build asserts the exact installed package versions using `apk info
-e` against the installed package database with repository and network inputs
disabled. Selenium receives the explicit path `/usr/bin/chromedriver`;
Selenium Manager fallback is not used. `SE_OFFLINE=true`,
`SE_AVOID_BROWSER_DOWNLOAD=true`, and `SE_AVOID_STATS=true` are set in the
image. Browser, driver, Python `3.14.7-r1`, Selenium `4.48.0` and every locked
Python dependency installed successfully during target build attempt 1.
Runtime binary downloading is forbidden by construction and is checked
statically, but an offline runtime start has **NOT** executed.

The Python dependency set is fully version pinned and SHA-256 locked in
`poc/phase2a-runtime/requirements.lock`. Selenium is `4.48.0`. The Selenium
project documents that an explicit `Service` path skips Selenium Manager and
that its offline/download controls exist:
<https://www.selenium.dev/documentation/selenium_manager/>.

## 7. UID and GID

The proposed dedicated identity is:

| Identity | Value | Classification |
| --- | ---: | --- |
| UID | `2000` | STATICALLY VERIFIED in Dockerfile |
| GID | `2000` | STATICALLY VERIFIED in Dockerfile |
| Effective UID/GID at probe entry | Must equal `2000:2000` or the probe exits before starting Chromium | DESIGN VERIFIED |
| Effective UID/GID of every observed Chromium process | Must equal `2000:2000` or sandbox verification fails | DESIGN VERIFIED |

The final image declares `USER 2000:2000`. The build verifies package metadata
without starting the Chromium or ChromeDriver executable as root. Actual
effective process identities are **NOT VERIFIED** until the App runs on the
target.

## 8. Chromium sandbox verification result

**NOT VERIFIED / BLOCKED.** Chromium did not run in Linux or HA OS, so the
required sandbox result cannot be asserted.

The probe is designed to fail closed unless all of these conditions are true:

1. `chrome://sandbox` reports a layer 1 Namespace or SUID sandbox.
2. `chrome://sandbox` reports `Seccomp-BPF sandbox Yes`.
3. At least one renderer process is observed.
4. Every observed renderer has `/proc/<pid>/status` values `Seccomp: 2` and
   `NoNewPrivs: 1`.
5. Every observed Chromium process has effective UID/GID `2000:2000`.
6. No observed browser process contains any forbidden sandbox-disabling
   argument.

The probe records user, PID, network, mount and IPC namespace identifiers for
each process. Container seccomp alone is not treated as proof of Chromium's
renderer sandbox. Chromium's own Linux sandbox status definitions and internal
page behavior are evidenced by:

- <https://chromium.googlesource.com/chromium/src/+/HEAD/sandbox/policy/linux/sandbox_linux.h>
- <https://chromium.googlesource.com/chromium/src/+/4b74fa1307784d2fe83c3dad453874e7b3911331/chrome/browser/resources/sandbox_internals/sandbox_internals.js>
- <https://chromium.googlesource.com/chromium/src/+/0e94f26e8/docs/linux_sandboxing.md>

No sandbox-disabling flag is passed by the PoC. Static inspection found none in
the effective launch argument construction. This absence is necessary but is
not a positive sandbox result.

## 9. Required Linux capabilities and container privileges

The PoC requests no Linux capability. It also explicitly disables all optional
Home Assistant/Supervisor APIs and `full_access`; it declares no host directory
map, published port, device access or host-network option.

| Prohibited item | PoC declaration | Classification |
| --- | --- | --- |
| Privileged/full access | `full_access: false`; no `privileged` list | STATICALLY VERIFIED |
| `NET_ADMIN` / `SYS_ADMIN` | No capabilities requested | STATICALLY VERIFIED |
| Host network / PID / IPC | No such option requested | STATICALLY VERIFIED |
| Docker socket | `docker_api: false`; no map | STATICALLY VERIFIED |
| `/config` / `/ssl` | No map | STATICALLY VERIFIED |
| Home Assistant / Supervisor / auth API | Explicitly `false` | STATICALLY VERIFIED |
| Effective deployed privileges | Unknown until Supervisor inspection | NOT VERIFIED |

Home Assistant documents that Apps are protection-enabled by default and that
`full_access`, API switches, privileged capabilities and maps must be requested
in App configuration:
<https://developers.home-assistant.io/docs/apps/security/> and
<https://developers.home-assistant.io/docs/apps/configuration/>.

If the target build or run needs a prohibited privilege, Phase 2A-1 fails. The
PoC must not be changed to grant it.

## 10. Filesystem requirements

The PoC installs immutable root-owned application files under `/opt` and a
non-writable root-owned placeholder home, with write bits removed after
installation. At startup it creates a private `0700` runtime root under `/tmp`
for HOME, XDG paths and one private subdirectory per browser session:

- browser profile: `/tmp/phase2a-runtime-*/<case>-*/profile`, mode `0700`;
- controlled download: `/tmp/phase2a-runtime-*/<case>-*/download`, mode `0700`;
- Python temporary root: mode `0700`;
- persistent application data: not used by the probe.

The App declares no `/config`, `/ssl`, share, media, backup or other host map.
Home Assistant nevertheless provides the App-owned `/data` volume by platform
design. The PoC does not write to it. The documentation confirms that `/data`
is the App's persistent storage and is always mapped:
<https://developers.home-assistant.io/docs/apps/configuration/>.

Actual ownership and mount options are **NOT VERIFIED**. A read-only container
root filesystem is **NOT VERIFIED** and is not claimed. Running the whole probe
as UID `2000` is intended to prevent writes to root-owned image paths; the
effective deployed filesystem must be inspected on HA OS.

## 11. Tmpfs and shared-memory requirements

The probe requires writable private subdirectories below `/tmp` and access to
the container's `/dev/shm`. It deliberately does not use
`--disable-dev-shm-usage`, so shared-memory requirements remain observable.

At runtime the probe records total, used and free bytes for `/tmp` and
`/dev/shm`, plus profile and download bytes for every case. No measurement was
produced in the current environment.

- Appropriate `/tmp` size: **NOT VERIFIED**.
- Appropriate `/dev/shm` size: **NOT VERIFIED**.
- Supervisor tmpfs backing/mount behavior: **NOT VERIFIED**.
- Profile/download use of private `/tmp` directories: **DESIGN VERIFIED**.

No size recommendation is made without measurements from the target.

## 12. Process cleanup results

**NOT VERIFIED / BLOCKED.** No Selenium, ChromeDriver or Chromium process ran.

The included probe has three cases:

| Case | Intended evidence | Current result |
| --- | --- | --- |
| Normal completion | `driver.quit()` followed by `/proc` descendant audit | NOT VERIFIED |
| Selenium exception | Expected `NoSuchElementException`, `finally` cleanup and descendant audit | NOT VERIFIED |
| Selenium timeout | Expected script `TimeoutException`, `finally` cleanup and descendant audit | NOT VERIFIED |
| Forced Collector/App termination | Supervisor stop plus host-level before/after process audit | BLOCKED; target access required |

The script tracks the full ChromeDriver descendant tree both before and after
browser actions and waits for every observed PID to disappear. Any surviving PID
makes the case fail. SIGTERM raises `SystemExit`, allowing the active `finally`
block to call `driver.quit()`.

Forced termination cannot be proven from inside a container after the container
has stopped. It requires a separately reviewed hold scenario and host/Supervisor
process observation on the actual target. That variant was not added because it
could not be safely validated here.

## 13. Resource measurements

No Chromium resource values were measured. Required measurements are
**NOT VERIFIED**:

- RAM usage;
- CPU usage;
- startup time;
- browser process count;
- profile/download and `/tmp` usage;
- `/dev/shm` usage.

When run, the probe reports approximate summed observed RSS, CPU seconds during
each action, startup/action wall time, process count, per-process RSS, private
directory bytes, and `/tmp` and `/dev/shm` filesystem usage. These will be
environment-specific and must not be generalized beyond the exact HA OS,
Supervisor, image digest, kernel and Synology VMM configuration tested.

## 14. Failures and uncompleted tests

1. Target build attempt 1 reached the final package-version assertions and
   failed because `apk info -v` depended on an absent cached repository index.
2. **BLOCKED locally:** no local Linux container engine or WSL distribution.
3. Chromium/ChromeDriver image build: **INCOMPLETE** pending a repeat build with
   the installed-database-only assertion.
4. Selenium browser startup/navigation/DOM/download/shutdown: **NOT VERIFIED**.
5. Positive namespace/seccomp/SUID-or-user-namespace sandbox proof:
   **NOT VERIFIED**.
6. Runtime privilege, AppArmor, mount and process inventory: **NOT VERIFIED**.
7. Forced App termination and host orphan audit: **NOT VERIFIED**.
8. Home Assistant App discovery and `config.yaml` acceptance by Supervisor
   `2026.08.0`: **HA OS VERIFIED**.
9. Python files compiled successfully; authoritative `config.yaml` and fixture
   `config.json` parsed and matched on the authoring host: **LOCALLY TESTED**.
10. `static_verify.py` passed all included policy assertions:
    **LOCALLY TESTED / STATICALLY VERIFIED**.

The build-verification defect is not treated as a failed Chromium or sandbox
experiment. The final decision remains `NOT TESTED` because no relevant target
runtime test ran.

## 15. Security deviations

No intentional deviation from the Phase 2A-1 security rules was introduced in
the PoC design:

- no credential input, placeholder credential, CEZ host or CEZ login flow;
- no cookies, account screenshots, authenticated DOM or account data;
- no sandbox weakening;
- no privileged mode or prohibited capability;
- no runtime executable dependency download;
- no Selenium telemetry;
- no Home Assistant, Supervisor, auth or Docker API access;
- no host filesystem map or published port.

The browser test is constrained to a loopback synthetic server. Chromium
background networking is disabled, non-loopback DNS is mapped to failure, and
Chrome performance logs are audited; an observed non-synthetic request URL
fails the probe. These controls are only **DESIGN VERIFIED**. They are not a
production egress boundary and do not prove denial of arbitrary direct sockets.

The absence of runtime evidence is recorded as uncertainty, not as compliance.
No security property that depends on Linux, Supervisor or HA OS is claimed.

## 16. Blocking findings

The following findings block Phase 2A-1 `PASS`, Phase 2A-1
`PASS WITH CONDITIONS`, and entry into Phase 2A-2:

1. The disposable image has not completed building in the approved HA OS amd64
   Supervisor environment; the corrected assertion requires a repeat build.
2. Chromium has not run as effective UID/GID `2000:2000` in that environment.
3. The layer 1 and seccomp-BPF sandbox have not been positively verified there.
4. Effective capabilities, AppArmor status, namespace layout, mounts and network
   mode have not been inspected there.
5. Required `/tmp` and `/dev/shm` sizes have not been measured there.
6. Normal, exception, timeout and forced-termination cleanup have not all been
   demonstrated without orphan processes.
7. Resource use has not been measured there.

No prohibited capability requirement was discovered. That statement is limited
to static design; it is not experimental proof that none will be needed.

## Evidence inventory

| Evidence | Result | Classification |
| --- | --- | --- |
| Local App discovery and authoritative `config.yaml` acceptance | PASS on Supervisor `2026.08.0` | HA OS VERIFIED |
| Base image pull | PASS | HA OS VERIFIED for target build attempt 1 |
| Chromium, ChromeDriver, Python, Selenium and locked dependency installation | PASS | HA OS VERIFIED for target build attempt 1 |
| Completed image and Chromium runtime | FAIL at obsolete version assertion; runtime not reached | NOT VERIFIED |
| `poc/phase2a-runtime/config.yaml` and `config.json` parsed and compared | PASS | LOCALLY TESTED |
| `poc/phase2a-runtime/static_verify.py` | PASS | LOCALLY TESTED / STATICALLY VERIFIED |
| `python -m py_compile` for both Python files | PASS | LOCALLY TESTED |
| `git status` branch check | `phase2a/runtime-verification` | LOCALLY TESTED |
| Direct Alpine package metadata retrieval | Matching browser/driver `152.0.7977.82-r0`, x86_64, same origin and commit | STATICALLY VERIFIED |
| Docker/Podman/nerdctl/WSL environment inventory | No usable Linux container runtime | LOCALLY TESTED |
| HA OS App runtime log | Not available because the image did not complete | BLOCKED |

The local Python compilation created only ignored bytecode cache files; those
files were removed immediately and are not part of the proposed repository
diff.

## Required target run before reassessment

- [x] Record exact HA OS, Supervisor, Home Assistant and machine architecture.
- [x] Confirm local App discovery and `config.yaml` acceptance.
- [ ] Copy only `config.yaml`, `Dockerfile`, `requirements.lock` and
      `runtime_probe.py` to the local Apps area for the repeat attempt.
- [ ] Repeat the build on `linux/amd64` and retain full build output and final
      image digest.
- [ ] Confirm the installed Chromium/ChromeDriver/Selenium versions from the
      probe output.
- [ ] Inspect the effective deployed App configuration, mounts, AppArmor,
      network/PID/IPC modes and capabilities.
- [ ] Run the synthetic probe and retain its complete JSON output and exit code.
- [ ] Confirm `sandbox.verified: true` with process-level evidence.
- [ ] Review `/tmp`, `/dev/shm`, RSS, CPU, startup, process and disk values.
- [ ] Execute a separately reviewed forced-termination test and host-side orphan
      process audit.
- [ ] Repeat with the exact production-candidate base/package versions before
      Phase 2B approval.

## Phase 2A-1 Decision

NOT TESTED
