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

Five target attempts now provide **HA OS VERIFIED** evidence for App discovery,
manifest acceptance, image construction and four runtime executions. Runtime
attempt 3 positively verified Chromium sandboxing and cleanup without a
security deviation. Runtime attempt 4 identifies the functional failure
boundary and a separate process-snapshot lifecycle race. Functional execution
remains unresolved and keeps the overall result false.

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

## Target runtime attempt 1

After the installed-package verification fix, the image built, installed and
started successfully on Home Assistant OS `18.2`, Supervisor `2026.08.0`, Home
Assistant `2026.9.0`, kernel `6.18.39-haos`, `amd64` / `qemux86-64`.

The probe returned:

| Result | Value |
| --- | --- |
| Overall `passed` | `false` |
| `cleanup_verified` | `false` |
| `sandbox.verified` | `false` |

The process evidence nevertheless positively established the following facts:

- ChromeDriver and every observed Chromium process used effective UID/GID
  `2000:2000`.
- No prohibited sandbox-disabling argument supplied by the probe was observed.
- Renderer processes were present with `NoNewPrivs: 1` and `Seccomp: 2`.
- Sandboxed child processes occupied additional user, PID and network
  namespaces.
- The App declared no extra Linux capability.

The reported `renderer_count: 0` was a probe aggregation defect. The evaluator
read only the `normal` case, whose action failed before its final process data
was stored, while the valid renderer snapshot belonged to the `timeout` case.
Likewise, the two `chrome_sandbox_page_*: false` values represented missing
action output converted through `bool(None)`, not a negative observation from
Chromium.

The normal case also navigated away from the synthetic renderer to
`chrome://sandbox` before recording its final snapshot. That internal page is
no longer used as authoritative evidence. The corrected probe captures process
state before, after and on failure of each action, selects the strongest
same-snapshot evidence across all cases, and requires renderer namespace
isolation plus `NoNewPrivs: 1` and `Seccomp: 2`.

The observed `--no-zygote-sandbox` argument was generated by Chromium on a
`--type=zygote` process, not supplied by this PoC. Chromium upstream documents
this as the unsandboxed zygote used to fork processes that apply their own
custom sandbox later. The corrected probe permits this internal flag only on a
zygote and still verifies the resulting renderer sandbox independently. Any
occurrence on another process type fails closed. Upstream evidence:

- <https://chromium.googlesource.com/chromium/src/+/HEAD/sandbox/policy/switches.cc>
- <https://chromium.googlesource.com/chromium/src.git/+/f2f6fabd25926d360ec58fd34deb28c7017906d8%5E%21/>

The `InvalidSessionIdException` is not yet conclusively attributed to one
kernel or Chromium failure. The first normal failure may have occurred during
the internal-page transition; the following case may also have experienced
resource pressure from unreaped processes. Other live possibilities include
`/dev/shm` exhaustion, an OOM kill, an AppArmor denial or a Chromium defect.
The corrected probe records action milestones, ChromeDriver's return code and
verbose log tail, `/dev/shm` state and process evidence on exceptions so the
repeat run can distinguish these causes without adding privilege.

## Target runtime attempt 2

The hardened probe was run again on the same HA OS target. Chromium
`152.0.7977.82` and ChromeDriver `152.0.7977.82` started as UID/GID
`2000:2000`. The captured `renderer_discovery_timeout` snapshot visibly
contained renderer PIDs `432`, `443`, `446` and `516`. Those renderers had
`NoNewPrivs: 1`, `Seccomp: 2`, effective UID/GID `2000:2000`, and user, PID and
network namespace identifiers distinct from the browser process. Forbidden
sandbox arguments were absent and the App still declared no additional Linux
capability.

Cleanup succeeded in this run: `cleanup_verified` was `true` and every
`orphan_pids_after_cleanup` list was empty. Peak observed aggregate PSS was
approximately `394489 KiB`.

| Attempt 2 result | Value | Interpretation |
| --- | --- | --- |
| Overall `passed` | `false` | Functional and aggregate sandbox gates did not pass |
| Functional execution | `false` | DevTools connection was lost |
| `cleanup_verified` | `true` | All tracked cases cleaned up |
| `orphan_pids_after_cleanup` | `[]` | No tracked orphan remained |
| `sandbox.verified` | `false` | Invalid negative result due to renderer classification defect |

The snapshot nevertheless reported `renderer_count: 0`. This is a confirmed
probe classification defect. `/proc/<pid>/cmdline` is NUL-separated, and the
old reader correctly retained its actual fields. Chromium had rewritten each
child's Linux process title into one field containing the executable and
space-separated switches. The old classifier then incorrectly tested whether
the list contained an element exactly equal to `--type=renderer`; it did not
inspect switches inside the single process-title field.

Chromium upstream explains both parts of this behavior. Its Linux
`SetProcessTitleFromCommandLine()` constructs one string from all command-line
arguments because `setproctitle()` cannot retain them separately. The Linux
implementation then overwrites the original argv/environment memory with that
single replacement title, which is what the kernel exposes through
`/proc/<pid>/cmdline`:

- <https://chromium.googlesource.com/chromium/src/base/+/refs/heads/main/process/set_process_title_linux.h>
- <https://chromium.googlesource.com/chromium/src/+/refs/tags/124.0.6367.29/base/process/set_process_title.cc>
- <https://chromium.googlesource.com/experimental/chromium/src/+/HEAD/base/process/set_process_title_linux.cc>

The parser now accepts raw bytes, preserves the kernel's NUL fields and
termination status, and separately extracts switch tokens for classification.
All renderer, zygote and forbidden-argument checks use that common classifier.
Malformed non-NUL-terminated evidence fails closed. The former
`startup_timeout` label was also misleading: Selenium and Chromium had already
started, and the probe did not raise a startup failure. It is now named
`renderer_discovery_timeout`, while `webdriver_started` and renderer discovery
are reported independently.

Functional execution still failed with `InvalidSessionIdException`, "session
deleted as the browser has closed the connection", and "not connected to
DevTools". The available evidence proves that WebDriver, Chromium and renderers
started and that cleanup ran only after the action failure. It therefore rules
out initial startup failure and premature probe cleanup. The error establishes
loss of the browser/DevTools control channel but does not identify why it was
lost. The complete ChromeDriver/Chromium log lines, action milestone reached,
process disappearance/return-code sequence, `/dev/shm` values, OOM evidence and
AppArmor audit result are not present in the retained repository evidence.
Chromium crash, renderer crash, ChromeDriver failure, `/dev/shm` exhaustion,
OOM, AppArmor denial, sandbox/namespace interaction and scenario-specific
behavior therefore remain **OPEN / NEEDS VERIFICATION** where applicable.
Chromium's ChromeDriver source defines "not connected to DevTools" as a
disconnected DevTools socket and notes browser crash, closed connection or a
DevTools availability policy change as examples; it does not distinguish them
without surrounding diagnostics:
<https://chromium.googlesource.com/chromium/src/+/main/chrome/test/chromedriver/chrome/devtools_client_impl.cc>.

## Target runtime attempt 3

The NUL-aware probe resolved process classification on the HA OS target. The
latest aggregate result was:

| Result | Value | Classification |
| --- | --- | --- |
| `sandbox.verified` | `true` | CONFIRMED |
| `renderer_count` | `3` | CONFIRMED |
| `cleanup_verified` | `true` | CONFIRMED |
| `security_deviations` | `[]` | CONFIRMED |
| `functional_cases_passed` | `false` | CONFIRMED |
| Overall `passed` | `false` | CONFIRMED |

This run closes the renderer classification finding. Matching Chromium and
ChromeDriver `152.0.7977.82-r0`, runtime UID/GID `2000:2000`, renderer
discovery, renderer seccomp and `NoNewPrivs`, separate user/PID/network
namespaces, forbidden-argument absence, successful cleanup, lack of persistent
storage and non-exhausted `/dev/shm` are **CONFIRMED** for this target run. No
security relaxation was required.

The retained evidence available for this analysis does not include the
per-case `cases` object, its `action_progress`, exception object, verbose
ChromeDriver log tail, process snapshots, return code or exact `/dev/shm`
numbers. Consequently, the exact failed case and last successful action
milestone are **OPEN / NEEDS VERIFICATION**. It is also **OPEN / NEEDS
VERIFICATION** whether the immediate DevTools disconnect seen in prior runs
recurred in the same case and at the same milestone.

The aggregate result proves only that at least one action did not set
`action_passed: true`. It does not distinguish normal, Selenium-exception or
timeout cases. Browser or renderer crash, ChromeDriver failure, Selenium timeout
interaction, scenario design, OOM, AppArmor and namespace interaction must not
be inferred from that aggregate bit. `/dev/shm` exhaustion is not supported by
this run because the captured state did not show exhaustion.

To prevent loss of the decisive fields in another large JSON result, the probe
now produces a compact `functional_failures` list. For each failed case it
records WebDriver startup, renderer discovery, last action milestone, exact
exception, browser and renderer PIDs present in the `action_error` snapshot,
ChromeDriver return code before cleanup and cleanup status. This is diagnostic
only; the existing functional and fail-closed security gates are unchanged.

## Target runtime attempt 4

The per-case diagnostics from the latest HA OS run establish the first
behavioral difference after renderer discovery:

| Case | First operation after renderer discovery | Result |
| --- | --- | --- |
| `normal` | `driver.get(base_url)` | `InvalidSessionIdException` before `after_synthetic_navigation` |
| `selenium_exception` | `driver.get(base_url)` | Same disconnect before `after_synthetic_navigation` |
| `timeout` | `set_script_timeout(1)`, then `execute_async_script("void 0;")` on the initial document | Remained operational and provided four renderer processes |

For both failing cases, `webdriver_started` is true, renderer discovery was
observed during the startup window, and the last milestone is
`before_synthetic_navigation`. At the action-error snapshot no renderer PID
remained, while ChromeDriver itself still had return code `null`. Cleanup then
succeeded. It is therefore **CONFIRMED** that the first `driver.get()` command
is the failure boundary and that cleanup did not run before the failure. It is
also **CONFIRMED** that the timeout scenario differs by issuing no navigation
command.

The best-supported interpretation is that Chromium's browser/renderer or
DevTools connection disappeared while ChromeDriver was still serving the
navigation request. This is **SUPPORTED** by the empty renderer set at the
error snapshot and ChromeDriver's still-running state. The
`InvalidSessionIdException` and "Unable to receive message from renderer" text
are consequences of that loss, not its root cause.

The retained evidence provided for this analysis does not contain the actual
ChromeDriver verbose-log tail, Chromium stderr, browser PID at each milestone,
process exit status or signal, kernel OOM record, or AppArmor audit record.
Consequently, a Chromium/browser crash, renderer crash, DevTools transport
failure, OOM action, AppArmor denial, namespace interaction, or Chromium 152
defect is **OPEN / NEEDS VERIFICATION**. `/dev/shm` exhaustion is not supported
because exhaustion was not observed. Early cleanup and WebDriver startup
failure are contradicted by the recorded sequence.

The same run captured four renderers that met UID/GID, seccomp,
`NoNewPrivs`, namespace and forbidden-argument requirements. Two additional
Chromium identities, PIDs `516` and `526`, had an empty command line,
`cmdline_complete: false`, `VmRSS: 0`, unavailable PSS and disappearing
namespace entries; they were reparented to PID 1. This combination is
**SUPPORTED** as a process-exit/zombie race during the multi-file `/proc`
snapshot. Linux documents that a zombie has an empty `/proc/<pid>/cmdline`, and
that orphaned children are adopted by init or a subreaper:

- <https://man7.org/linux/man-pages/man5/proc_pid_cmdline.5.html>
- <https://man7.org/linux/man-pages/man2/wait.2.html>

Because `init: false` and the image `CMD` start `runtime_probe.py` directly,
the Python probe is the container's PID 1 and adopts orphaned Chromium children.
Reparenting therefore shows that each process's former immediate parent exited;
it does not by itself prove why the Chromium process tree or DevTools connection
disappeared. The temporal correlation is **SUPPORTED**, while causation is
**OPEN / NEEDS VERIFICATION**.

The raw run's `sandbox.verified: false` is **SUPPORTED** as a snapshot-lifecycle
artifact rather than evidence that the four live renderers lacked sandboxing.
The old probe correctly failed closed because it could not distinguish an
exiting identity from an unreadable live process. The revised probe retains all
records and excludes only an identity whose PID plus start time is positively
shown to have entered an exit state, disappeared, or been replaced after
collection. A still-live or ambiguous identity with incomplete command-line,
namespace, status or PSS evidence remains in the verdict and fails closed.
Another HA OS run is required to validate that distinction on the target.

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
- Chromium runtime execution on that target: **HA OS VERIFIED; probe failed**.

## 5. Chromium version and availability

| Property | Finding | Classification |
| --- | --- | --- |
| Package | Alpine `chromium` | STATICALLY VERIFIED |
| Version pinned in PoC | `152.0.7977.82-r0` | STATICALLY VERIFIED |
| Repository | Alpine 3.24 `community` | STATICALLY VERIFIED |
| Architecture | `x86_64` | STATICALLY VERIFIED |
| Alpine source commit | `73650098eb2aa1baf6fe7b09586838990466235c` | STATICALLY VERIFIED |
| Package installation in target build layer | `152.0.7977.82-r0` installed | HA OS VERIFIED for build attempt 1 |
| Completed image / executable runtime | Image built and the probe started | HA OS VERIFIED; probe result FAIL |

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

The first target build stopped at its obsolete assertion. After correction, the
image completed and the probe reported executable versions during target
runtime attempt 1.

## 6. ChromeDriver version and compatibility

| Property | Finding | Classification |
| --- | --- | --- |
| Package | Alpine `chromium-chromedriver` | STATICALLY VERIFIED |
| Version pinned in PoC | `152.0.7977.82-r0` | STATICALLY VERIFIED |
| Repository / architecture | Alpine 3.24 `community` / `x86_64` | STATICALLY VERIFIED |
| Origin / source commit | `chromium` / `73650098eb2aa1baf6fe7b09586838990466235c` | STATICALLY VERIFIED |
| Installation in target build layer | Exact pinned ChromeDriver package installed | HA OS VERIFIED for build attempt 1 |
| Browser/driver compatibility | Sessions started, then two renderer connections failed | PARTIALLY HA OS VERIFIED; stability FAIL |

Evidence: <https://pkgs.alpinelinux.org/package/v3.24/community/x86_64/chromium-chromedriver>.

The Docker build asserts the exact installed package versions using `apk info
-e` against the installed package database with repository and network inputs
disabled. Selenium receives the explicit path `/usr/bin/chromedriver`;
Selenium Manager fallback is not used. `SE_OFFLINE=true`,
`SE_AVOID_BROWSER_DOWNLOAD=true`, and `SE_AVOID_STATS=true` are set in the
image. Browser, driver, Python `3.14.7-r1`, Selenium `4.48.0` and every locked
Python dependency installed successfully during target build attempt 1.
Runtime binary downloading is forbidden by construction and is checked
statically. Two offline runtime starts have executed on the target without a
runtime binary download.

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
| Effective UID/GID at probe entry | `2000:2000` | HA OS VERIFIED |
| Effective UID/GID of every observed Chromium process | `2000:2000` | HA OS VERIFIED for captured processes |

The final image declares `USER 2000:2000`. Target runtime process evidence
confirmed the intended effective identity for ChromeDriver and all captured
Chromium processes.

## 8. Chromium sandbox verification result

**HA OS VERIFIED / PASS for the sandbox mechanism in runtime attempt 3.** That
run returned `sandbox.verified: true` and `renderer_count: 3`; the process-title
classification issue is resolved. Attempt 4 again positively captured four
renderers meeting every renderer security property, but its aggregate gate
failed because two additional process identities became unreadable while the
snapshot was collected. The lifecycle-aware correction requires a target
repeat before the latest aggregate gate can be accepted.

The runtime evidence positively demonstrates:

1. Renderer processes existed.
2. Captured renderers had `/proc/<pid>/status` values `Seccomp: 2` and
   `NoNewPrivs: 1`, positively establishing an active seccomp filter and the
   no-new-privileges bit for those processes.
3. Captured sandboxed children used additional user, PID and network
   namespaces, positively establishing a namespace isolation layer in that
   snapshot.
4. Captured Chromium processes ran as UID/GID `2000:2000`.
5. Prohibited sandbox-disabling arguments were absent.

Attempts 2 through 4 establish that cleanup is reliable for normal, exception
and timeout paths in those runs. The evaluator reports `verified: true`
only when one internally consistent snapshot contains a browser and renderer
set where every renderer has all required namespace, seccomp and `NoNewPrivs`
properties, all Chromium processes are non-root, all command-line evidence is
derived from complete, losslessly decoded, NUL-terminated raw procfs data, no
forbidden argument exists, and the internal zygote flag appears only on a
zygote. Overall PASS additionally requires all actions and cleanup cases to
succeed; that functional condition did not pass in attempt 3.

The probe records user, PID, network, mount and IPC namespace identifiers for
each process. Container seccomp alone is not treated as proof of Chromium's
renderer sandbox. Chromium's own Linux sandbox status definitions are evidenced
by:

- <https://chromium.googlesource.com/chromium/src/+/HEAD/sandbox/policy/linux/sandbox_linux.h>
- <https://chromium.googlesource.com/chromium/src/+/4b74fa1307784d2fe83c3dad453874e7b3911331/chrome/browser/resources/sandbox_internals/sandbox_internals.js>
- <https://chromium.googlesource.com/chromium/src/+/0e94f26e8/docs/linux_sandboxing.md>

No sandbox-disabling flag is passed by the PoC. Static inspection and all
relevant runtime captures found none in the effective launch arguments. Attempt
3 positively passed the complete sandbox gate rather than relying on argument
absence alone. The lifecycle correction does not relax any renderer property:
only a positively exited PID identity is removed from the live-process set;
ambiguous or live incomplete evidence still prevents verification.

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

The first runtime produced process and filesystem observations, but the
available report does not include the exact `/tmp` and `/dev/shm` values needed
for sizing or for attributing the renderer disconnect. Later target evidence
states that `/dev/shm` was not observed exhausted. The probe records these
values even when a Selenium action raises.

- Appropriate `/tmp` size: **NOT VERIFIED**.
- Appropriate `/dev/shm` size: **NOT VERIFIED**.
- Supervisor tmpfs backing/mount behavior: **NOT VERIFIED**.
- Profile/download use of private `/tmp` directories: **DESIGN VERIFIED**;
  filesystem cleanup requires confirmation in the repeat run.

No size recommendation is made without measurements from the target.

## 12. Process cleanup results

**HA OS VERIFIED for attempt 2.** Chromium processes remained after every case
in attempt 1. After the bounded cleanup correction, attempt 2 reported
`cleanup_verified: true` and empty `orphan_pids_after_cleanup` lists.

The included probe has three cases:

| Case | Intended evidence | Current result |
| --- | --- | --- |
| Normal completion | Functional disconnect followed by complete cleanup | CLEANUP PASS; FUNCTION FAIL at synthetic navigation |
| Selenium exception | Functional disconnect followed by complete cleanup | CLEANUP PASS; FUNCTION FAIL at synthetic navigation |
| Selenium timeout | Complete cleanup after timeout path | CLEANUP PASS; operational renderer evidence captured |
| Forced Collector/App termination | Supervisor stop plus host-level before/after process audit | BLOCKED; target access required |

The original script tracked descendants by PID and only waited after
`driver.quit()`. It did not handle reparented Chromium processes, PID reuse,
failed WebDriver shutdown or zombie adoption by the Python PID 1 process.

The corrected cleanup records PID plus `/proc` start time, rediscovers new
Chromium/ChromeDriver processes outside the pre-case baseline, attempts normal
WebDriver and service shutdown, then sends SIGTERM and finally SIGKILL only to
same-UID tracked processes. It calls non-blocking `waitpid()` to reap adopted
children and fails if any tracked identity remains. These operations require no
additional capability or privilege.

Attempts 2 through 4 confirm this cleanup path for ordinary case completion and
handled exceptions. PIDs `516` and `526` becoming PPID 1 is consistent with
child adoption after their parent exited and with the probe's explicit reaping
role. It is temporally correlated with the DevTools disconnect but does not
establish its cause. These runs do not replace the separate host-side forced
App termination test.

Forced termination cannot be proven from inside a container after the container
has stopped. It requires a separately reviewed hold scenario and host/Supervisor
process observation on the actual target. That variant was not added because it
could not be safely validated here.

## 13. Resource measurements

The timeout snapshot reported summed RSS of approximately `1,077,064 KiB`.
That value is not a reliable unique-memory measurement because RSS is summed
across Chrome's browser, zygote, GPU, utility and renderer processes and counts
shared pages repeatedly. Processes leaked by earlier cases could also increase
system pressure even where they were not descendants included in the timeout
sum.

The corrected probe isolates each case from its pre-case process baseline and
reports both aggregate RSS and aggregate proportional set size (PSS) from
`/proc/<pid>/smaps_rollup`. PSS is the better estimate of the unique physical
footprint because shared pages are divided among the processes that map them.
The result also records whether PSS was available for every captured process,
so an incomplete reading cannot be mistaken for a small footprint. Linux
kernel evidence: <https://docs.kernel.org/filesystems/proc.html>.

Reliable resource sizing remains **NOT VERIFIED** until a clean repeat run
reports complete PSS without stale processes.

Attempt 2 reported peak aggregate PSS of approximately `394489 KiB` (about
`385 MiB`) with successful per-case cleanup. This is a substantially better
process-set estimate than the earlier summed RSS. The retained summary does not
state whether `pss_complete` was true or include the per-process values, so final
sizing remains **OPEN / NEEDS VERIFICATION**.

Other required measurements remain **NOT VERIFIED**:

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

1. Build attempt 1 failed at the obsolete APK assertion; the corrected build
   subsequently completed.
2. Runtime attempt 4 confirms that `normal` and `selenium_exception` lose the
   browser/DevTools session on their first `driver.get(base_url)` command.
   The underlying reason for the browser/renderer disappearance remains open.
3. Attempt 1 left Chromium PIDs; attempt 2 passed cleanup without orphans.
4. Attempt 1 selected the wrong case. Attempt 2 captured renderers but classified
   Chromium's flattened Linux process title as one argument and therefore
   reported `renderer_count: 0`.
5. Attempt 3 resolved classification and positively passed the aggregate
   renderer sandbox gate with three renderers.
6. Attempt 4 captured four compliant renderers but failed aggregate command-line
   completeness while PIDs `516` and `526` appeared to exit during collection.
   The lifecycle-aware correction requires a target repeat.
7. Effective capabilities and AppArmor enforcement still require explicit
   target inspection; no extra capability was declared.
8. Forced App termination and host orphan audit remain **NOT VERIFIED**.
9. **BLOCKED locally:** no local Linux container engine or WSL distribution.

Attempt 4 identifies the functional boundary and confirms cleanup, but does not
identify the underlying navigation-triggered process failure. It does not
permit entry into Phase 2A-2.

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

Positive runtime observations are recorded narrowly. Unmeasured or
inconsistently aggregated properties remain uncertainty rather than compliance.

## 16. Blocking findings

The following findings block Phase 2A-1 `PASS`, Phase 2A-1
`PASS WITH CONDITIONS`, and entry into Phase 2A-2:

1. The `normal` and `selenium_exception` cases fail at the first synthetic
   navigation, so all functional cases have not passed on the target.
2. The cause of the browser/renderer or DevTools disappearance during
   navigation remains **OPEN / NEEDS VERIFICATION**.
3. The lifecycle-aware distinction between positively exited and unreadable
   live Chromium processes has not yet run on HA OS.
4. Effective capabilities, AppArmor status, mounts and Supervisor namespace
   configuration have not been fully inspected.
5. Required `/tmp` and `/dev/shm` sizes have not been established, although
   exhaustion was not observed.
6. Complete PSS evidence and final resource sizing have not been established.
7. Forced App termination and host-side orphan auditing have not been performed.

No prohibited capability requirement was discovered. That statement is limited
to static design; it is not experimental proof that none will be needed.

## Evidence inventory

| Evidence | Result | Classification |
| --- | --- | --- |
| Local App discovery and authoritative `config.yaml` acceptance | PASS on Supervisor `2026.08.0` | HA OS VERIFIED |
| Base image pull | PASS | HA OS VERIFIED for target build attempt 1 |
| Chromium, ChromeDriver, Python, Selenium and locked dependency installation | PASS | HA OS VERIFIED for target build attempt 1 |
| Completed image and App start | PASS after APK assertion fix | HA OS VERIFIED |
| Normal synthetic action | Renderer disconnected | FAIL |
| Expected Selenium-exception action | Renderer disconnected | FAIL |
| Expected timeout action | Ran and captured renderer processes | PARTIAL PASS |
| Captured renderer `Seccomp: 2` / `NoNewPrivs: 1` | Observed | HA OS VERIFIED for captured renderers |
| Captured renderer namespace separation | Additional user/PID/network namespaces observed | HA OS VERIFIED for captured snapshot |
| UID/GID `2000:2000` | Observed for ChromeDriver and Chromium | HA OS VERIFIED for captured processes |
| Cleanup attempt 1 | Chromium PIDs remained after all cases | FAIL |
| Cleanup attempt 2 | `cleanup_verified: true`; no orphan PIDs | HA OS VERIFIED |
| Original aggregate sandbox result | False due to wrong-case/missing-evidence aggregation | INVALID AS A NEGATIVE SANDBOX CONCLUSION |
| Attempt 2 aggregate renderer count | Zero despite visible renderers because Chromium flattened its process title | INVALID AS A NEGATIVE SANDBOX CONCLUSION |
| Attempt 2 peak aggregate PSS | Approximately `394489 KiB` | HA OS OBSERVED; completeness OPEN |
| `poc/phase2a-runtime/config.yaml` and `config.json` parsed and compared | PASS | LOCALLY TESTED |
| `poc/phase2a-runtime/static_verify.py` | PASS | LOCALLY TESTED / STATICALLY VERIFIED |
| `python -m py_compile` for both Python files | PASS | LOCALLY TESTED |
| `git status` branch check | `phase2a/runtime-verification` | LOCALLY TESTED |
| Direct Alpine package metadata retrieval | Matching browser/driver `152.0.7977.82-r0`, x86_64, same origin and commit | STATICALLY VERIFIED |
| Docker/Podman/nerdctl/WSL environment inventory | No usable Linux container runtime | LOCALLY TESTED |
| Attempt 3 renderer classification | Three renderers | CONFIRMED / HA OS VERIFIED |
| Attempt 3 sandbox | `sandbox.verified: true` | CONFIRMED / HA OS VERIFIED |
| Attempt 3 cleanup | `cleanup_verified: true` | CONFIRMED / HA OS VERIFIED |
| Attempt 3 security deviations | Empty | CONFIRMED / HA OS VERIFIED |
| Attempt 3 functional result | `functional_cases_passed: false`; exact case absent from retained evidence | CONFIRMED aggregate; case OPEN |
| Attempt 4 normal action | Failed during first `driver.get(base_url)` | CONFIRMED / HA OS VERIFIED |
| Attempt 4 expected-exception action | Failed during first `driver.get(base_url)` before the intended missing-element exception | CONFIRMED / HA OS VERIFIED |
| Attempt 4 timeout action | Stayed operational and supplied four renderer processes | CONFIRMED / HA OS VERIFIED |
| Attempt 4 renderer properties | Four renderers passed UID/GID, seccomp, `NoNewPrivs` and namespace checks | CONFIRMED / HA OS VERIFIED |
| Attempt 4 incomplete PIDs | PIDs `516`/`526`: empty cmdline, zero RSS, unavailable PSS/namespaces, PPID 1 | CONFIRMED observations; exit race SUPPORTED |
| Lifecycle-aware snapshot policy | Excludes only positively exited PID/start-time identities; live/unknown remains fail closed | LOCALLY TESTED / TARGET REPEAT REQUIRED |

The local Python compilation created only ignored bytecode cache files; those
files were removed immediately and are not part of the proposed repository
diff.

## Required target run before reassessment

- [x] Record exact HA OS, Supervisor, Home Assistant and machine architecture.
- [x] Confirm local App discovery and `config.yaml` acceptance.
- [x] Build and start the image on the target after the APK assertion fix.
- [x] Confirm the installed Chromium/ChromeDriver/Selenium versions from the
      target build and probe output.
- [x] Deploy the NUL-aware corrected probe using only `config.yaml`, `Dockerfile`,
      `requirements.lock` and `runtime_probe.py`.
- [ ] Inspect the effective deployed App configuration, mounts, AppArmor,
      network/PID/IPC modes and capabilities.
- [ ] Run the lifecycle-aware probe again and retain its complete JSON output
      and exit code, including verbose driver/browser logs and all action
      milestones.
- [x] Confirm `sandbox.verified: true` with process-level evidence.
- [ ] Review `/tmp`, `/dev/shm`, RSS, CPU, startup, process and disk values.
- [ ] Execute a separately reviewed forced-termination test and host-side orphan
      process audit.
- [ ] Repeat with the exact production-candidate base/package versions before
      Phase 2B approval.

## Phase 2A-1 Decision

FAIL — NAVIGATION FAILURE ROOT CAUSE AND LIFECYCLE-AWARE REPEAT REQUIRED
