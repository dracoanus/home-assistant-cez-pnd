# Minimal Collector runtime experiment

This directory evaluates a small, production-oriented Chromium/Selenium
runtime through fast local Docker iteration. It contains no CEZ host, login,
credential, cookie, account identifier or production Collector behavior. The
Phase 2A diagnostic probe remains a separate frozen evidence artifact.

## Proposed architecture

The experiment uses one non-root Python process under `tini`. Python starts a
loopback-only HTTP server and then creates one Selenium session through the
distribution-matched ChromeDriver and Chromium packages. It performs only:

1. WebDriver session creation;
2. explicit `about:blank` navigation;
3. `return 1` JavaScript execution;
4. an inline `data:text/html` navigation and DOM check;
5. loopback HTTP navigation and DOM check;
6. normal WebDriver, ChromeDriver and server shutdown.

The runtime has no published port, host mount or device. The local Compose
profile uses an isolated network namespace with no external interface, a
read-only root filesystem, private temporary storage, a private `/dev/shm`, UID
and GID `2000:2000`, all Linux capabilities dropped and container-level
`no-new-privileges` enabled.

The Dockerfile uses a glibc-based Debian Bookworm Python image rather than the
Alpine/musl Home Assistant base. Chromium `152.0.7977.82-1~deb12u1` and the
matching `chromium-driver` are installed from timestamped Debian snapshots.
Selenium `4.48.0` and its complete dependency set are hash locked. Selenium
Manager downloads and telemetry are disabled.

The browser packages and Python dependencies are installed before
`smoke_test.py` is copied. Rebuilding after a source-only change therefore
reuses the expensive browser and dependency layers.

The first Synology build after the sandbox-package correction stopped at
`groupadd`. The Dockerfile's restricted `PATH` excludes `/usr/sbin`, and the
slim base does not provide an interface contract guaranteeing the Shadow
account-management tools. The runtime now explicitly installs and verifies
`passwd=1:4.13+dfsg1-1+deb12u2`, which supplies both `/usr/sbin/groupadd` and
`/usr/sbin/useradd`, and invokes them by absolute path. The account uses
`/bin/false` as its non-login shell, avoiding another dependency on an optional
`/usr/sbin/nologin` path.

## Dockerfile executable audit

| Executable | Provider and guarantee |
| --- | --- |
| `/bin/sh`, `printf`, `test`, `command` | Shell and builtins supplied by the digest-pinned Debian/Python base |
| `apt-get` | APT supplied by the Debian slim base; already exercised successfully on Synology |
| `rm`, `chmod`, `install`, `stat`, `/bin/false` | `coreutils`, part of the digest-pinned Debian base; `install` and `stat` are also checked before use |
| `dpkg-query` | `dpkg` from the digest-pinned Debian base and checked before package validation |
| `/usr/local/bin/python` | Supplied by the digest-pinned official Python base |
| `/opt/collector-venv/bin/pip` | Created by `/usr/local/bin/python -m venv` and checked before package installation |
| `/usr/sbin/groupadd`, `/usr/sbin/useradd` | Explicitly installed from pinned `passwd=1:4.13+dfsg1-1+deb12u2` and checked before use |
| `/usr/bin/tini` | Explicitly installed from pinned `tini=0.19.0-1+b3` and checked before use |
| `/usr/bin/chromium` | Explicitly installed from the pinned `chromium` package and checked before runtime |
| `/usr/bin/chromedriver` | Explicitly installed from the matching pinned `chromium-driver` package and checked before runtime |

The static verifier parses every shell-form `RUN` instruction and rejects a
command without an audited provider. It also rejects removal of the pinned
`passwd` package, a return to PATH-dependent `groupadd`, and recombining cheap
validation or user creation with expensive installation layers.

## Expected build and startup improvement

The first local build still downloads and installs Chromium, ChromeDriver and
the locked Python wheels. Later source-only edits invalidate only the final
`COPY smoke_test.py` layer, so Docker should rebuild that layer without running
APT or pip again. Exact cold and warm build times remain to be measured on the
development Docker host.

APT installation, package/executable validation, hash-locked Python dependency
installation, user creation, and source copying are separate layers. Once an
expensive APT or pip layer finishes, a later validation or account-creation
failure can be corrected without downloading those dependencies again, as long
as the relevant preceding instruction and build context remain unchanged.

At runtime there is no X server, window manager, VNC server, noVNC frontend,
NGINX or general service supervisor. `tini` starts one Python process, which
starts one ChromeDriver and one Chromium process tree for the test. This should
start faster and use less memory than the jlesage GUI stack, but the claim
remains an estimate until local measurement. The estimated compressed image is
approximately `170–240 MiB`, compared with the measured registry layer sum of
approximately `390 MiB` for jlesage `v26.08.3` on amd64.

## Comparison

| Property | Frozen Alpine Phase 2A probe | This experiment | Mincka/jlesage control |
| --- | --- | --- | --- |
| Base | Home Assistant Alpine `3.24`, musl | Python/Debian Bookworm slim, glibc | jlesage GUI base on Alpine `3.24`, musl |
| Browser | Alpine Chromium `152.0.7977.82-r0` | Debian Chromium `152.0.7977.82-1~deb12u1` | Alpine Chromium `151.0.7922.173-r0` in `v26.08.3` |
| Driver | Matching Alpine ChromeDriver | Matching Debian ChromeDriver | Not included by the reference image |
| Display | New headless mode | New headless mode | X server, Openbox, VNC/noVNC and NGINX |
| GPU path | Headless path produced GPU `SIGSEGV` evidence | Default Debian headless path; result pending | Mesa/X11 path with `--ignore-gpu-blocklist` |
| Process model | Large diagnostic Python PID 1 | `tini` plus one small Python test | Init/process supervisor plus GUI and web services |
| Persistence | Temporary probe data | Temporary data only | `/config`, with Mincka remapping profile to `/data` and downloads to `/share` |
| Network | Loopback test plus browser request audit | Docker `network_mode: none`; loopback remains available | Ingress/VNC/debug ports and normal network access |
| Privilege | No additional capability | No capability; all capabilities dropped locally | Mincka requests `SYS_ADMIN` |
| Estimated compressed image | Not measured | Approximately 170–240 MiB; measure after build | Approximately 390 MiB for jlesage `v26.08.3` amd64 |

The jlesage image is a useful control because it demonstrates an Alpine
Chromium package running through an X11/Mesa path. It does not isolate the
Phase 2A failure: its browser version, graphical stack, process supervisor,
arguments and sandbox startup behavior differ from the headless Selenium
runtime.

## Mincka/jlesage sandbox implications

Mincka currently derives directly from `jlesage/chromium:v26.08.3`. Its Home
Assistant manifest requests `SYS_ADMIN` because the jlesage startup script runs
a setuid PID-namespace test. If that test fails, jlesage automatically adds
`--no-sandbox`. jlesage recommends either a tailored seccomp profile,
`SYS_ADMIN`, or privileged mode to permit its sandbox startup.

That behavior is incompatible with this project's security policy. We must not
use the jlesage image unchanged: both its `SYS_ADMIN` route and automatic
`--no-sandbox` fallback are blockers.

Chromium itself can use an unprivileged user-namespace layer together with
seccomp-BPF when the kernel and outer container policy permit the required
namespace operations. The successful Phase 2A HA OS renderer evidence already
demonstrates this mechanism without `SYS_ADMIN` on the target.

Debian packages the setuid helper separately as `chromium-sandbox`. Both
`chromium` and `chromium-common` recommend it; neither depends on it. The first
Synology build nevertheless found the package installed, so the former
assertion that it must be absent deliberately failed after the browser and
driver had installed successfully. The runtime now installs the helper at the
same exact version as Chromium and verifies its installed state plus the Debian
package's expected `root:root` ownership and mode `4755` at
`/usr/lib/chromium/chrome-sandbox`.

The local Compose profile enables container-level `no-new-privileges`. Linux
therefore prevents the helper's setuid bit from changing process credentials,
and all container capabilities are also dropped. Chromium must use its
unprivileged user-namespace sandbox path or fail closed. The actual path must
still be confirmed by the runtime test on each target; a failure must not be
bypassed with a forbidden argument or capability. Keeping the verified helper
makes the Debian package layout deterministic without granting it an effective
privilege transition under this Compose security profile.

Relevant source evidence:

- <https://github.com/mincka/ha-addons/blob/main/chromium/config.yaml>
- <https://github.com/mincka/ha-addons/blob/main/chromium/Dockerfile>
- <https://github.com/jlesage/docker-chromium/blob/v26.08.3/Dockerfile>
- <https://github.com/jlesage/docker-chromium/blob/v26.08.3/rootfs/etc/services.d/app/params>
- <https://github.com/jlesage/docker-chromium/blob/v26.08.3/src/check_pid_namespace/check_pid_namespace.c>
- <https://github.com/jlesage/docker-chromium/blob/v26.08.3/README.md#enable-usage-of-sandbox>
- <https://chromium.googlesource.com/chromium/src/+/main/sandbox/linux/README.md>
- <https://packages.debian.org/bookworm/chromium>
- <https://packages.debian.org/bookworm/chromium-driver>
- <https://packages.debian.org/bookworm/chromium-sandbox>
- <https://packages.debian.org/bookworm/amd64/passwd/filelist>
- <https://docs.kernel.org/userspace-api/no_new_privs.html>

## Fast local cycle

Run from this directory on an amd64 Docker host:

```text
python static_verify.py
docker compose build
docker compose run --rm collector-runtime
```

After changing only `smoke_test.py`, the second command pair should reuse the
browser and Python dependency layers:

```text
docker compose build
docker compose run --rm collector-runtime
```

Useful inspection commands are:

```text
docker image inspect cez-pnd-collector-runtime:local --format '{{.Size}}'
docker history cez-pnd-collector-runtime:local
docker compose config
```

The runtime command must not be changed to add `--privileged`, `--cap-add`, host
networking, host mounts or a relaxed seccomp profile merely to make the smoke
test pass.

## Prebuilt Home Assistant image path

After the local runtime passes and its sandbox model is reviewed, CI can build
the expensive runtime image once and publish an immutable versioned image to
GHCR, for example:

```text
ghcr.io/dracoanus/home-assistant-cez-pnd/collector-runtime:<version>
```

The release pipeline should build for approved architectures, generate an SBOM
and provenance, scan the image, record its manifest digest and never replace a
published tag. The future Home Assistant App manifest can reference that
prebuilt image instead of asking Supervisor to build Chromium during
installation. Supervisor then pulls the reviewed image layers; ordinary Python
source changes can be delivered as a new small top layer.

No Home Assistant manifest is created in this experiment. That work remains
outside Phase 2A-1 and requires separate review.

## Risks and blockers

- Local Docker and the HA OS Supervisor can apply different seccomp and
  AppArmor policies. Local success does not replace the final HA OS sandbox
  validation.
- The unprivileged namespace sandbox may be blocked by a particular Docker
  daemon, kernel or LSM policy. This is a fail-closed blocker, not grounds for
  `SYS_ADMIN` or `--no-sandbox`.
- Switching from Alpine/musl to Debian/glibc changes more than the GPU library,
  so a successful run narrows the architecture choice but does not identify the
  exact Alpine crash component.
- Debian's matched Chromium and driver packages are large and security updates
  require rebuilding and publishing a new pinned image.
- The image-size estimate must be replaced with measured compressed and
  unpacked sizes after the first local build.
- The eventual HA OS image must still prove renderer UID/GID, namespaces,
  seccomp, `NoNewPrivs`, cleanup and effective Supervisor isolation.

## Recommendation

Use the Debian/glibc experiment as the next runtime candidate. It keeps browser
and driver versions distribution-matched, removes the GUI/VNC stack, avoids the
jlesage automatic sandbox fallback and changes the libc/rendering environment
that produced the Alpine headless GPU crash. Keep Alpine as a comparison
candidate until the Debian runtime completes both local and HA OS checks. Do
not adopt Mincka/jlesage directly for the Collector because its current sandbox
startup requires an unacceptable capability or a forbidden fallback.
