# Home Assistant Debian Collector runtime gate

This experimental Home Assistant App contains only an authoritative
`config.yaml`. Its `image` and `version` fields instruct Supervisor to pull the
prebuilt public GHCR image
`ghcr.io/dracoanus/home-assistant-cez-pnd-collector-runtime:0.1.0`.
Supervisor must not build Chromium or Python locally for this App.

The image runs the existing offline `smoke_test.py`. It contains no CEZ host,
credential, cookie, account identifier or authentication behavior. The App has
no port, mount, device, API permission, host namespace, privileged capability
or full-access request. AppArmor remains enabled.

## HA OS test installation

1. Publish reviewed tag `collector-runtime-v0.1.0` through the repository
   workflow and make the resulting GHCR package public.
2. Record the workflow's `immutable_reference` digest before installation.
3. Copy this directory to
   `/addons/cez_pnd_collector_runtime_gate/` on the HA OS host. The directory
   must contain `config.yaml` and may contain this README; it must not contain a
   Dockerfile.
4. Refresh the local App store, install **CEZ PND Collector Runtime Gate**, and
   verify Supervisor reports an image pull rather than a local build.
5. Start the App once and retain its final JSON log.
6. Require all ordered functional milestones through
   `loopback_dom_verified`, followed by `renderer_sandbox_verified`.
7. Require `sandbox.verified=true`, at least one renderer, UID/GID 2000,
   `NoNewPrivs=1`, `Seccomp=2`, zero effective capabilities, separate
   user/PID/network namespaces, no forbidden arguments,
   `cleanup_verified=true`, no orphan Chromium PIDs, and overall
   `passed=true`.
8. Compare the pulled image digest reported by the target with the workflow's
   recorded immutable reference. Any mismatch or missing positive evidence is
   a failed gate.

Do not add a local Dockerfile, sandbox-disabling flag, capability, host network,
mount or device to make this gate pass.

