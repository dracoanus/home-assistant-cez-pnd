# CEZ PND Collector Runtime Gate

This experimental Home Assistant App pulls the prebuilt public image
`ghcr.io/dracoanus/home-assistant-cez-pnd-collector-runtime:0.1.0`.
Supervisor does not build Chromium or Python during installation.

The image runs the existing offline runtime smoke test. It contains no CEZ
host, credential, cookie, account identifier, or authentication behavior. The
App requests no port, mount, device, API permission, host namespace, privileged
capability, or full access. AppArmor remains enabled.

## Installation

1. In Home Assistant, open **Settings -> Apps -> App Store -> Repositories**.
2. Add `https://github.com/dracoanus/home-assistant-cez-pnd`.
3. Select **CEZ PND Collector Runtime Gate** from the App Store and install it.
4. Verify Supervisor pulls the prebuilt image rather than starting a local
   image build.
5. Start the App manually and retain its final JSON log.

The runtime gate passes only when the ordered offline functional checks,
renderer sandbox verification, and bounded cleanup all pass without a security
deviation.

Do not add a local Dockerfile, sandbox-disabling flag, capability, host network,
mount, or device to make this gate pass.
