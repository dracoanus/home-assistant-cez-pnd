# Installation

This guide installs the Collector App first and the Home Assistant integration
second. The Collector stores CEZ credentials; the integration does not.

## 1. Install the Collector App

1. Open **Settings → Apps → App Store → Repositories**.
2. Add `https://github.com/dracoanus/home-assistant-cez-pnd`.
3. Install **CEZ PND Collector** and open its configuration.
4. Configure the CEZ credentials, EAN/ELM selector, history start and automatic
   synchronization described in [Configuration](configuration.md).
5. Start the App. It creates its managed local identity and publishes a
   discovery message for Home Assistant. A healthy startup emits
   `service_started` and `sync_worker_started` when scheduled synchronization
   is enabled.

The App uses a prebuilt image. Home Assistant does not build Chromium, Python
or Selenium during installation.

## 2. Install the HACS integration

1. In HACS, add `https://github.com/dracoanus/home-assistant-cez-pnd` as a
   custom integration repository.
2. Install **CEZ PND Collector**.
3. Restart Home Assistant. This is required after updating or first installing
   Python integration code.
4. Open **Settings → Devices & services → Add integration** and select
   **CEZ PND Collector**.

## 3. Configure the integration

1. Open **Settings → Devices & services**.
2. Locate the discovered **CEZ PND Collector** card and select **Configure**.
3. Confirm the guided pairing step. Home Assistant validates the Collector,
   creates the integration entry and stores only the scoped API token, opaque
   meter ID and CA certificate required for the local HTTPS connection.

Do not enter CEZ username, CEZ password, EAN or ELM here. Home Assistant Core
never receives them. TLS verification is mandatory.

Manual entry of the Collector URL, meter ID, API token and CA certificate is a
legacy/recovery path. It is not required for a normal managed installation.

## 4. Verify the result

After setup, check Collector health, source status, data timestamp, last sync
attempt/success, completeness, valid/missing counts and the grid import entity.
The Collector returns `401` for absent or wrong bearer tokens and `200` for a
valid token; guided pairing and setup validate this without displaying secrets.

Continue with [Energy Dashboard](energy-dashboard.md) or
[Troubleshooting](troubleshooting.md).
