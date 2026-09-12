# Installation

This guide installs the Collector App first and the Home Assistant integration
second. The Collector stores CEZ credentials; the integration does not.

## 1. Install the Collector App

1. Open **Settings → Apps → App Store → Repositories**.
2. Add `https://github.com/dracoanus/home-assistant-cez-pnd`.
3. Install **CEZ PND Collector** and open its configuration.
4. Enter the required private options described in [Configuration](configuration.md).
5. Start the App and inspect its log. A healthy startup emits `service_started`
   and `sync_worker_started` when scheduled synchronization is enabled.

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

| Field | What to enter |
| --- | --- |
| Collector HTTPS URL | The App internal HTTPS address, normally the default offered by the form. |
| Opaque meter ID | The configured `meter_id`, formatted like `mtr_<generated-id>`. |
| Collector API token | The plaintext limited token retained outside App options. |
| Collector CA certificate | PEM certificate of the CA that issued the Collector certificate. |

Do not enter CEZ username, CEZ password, EAN or ELM here. Home Assistant Core
never receives them. TLS verification is mandatory.

## 4. Verify the result

After setup, check Collector health, source status, data timestamp, last sync
attempt/success, completeness, valid/missing counts and the grid import entity.
The Collector returns `401` for absent or wrong bearer tokens and `200` for a
valid token; the setup flow validates this without displaying secrets.

Continue with [Energy Dashboard](energy-dashboard.md) or
[Troubleshooting](troubleshooting.md).
