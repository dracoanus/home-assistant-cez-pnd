# Offline Synology/Docker smoke profile

This profile validates only the Collector service container, HTTPS, bearer
authentication, synthetic API contract, missing-data semantics, and clean
shutdown. It does not contact CEZ and is not the production token-pairing or TLS
design.

The profile publishes no host port. The Collector and one-shot client share a
dedicated Docker network declared `internal: true`. Both run as `2000:2000`,
drop all capabilities, enable `no-new-privileges`, use read-only root
filesystems, and receive only narrow read-only test-material mounts.

## Recorded result

The real Synology/Docker run passed HTTPS startup, both negative authentication
checks, all three authenticated API requests, explicit missing-data semantics,
normal SIGTERM shutdown, container/network removal, and temporary-material
cleanup. The exact evidence and its scope are recorded in the
[Phase 2B validation document](../../docs/phase2b-collector-service-validation.md).

Synology warned that its kernel/cgroup configuration discarded `pids_limit`.
That control remains configured and is **OPEN / NEEDS VERIFICATION on HA OS**;
the successful Synology run is not evidence that the PID limit was enforced.

## Automated Docker Compose procedure

The Synology host must have Container Manager/Docker Compose and `openssl`.
The preparation script must run as root solely to create files owned by UID/GID
2000; it never prints the generated token.

From an SSH shell in the repository checkout:

```sh
cd collector/smoke
sudo sh ./run_smoke.sh
```

The script builds `collector/Dockerfile`, starts the Collector, runs the
one-shot HTTPS client, stops the Collector with a ten-second grace period,
requires both `service_started` and `service_stopped` log events, removes the
Compose project, and deletes the temporary token and TLS material.

The final client line must contain `"passed":true`. Expected HTTP statuses are:

| Request | Status |
| --- | --- |
| Unauthenticated health | `401` |
| Health with wrong token | `401` |
| Authenticated health | `200` |
| Authenticated status | `200` |
| Authenticated measurements | `200` |

## Synology Container Manager UI

For a UI-assisted run:

1. Place the complete repository checkout in a Synology shared folder.
2. Run `sudo sh collector/smoke/prepare_material.sh` over SSH. Container Manager
   cannot securely create the required UID-2000 private files itself.
3. In **Container Manager -> Project**, create a project from
   `collector/smoke/compose.yaml` and build/start it.
4. Wait for `smoke-client` to exit. Its log must contain `"passed":true` and
   the expected statuses above.
5. Stop the project with the normal Container Manager stop action. The
   Collector log must contain `"event":"service_stopped"`.
6. Delete the stopped project, then run
   `sudo sh collector/smoke/cleanup_material.sh` over SSH.

The automated shell procedure performs stricter cleanup verification and is
preferred when Docker Compose is available.

## Expected rebuild scope

The production service Dockerfile begins with the immutable, already-built
Collector Runtime Gate image. Chromium, ChromeDriver, Python, and Selenium are
therefore reused. A source edit invalidates only the late `COPY`, permission,
and metadata layers; it does not reinstall browser or Python packages.
