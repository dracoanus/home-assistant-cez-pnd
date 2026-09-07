# Phase 2B Collector service offline validation

Status: **PASS** for the limited offline Collector service skeleton on the
Synology Docker control host. This evidence does not validate production
pairing, Home Assistant connectivity, CEZ behavior, credentials, browser
automation, or external network access.

## Validated scope

The real Synology/Docker Compose smoke execution built `collector/Dockerfile`,
started the service as UID/GID `2000:2000`, generated temporary test-only TLS
and bearer material, and exercised the API over HTTPS on an internal Docker
network.

| Check | Observed result |
| --- | --- |
| Overall smoke result | `passed=true` |
| HTTPS startup | PASS |
| Unauthenticated request | Rejected with `401` |
| Wrong bearer token | Rejected with `401` |
| Authenticated `GET /api/v1/health` | `200`, PASS |
| Authenticated `GET /api/v1/status` | `200`, PASS |
| Authenticated `GET /api/v1/measurements` | `200`, PASS |
| Missing measurement value | `value_kwh=null`, PASS |
| Missing measurement quality | `quality=missing`, PASS |
| Missing measurement converted to zero | No, PASS |

This positively validates the synthetic/offline API behavior exercised by the
profile. It does not turn test TLS or the test bearer-token generator into the
production pairing or TLS design.

## Lifecycle and cleanup evidence

- The service logged `service_started`.
- Normal Compose stop delivered SIGTERM and completed successfully.
- The service logged `service_stopped`.
- The Collector container was removed.
- The internal smoke network was removed.
- Temporary TLS and bearer-token material was removed.
- The runner ended with `PASS: Collector stopped cleanly and the temporary
  material was removed.`

No generated certificate, private key, bearer token, verifier, runtime output,
or container artifact is retained in this repository.

## Synology PID-limit limitation

Synology emitted the following warning during the successful run:

> Your kernel does not support PIDs limit capabilities or the cgroup is not
> mounted. PIDs limit discarded.

Classification: **OPEN / NEEDS VERIFICATION on HA OS**. The Synology control
host did not enforce the Compose `pids_limit`, so this run supplies no evidence
that the configured Collector or smoke-client PID ceilings were effective.
The intended limit remains present and must not be removed or weakened. Its
effective cgroup enforcement, configured value, and fail-safe behavior must be
verified independently in the actual HA OS App environment before production
runtime acceptance.

## Decision

The limited Phase 2B Collector service skeleton has passed its offline
Synology container/API gate. This is sufficient evidence to commit the offline
skeleton for review. It does not close the remaining Phase 2B production
decisions, authorize CEZ access, start browser automation, or establish that
the service is production ready.
