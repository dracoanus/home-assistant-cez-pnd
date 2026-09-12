# Collector service

This directory contains the CEZ PND Collector service. It authenticates to CEZ
inside the Collector boundary, validates bounded CEZ exports, stores normalized
intervals in SQLite and exposes a limited local HTTPS API to Home Assistant.

The three supported routes are `GET /api/v1/health`, `GET /api/v1/status` and
`GET /api/v1/measurements`. All require the scoped bearer token. The service
does not expose browser, shell, file, CEZ-login or arbitrary-URL control.

Automatic synchronization stores normalized data only; raw CEZ CSV is not
persisted. Current-day work runs hourly and historical backfill/correction runs
every six hours. See [architecture](../docs/architecture.md),
[API contract](../docs/collector-api-contract.md) and
[maintainer context](../docs/development/maintainer-context.md).

For local validation:

```bash
PYTHONPATH=collector python -m unittest discover -s collector/tests
python collector/static_verify.py
python -m compileall -q collector/collector_service collector/tests
```
