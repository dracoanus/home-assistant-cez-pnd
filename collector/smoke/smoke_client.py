"""One-shot HTTPS client for the separate offline container smoke profile."""

from __future__ import annotations

import json
from pathlib import Path
import ssl
import sys
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


BASE_URL = "https://collector:8443"
TOKEN_FILE = Path("/smoke/client/token")
CA_FILE = Path("/smoke/ca.crt")
METER_ID = "mtr_7f93b3e31d514db18cd62c0fcaa19a8e"
MEASUREMENT_QUERY = (
    f"meter_id={METER_ID}"
    "&start=2026-08-01T00:00:00Z"
    "&end=2026-08-01T00:30:00Z"
)


def request_json(
    context: ssl.SSLContext,
    path: str,
    token: str | None,
) -> tuple[int, dict[str, Any]]:
    headers = {"Accept": "application/json"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    request = Request(f"{BASE_URL}{path}", headers=headers, method="GET")
    try:
        with urlopen(request, context=context, timeout=5) as response:
            return response.status, json.loads(response.read(1024 * 1024).decode("utf-8"))
    except HTTPError as error:
        return error.code, json.loads(error.read(64 * 1024).decode("utf-8"))


def wait_for_https(context: ssl.SSLContext, token: str) -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            status, _ = request_json(context, "/api/v1/health", token)
            if status == 200:
                return
        except (OSError, URLError, ValueError, json.JSONDecodeError):
            pass
        time.sleep(0.5)
    raise RuntimeError("collector HTTPS startup timeout")


def main() -> int:
    token = TOKEN_FILE.read_text(encoding="ascii")
    context = ssl.create_default_context(cafile=str(CA_FILE))
    wait_for_https(context, token)

    unauthenticated_status, _ = request_json(context, "/api/v1/health", None)
    wrong_status, _ = request_json(context, "/api/v1/health", "A" * 43)
    health_status, health = request_json(context, "/api/v1/health", token)
    status_status, status = request_json(
        context, f"/api/v1/status?meter_id={METER_ID}", token
    )
    measurements_status, measurements = request_json(
        context, f"/api/v1/measurements?{MEASUREMENT_QUERY}", token
    )

    missing_values = [
        value for value in measurements.get("values", []) if value.get("quality") == "missing"
    ]
    checks = {
        "https_startup": health_status == 200,
        "unauthenticated_rejected": unauthenticated_status == 401,
        "wrong_token_rejected": wrong_status == 401,
        "health": health == {"schema_version": "1.0", "service_status": "ok"},
        "status": status_status == 200
        and status.get("data_timestamp") is not None
        and status.get("last_attempt") is not None
        and status.get("last_success") is None
        and status.get("completeness", {}).get("state") == "partial"
        and status.get("source_status") == "synthetic_offline_partial",
        "measurements": measurements_status == 200,
        "missing_is_null": len(missing_values) == 1
        and missing_values[0].get("value_kwh") is None,
        "missing_is_not_zero": all(
            value.get("value_kwh") not in (0, "0", "0.0") for value in missing_values
        ),
    }
    passed = all(checks.values())
    print(
        json.dumps(
            {
                "passed": passed,
                "checks": checks,
                "http_status": {
                    "unauthenticated": unauthenticated_status,
                    "wrong_token": wrong_status,
                    "health": health_status,
                    "status": status_status,
                    "measurements": measurements_status,
                },
            },
            separators=(",", ":"),
        )
    )
    return 0 if passed else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(
            json.dumps(
                {
                    "passed": False,
                    "error": {
                        "type": type(error).__name__,
                        "code": "offline_smoke_failed",
                    },
                },
                separators=(",", ":"),
            )
        )
        raise SystemExit(1) from None
