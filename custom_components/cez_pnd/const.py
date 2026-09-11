"""Constants for the CEZ PND Collector integration."""

DOMAIN = "cez_pnd"
CONF_API_TOKEN = "api_token"
CONF_CA_CERTIFICATE = "ca_certificate"
CONF_COLLECTOR_URL = "collector_url"
CONF_METER_ID = "meter_id"
CONF_POLL_INTERVAL_SECONDS = "poll_interval_seconds"
DEFAULT_COLLECTOR_URL = "https://606197c3-cez-pnd-collector:8443"
DEFAULT_POLL_INTERVAL_SECONDS = 60
MIN_POLL_INTERVAL_SECONDS = 30
MAX_POLL_INTERVAL_SECONDS = 3600


def validate_poll_interval_seconds(value: object) -> int:
    """Return a strictly bounded integer polling interval."""

    if isinstance(value, float) and value.is_integer():
        value = int(value)
    if (
        type(value) is not int
        or not MIN_POLL_INTERVAL_SECONDS <= value <= MAX_POLL_INTERVAL_SECONDS
    ):
        raise ValueError("invalid_poll_interval")
    return value
