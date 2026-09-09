"""Constants for the CEZ PND Collector integration."""

from datetime import timedelta

DOMAIN = "cez_pnd"
CONF_API_TOKEN = "api_token"
CONF_CA_CERTIFICATE = "ca_certificate"
CONF_COLLECTOR_URL = "collector_url"
CONF_METER_ID = "meter_id"
DEFAULT_COLLECTOR_URL = "https://606197c3-cez-pnd-collector:8443"
POLL_INTERVAL = timedelta(minutes=15)
SYNTHETIC_RANGE_START = "2026-08-01T00:00:00Z"
SYNTHETIC_RANGE_END = "2026-08-01T00:30:00Z"
