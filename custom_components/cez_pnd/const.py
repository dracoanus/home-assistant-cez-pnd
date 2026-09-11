"""Constants for the CEZ PND Collector integration."""

from datetime import timedelta

DOMAIN = "cez_pnd"
CONF_API_TOKEN = "api_token"
CONF_CA_CERTIFICATE = "ca_certificate"
CONF_COLLECTOR_URL = "collector_url"
CONF_METER_ID = "meter_id"
DEFAULT_COLLECTOR_URL = "https://606197c3-cez-pnd-collector:8443"
POLL_INTERVAL = timedelta(minutes=15)
