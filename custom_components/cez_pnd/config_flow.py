"""Config flow for CEZ PND Collector."""

from __future__ import annotations

from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.config_entries import ConfigFlowResult
from homeassistant.core import HomeAssistant
from homeassistant.helpers import selector
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .client import (
    CollectorAuthenticationError,
    CollectorClient,
    CollectorConfigurationError,
    CollectorConnectionError,
    CollectorError,
    CollectorTlsError,
    create_collector_ssl_context,
)
from .const import (
    CONF_API_TOKEN,
    CONF_CA_CERTIFICATE,
    CONF_COLLECTOR_URL,
    CONF_METER_ID,
    DEFAULT_COLLECTOR_URL,
    DOMAIN,
)


def _schema(defaults: dict[str, Any] | None = None) -> vol.Schema:
    values = defaults or {}
    return vol.Schema(
        {
            vol.Required(
                CONF_COLLECTOR_URL,
                default=values.get(CONF_COLLECTOR_URL, DEFAULT_COLLECTOR_URL),
            ): selector.TextSelector(
                selector.TextSelectorConfig(type=selector.TextSelectorType.URL)
            ),
            vol.Required(CONF_METER_ID, default=values.get(CONF_METER_ID, "")): str,
            vol.Required(CONF_API_TOKEN): selector.TextSelector(
                selector.TextSelectorConfig(type=selector.TextSelectorType.PASSWORD)
            ),
            vol.Required(CONF_CA_CERTIFICATE): selector.TextSelector(
                selector.TextSelectorConfig(multiline=True)
            ),
        }
    )


async def _validate_input(hass: HomeAssistant, data: dict[str, Any]) -> None:
    context = create_collector_ssl_context(data[CONF_CA_CERTIFICATE])
    client = CollectorClient(
        async_get_clientsession(hass),
        data[CONF_COLLECTOR_URL],
        data[CONF_METER_ID],
        data[CONF_API_TOKEN],
        context,
    )
    await client.async_health()
    await client.async_status()


class CezPndConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Configure a single CEZ PND Collector connection."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Collect and verify only Collector-side configuration."""

        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                await _validate_input(self.hass, user_input)
            except CollectorAuthenticationError:
                errors["base"] = "invalid_auth"
            except CollectorTlsError:
                errors["base"] = "invalid_tls"
            except CollectorConnectionError:
                errors["base"] = "cannot_connect"
            except CollectorConfigurationError:
                errors["base"] = "invalid_configuration"
            except CollectorError:
                errors["base"] = "invalid_response"
            else:
                await self.async_set_unique_id(user_input[CONF_METER_ID])
                self._abort_if_unique_id_configured()
                return self.async_create_entry(
                    title="CEZ PND Collector", data=user_input
                )

        return self.async_show_form(
            step_id="user", data_schema=_schema(user_input), errors=errors
        )

    async def async_step_reauth(
        self, _entry_data: dict[str, Any]
    ) -> ConfigFlowResult:
        """Start replacement of a rejected Collector credential."""

        self._reauth_entry = self.hass.config_entries.async_get_entry(
            self.context["entry_id"]
        )
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Verify a replacement limited Collector API token."""

        errors: dict[str, str] = {}
        if user_input is not None:
            candidate = {**self._reauth_entry.data, **user_input}
            try:
                await _validate_input(self.hass, candidate)
            except CollectorAuthenticationError:
                errors["base"] = "invalid_auth"
            except CollectorTlsError:
                errors["base"] = "invalid_tls"
            except CollectorConnectionError:
                errors["base"] = "cannot_connect"
            except CollectorError:
                errors["base"] = "invalid_response"
            else:
                return self.async_update_reload_and_abort(
                    self._reauth_entry,
                    data_updates={CONF_API_TOKEN: user_input[CONF_API_TOKEN]},
                )

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_API_TOKEN): selector.TextSelector(
                        selector.TextSelectorConfig(
                            type=selector.TextSelectorType.PASSWORD
                        )
                    )
                }
            ),
            errors=errors,
        )
