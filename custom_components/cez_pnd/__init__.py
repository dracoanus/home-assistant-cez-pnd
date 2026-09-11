"""CEZ PND Collector integration."""

from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .client import CollectorClient, create_collector_ssl_context
from .const import (
    CONF_API_TOKEN,
    CONF_CA_CERTIFICATE,
    CONF_COLLECTOR_URL,
    CONF_METER_ID,
)
from .coordinator import CezPndCoordinator

PLATFORMS = [Platform.SENSOR]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up CEZ PND Collector from a config entry."""

    ssl_context = create_collector_ssl_context(entry.data[CONF_CA_CERTIFICATE])
    client = CollectorClient(
        async_get_clientsession(hass),
        entry.data[CONF_COLLECTOR_URL],
        entry.data[CONF_METER_ID],
        entry.data[CONF_API_TOKEN],
        ssl_context,
    )
    coordinator = CezPndCoordinator(hass, entry, client)
    entry.async_on_unload(entry.add_update_listener(_async_update_listener))
    await coordinator.async_config_entry_first_refresh()
    entry.runtime_data = coordinator
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def _async_update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Reload the entry after its polling option changes."""

    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a CEZ PND Collector config entry."""

    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
