"""CEZ PND Collector integration."""

from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .client import (
    CollectorAuthenticationError,
    CollectorClient,
    CollectorError,
    CollectorPairingClient,
    PairingRejectedError,
    PairingUnavailableError,
    create_collector_ssl_context,
)
from .const import (
    CONF_API_TOKEN,
    CONF_CA_CERTIFICATE,
    CONF_COLLECTOR_URL,
    CONF_METER_ID,
    CONF_PAIRING_ACTIVATION_PENDING,
    CONF_PAIRING_FINALIZE_PENDING,
    CONF_PAIRING_MANAGED,
)
from .coordinator import CezPndCoordinator
from .pairing_recovery import (
    PairingRecoveryError,
    created_this_process,
    finalized_this_process,
    get_pairing_recovery_manager,
    mark_finalized_this_process,
)

PLATFORMS = [Platform.SENSOR]


def _managed_pairing_state(data: dict) -> tuple[bool, bool, bool]:
    """Validate and return managed, activation-pending, finalize-pending."""

    marker_keys = {
        CONF_PAIRING_MANAGED,
        CONF_PAIRING_ACTIVATION_PENDING,
        CONF_PAIRING_FINALIZE_PENDING,
    }
    present = marker_keys.intersection(data)
    if not present:
        return False, False, False
    if data.get(CONF_PAIRING_MANAGED) is not True:
        raise PairingRecoveryError("pairing_recovery_invalid")
    for key in (CONF_PAIRING_ACTIVATION_PENDING, CONF_PAIRING_FINALIZE_PENDING):
        if key in data and data[key] is not True:
            raise PairingRecoveryError("pairing_recovery_invalid")
    activation_pending = CONF_PAIRING_ACTIVATION_PENDING in data
    finalize_pending = CONF_PAIRING_FINALIZE_PENDING in data
    if activation_pending and not finalize_pending:
        raise PairingRecoveryError("pairing_recovery_invalid")
    return True, activation_pending, finalize_pending


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
    try:
        managed, activation_pending, finalize_pending = _managed_pairing_state(
            entry.data
        )
    except PairingRecoveryError:
        raise ConfigEntryNotReady("collector_pairing_unavailable") from None
    updated_data = dict(entry.data)
    pairing_client = None
    journal = None
    recovery = None
    recovery_loaded = False
    api_verified = False
    if managed:
        pairing_client = CollectorPairingClient(
            async_get_clientsession(hass),
            entry.data[CONF_COLLECTOR_URL],
            ssl_context,
        )
        journal = get_pairing_recovery_manager(hass)
    if activation_pending:
        try:
            recovery = await journal.async_load()
            recovery_loaded = True
            if recovery is None or not recovery.matches_entry(
                entry.data[CONF_METER_ID],
                entry.data[CONF_COLLECTOR_URL],
                entry.data[CONF_API_TOKEN],
                entry.data[CONF_CA_CERTIFICATE],
            ):
                raise PairingRecoveryError("pairing_recovery_mismatch")
            await pairing_client.async_activate(entry.data[CONF_API_TOKEN])
            await client.async_health()
            await client.async_status()
        except (PairingRejectedError, CollectorAuthenticationError) as error:
            raise ConfigEntryAuthFailed("collector_pairing_rejected") from error
        except (PairingRecoveryError, CollectorError) as error:
            raise ConfigEntryNotReady("collector_pairing_unavailable") from error
        updated_data.pop(CONF_PAIRING_ACTIVATION_PENDING, None)
        api_verified = True
    if finalize_pending and not created_this_process(entry.data[CONF_METER_ID]):
        try:
            if not recovery_loaded:
                recovery = await journal.async_load()
            if recovery is None or not recovery.matches_entry(
                entry.data[CONF_METER_ID],
                entry.data[CONF_COLLECTOR_URL],
                entry.data[CONF_API_TOKEN],
                entry.data[CONF_CA_CERTIFICATE],
            ):
                raise PairingRecoveryError("pairing_recovery_mismatch")
            if not api_verified:
                await client.async_health()
                await client.async_status()
            await pairing_client.async_finalize(entry.data[CONF_API_TOKEN])
        except (PairingRejectedError, CollectorAuthenticationError) as error:
            raise ConfigEntryAuthFailed("collector_pairing_rejected") from error
        except PairingUnavailableError:
            # ACTIVE remains usable; retry discovery cleanup on a later setup.
            pass
        except (PairingRecoveryError, CollectorError) as error:
            raise ConfigEntryNotReady("collector_pairing_unavailable") from error
        else:
            # Keep the journal until a later process observes these markers
            # durably absent from the reconstructed ConfigEntry.
            mark_finalized_this_process(entry.data[CONF_METER_ID])
            updated_data.pop(CONF_PAIRING_ACTIVATION_PENDING, None)
            updated_data.pop(CONF_PAIRING_FINALIZE_PENDING, None)
    if (
        managed
        and not activation_pending
        and not finalize_pending
        and not created_this_process(entry.data[CONF_METER_ID])
        and not finalized_this_process(entry.data[CONF_METER_ID])
    ):
        # Clean persistent markers prove a prior process completed finalize.
        # Journal cleanup is best effort and never gates normal operation.
        try:
            await journal.async_delete_if_matches(
                entry.data[CONF_METER_ID],
                entry.data[CONF_COLLECTOR_URL],
                entry.data[CONF_API_TOKEN],
                entry.data[CONF_CA_CERTIFICATE],
            )
        except PairingRecoveryError:
            pass
    if updated_data != entry.data:
        # The update listener is registered below, avoiding a reload loop.
        hass.config_entries.async_update_entry(entry, data=updated_data)
    coordinator = CezPndCoordinator(hass, entry, client)
    entry.async_on_unload(entry.add_update_listener(_async_update_listener))
    await coordinator.async_config_entry_first_refresh()
    entry.runtime_data = coordinator
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    from .statistics import CezPndStatisticsManager

    statistics_manager = CezPndStatisticsManager(hass, entry, client)
    entry.async_on_unload(
        coordinator.async_add_listener(
            lambda: statistics_manager.schedule(coordinator.data.status)
        )
    )
    statistics_manager.schedule(coordinator.data.status)
    return True


async def _async_update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Reload the entry after its polling option changes."""

    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a CEZ PND Collector config entry."""

    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
