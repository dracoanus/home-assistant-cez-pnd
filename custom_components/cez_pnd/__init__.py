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
    CollectorDatasetUnavailable,
    CollectorError,
    CollectorPairingClient,
    CollectorProtocolError,
    CollectorUpdateRequired,
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
from .event_listener import CollectorEventListener
from .pairing_recovery import (
    PairingRecoveryError,
    created_this_process,
    finalized_this_process,
    get_pairing_recovery_manager,
    mark_finalized_this_process,
)

PLATFORMS = [Platform.SENSOR]


async def async_migrate_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Remove only the obsolete polling option without contacting the Collector."""
    if entry.version != 1:
        return False
    if entry.minor_version < 2:
        options = dict(entry.options)
        options.pop("poll_interval_seconds", None)
        hass.config_entries.async_update_entry(entry, options=options, minor_version=2)
    return True


async def _verify_pairing_api(client: CollectorClient) -> None:
    """Activation proves API access even when initial collection has not finished."""
    await client.async_health()
    try:
        await client.async_status()
    except CollectorDatasetUnavailable:
        pass


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
            await _verify_pairing_api(client)
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
                await _verify_pairing_api(client)
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
        hass.config_entries.async_update_entry(entry, data=updated_data)
    try:
        initial_event = await client.async_events()
        if initial_event is None or initial_event.event != "state_reset":
            raise CollectorProtocolError("invalid_event_handshake")
    except CollectorAuthenticationError:
        raise ConfigEntryAuthFailed("collector_authentication_failed") from None
    except CollectorUpdateRequired:
        raise ConfigEntryNotReady("collector_update_required", translation_domain="cez_pnd",
                                  translation_key="collector_update_required") from None
    except CollectorError:
        raise ConfigEntryNotReady("collector_events_unavailable") from None
    coordinator = CezPndCoordinator(hass, entry, client)
    await coordinator.async_config_entry_first_refresh()
    entry.runtime_data = coordinator
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    from .statistics import CezPndStatisticsManager

    statistics_manager = CezPndStatisticsManager(hass, entry, client)

    def schedule_statistics() -> None:
        if coordinator.data.status is not None:
            statistics_manager.schedule(coordinator.data.status)

    entry.async_on_unload(coordinator.async_add_listener(schedule_statistics))
    schedule_statistics()
    coordinator.event_listener = CollectorEventListener(
        hass, entry, client, coordinator, initial_event.cursor
    )
    coordinator.event_listener.start()
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a CEZ PND Collector config entry."""

    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unloaded:
        await entry.runtime_data.event_listener.async_stop()
    return unloaded
