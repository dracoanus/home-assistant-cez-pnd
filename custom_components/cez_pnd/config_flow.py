"""Config flow for CEZ PND Collector."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import re
import secrets
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.config_entries import ConfigFlowResult
from homeassistant.core import HomeAssistant
from homeassistant.helpers import selector
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.service_info.hassio import HassioServiceInfo

from .client import (
    CollectorAuthenticationError,
    CollectorClient,
    CollectorPairingClient,
    CollectorConfigurationError,
    CollectorConnectionError,
    CollectorError,
    CollectorTlsError,
    METER_ID_PATTERN,
    PairingRejectedError,
    PairingUnavailableError,
    TOKEN_PATTERN,
    create_collector_ssl_context,
    normalize_collector_url,
)
from .const import (
    CONF_API_TOKEN,
    CONF_CA_CERTIFICATE,
    CONF_COLLECTOR_URL,
    CONF_METER_ID,
    CONF_PAIRING_ACTIVATION_PENDING,
    CONF_PAIRING_FINALIZE_PENDING,
    CONF_PAIRING_MANAGED,
    DEFAULT_COLLECTOR_URL,
    CONF_POLL_INTERVAL_SECONDS,
    DEFAULT_POLL_INTERVAL_SECONDS,
    DOMAIN,
    MAX_POLL_INTERVAL_SECONDS,
    MIN_POLL_INTERVAL_SECONDS,
    validate_poll_interval_seconds,
)
from .pairing_recovery import (
    PairingRecoveryError,
    PairingRecoveryRecord,
    get_pairing_recovery_manager,
    mark_created_this_process,
)


PAIRING_ID_PATTERN = re.compile(r"^[a-f0-9]{32}$")
SUPERVISOR_SLUG_PATTERN = re.compile(r"^[a-z0-9_]{1,128}$")
SUPERVISOR_HOSTNAME_PATTERN = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
MAX_DISCOVERY_CA_BYTES = 8 * 1024
DISCOVERY_FIELDS = {
    "pairing_schema_version",
    "meter_id",
    "ca_certificate",
    "pairing_id",
    "pairing_secret",
    "expires_at",
    "api_port",
}


class DiscoveryInvalidError(ValueError):
    """Supervisor discovery data failed the exact pairing contract."""


class DiscoveryExpiredError(ValueError):
    """The short-lived pairing bootstrap has expired."""


@dataclass(frozen=True)
class ValidatedPairingDiscovery:
    collector_url: str
    meter_id: str
    ca_certificate: str
    pairing_id: str
    pairing_secret: str = field(repr=False)
    expires_at: datetime


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _derive_collector_url(slug: object) -> str:
    if not isinstance(slug, str) or not SUPERVISOR_SLUG_PATTERN.fullmatch(slug):
        raise DiscoveryInvalidError("discovery_invalid")
    hostname = slug.replace("_", "-")
    if (
        not SUPERVISOR_HOSTNAME_PATTERN.fullmatch(hostname)
        or not hostname.endswith("-cez-pnd-collector")
    ):
        raise DiscoveryInvalidError("discovery_invalid")
    try:
        return normalize_collector_url(f"https://{hostname}:8443")
    except CollectorConfigurationError as error:
        raise DiscoveryInvalidError("discovery_invalid") from error


def _parse_discovery_expiry(value: object) -> datetime:
    if not isinstance(value, str) or len(value) != 20 or not value.endswith("Z"):
        raise DiscoveryInvalidError("discovery_invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise DiscoveryInvalidError("discovery_invalid") from error
    normalized = parsed.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )
    if parsed.tzinfo != timezone.utc or normalized != value:
        raise DiscoveryInvalidError("discovery_invalid")
    return parsed


def _validate_hassio_discovery(
    raw_config: object,
    slug: object,
    discovery_name: object,
) -> ValidatedPairingDiscovery:
    if not isinstance(raw_config, dict):
        raise DiscoveryInvalidError("discovery_invalid")
    config = dict(raw_config)
    addon = config.pop("addon", None)
    if (
        not isinstance(addon, str)
        or not 0 < len(addon) <= 128
        or any(ord(character) < 32 or ord(character) == 127 for character in addon)
        or addon != discovery_name
        or set(config) != DISCOVERY_FIELDS
    ):
        raise DiscoveryInvalidError("discovery_invalid")
    if (
        type(config["pairing_schema_version"]) is not int
        or config["pairing_schema_version"] != 1
        or type(config["api_port"]) is not int
        or config["api_port"] != 8443
        or not isinstance(config["meter_id"], str)
        or not METER_ID_PATTERN.fullmatch(config["meter_id"])
        or not isinstance(config["pairing_id"], str)
        or not PAIRING_ID_PATTERN.fullmatch(config["pairing_id"])
        or not isinstance(config["pairing_secret"], str)
        or not TOKEN_PATTERN.fullmatch(config["pairing_secret"])
        or not isinstance(config["ca_certificate"], str)
    ):
        raise DiscoveryInvalidError("discovery_invalid")
    if not 0 < len(config["ca_certificate"]) <= MAX_DISCOVERY_CA_BYTES:
        raise DiscoveryInvalidError("discovery_invalid")
    try:
        ca_size = len(config["ca_certificate"].encode("ascii"))
    except UnicodeEncodeError as error:
        raise DiscoveryInvalidError("discovery_invalid") from error
    if not 0 < ca_size <= MAX_DISCOVERY_CA_BYTES:
        raise DiscoveryInvalidError("discovery_invalid")
    try:
        create_collector_ssl_context(config["ca_certificate"])
    except CollectorConfigurationError as error:
        raise DiscoveryInvalidError("discovery_invalid") from error
    return ValidatedPairingDiscovery(
        collector_url=_derive_collector_url(slug),
        meter_id=config["meter_id"],
        ca_certificate=config["ca_certificate"],
        pairing_id=config["pairing_id"],
        pairing_secret=config["pairing_secret"],
        expires_at=_parse_discovery_expiry(config["expires_at"]),
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

    _pairing_discovery: ValidatedPairingDiscovery | None = None
    _pairing_recovery: PairingRecoveryRecord | None = None

    @staticmethod
    def async_get_options_flow(
        _config_entry: config_entries.ConfigEntry,
    ) -> CezPndOptionsFlow:
        """Return the polling interval options flow."""

        return CezPndOptionsFlow()

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

    async def async_step_hassio(
        self, discovery_info: HassioServiceInfo
    ) -> ConfigFlowResult:
        """Validate Supervisor-bound discovery and offer managed pairing."""

        raw_config = (
            dict(discovery_info.config)
            if isinstance(discovery_info.config, dict)
            else discovery_info.config
        )
        slug = discovery_info.slug
        name = discovery_info.name
        uuid = discovery_info.uuid
        # FlowManager retains init_data for the lifetime of the flow. Replace
        # its secret-bearing HassioServiceInfo immediately with the same safe
        # framework type so duplicate-flow indexing remains consistent.
        self.init_data = HassioServiceInfo(config={}, name=name, slug=slug, uuid=uuid)
        try:
            discovery = _validate_hassio_discovery(raw_config, slug, name)
            recovery = await get_pairing_recovery_manager(self.hass).async_load()
            if recovery is not None and not recovery.matches(
                discovery.meter_id,
                discovery.collector_url,
                discovery.ca_certificate,
            ):
                raise PairingRecoveryError("pairing_recovery_mismatch")
            if discovery.expires_at <= _utc_now() and recovery is None:
                raise DiscoveryExpiredError("discovery_expired")
        except DiscoveryExpiredError:
            return self.async_abort(reason="discovery_expired")
        except PairingRecoveryError:
            return self.async_abort(reason="discovery_invalid")
        except DiscoveryInvalidError:
            return self.async_abort(reason="discovery_invalid")
        self._pairing_discovery = discovery
        self._pairing_recovery = recovery
        # Keep meter_id as the stable unique ID. Using discovery_info.uuid would
        # let Supervisor discovery cleanup remove the newly paired entry.
        await self.async_set_unique_id(discovery.meter_id)
        self._abort_if_unique_id_configured()
        return await self.async_step_hassio_confirm()

    async def async_step_hassio_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Claim a generated API verifier before creating the durable entry."""

        discovery = self._pairing_discovery
        if discovery is None:
            return self.async_abort(reason="discovery_invalid")
        errors: dict[str, str] = {}
        if user_input is not None:
            if discovery.expires_at <= _utc_now() and self._pairing_recovery is None:
                errors["base"] = "discovery_expired"
            else:
                try:
                    manager = get_pairing_recovery_manager(self.hass)
                    async with manager.ownership_lock:
                        recovery = await manager.async_load()
                        if recovery is not None and not recovery.matches(
                            discovery.meter_id,
                            discovery.collector_url,
                            discovery.ca_certificate,
                        ):
                            raise PairingRecoveryError("pairing_recovery_mismatch")
                        if recovery is None:
                            if discovery.expires_at <= _utc_now():
                                raise DiscoveryExpiredError("discovery_expired")
                            api_token = secrets.token_urlsafe(32)
                            recovery = PairingRecoveryRecord(
                                discovery.meter_id,
                                discovery.collector_url,
                                api_token,
                                discovery.ca_certificate,
                            )
                            await manager._async_save_unlocked(recovery)
                        else:
                            api_token = recovery.api_token
                        verifier = hashlib.sha256(api_token.encode("ascii")).hexdigest()
                        context = create_collector_ssl_context(discovery.ca_certificate)
                        client = CollectorPairingClient(
                            async_get_clientsession(self.hass),
                            discovery.collector_url,
                            context,
                        )
                        await client.async_claim(
                            discovery.pairing_id,
                            discovery.pairing_secret,
                            verifier,
                        )
                        self._pairing_recovery = recovery
                except DiscoveryExpiredError:
                    errors["base"] = "discovery_expired"
                except CollectorTlsError:
                    errors["base"] = "invalid_tls"
                except CollectorConnectionError:
                    errors["base"] = "cannot_connect"
                except PairingRejectedError:
                    errors["base"] = "pairing_rejected"
                except (PairingRecoveryError, PairingUnavailableError, CollectorError):
                    errors["base"] = "pairing_unavailable"
                else:
                    mark_created_this_process(discovery.meter_id)
                    self._pairing_discovery = None
                    self._pairing_recovery = None
                    return self.async_create_entry(
                        title="CEZ PND Collector",
                        data={
                            CONF_COLLECTOR_URL: discovery.collector_url,
                            CONF_METER_ID: discovery.meter_id,
                            CONF_API_TOKEN: api_token,
                            CONF_CA_CERTIFICATE: discovery.ca_certificate,
                            CONF_PAIRING_MANAGED: True,
                            CONF_PAIRING_ACTIVATION_PENDING: True,
                            CONF_PAIRING_FINALIZE_PENDING: True,
                        },
                    )
        return self.async_show_form(
            step_id="hassio_confirm",
            data_schema=vol.Schema({}),
            errors=errors,
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


class CezPndOptionsFlow(config_entries.OptionsFlow):
    """Configure the local revision polling interval."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        current = self.config_entry.options.get(
            CONF_POLL_INTERVAL_SECONDS, DEFAULT_POLL_INTERVAL_SECONDS
        )
        if user_input is not None:
            try:
                interval = validate_poll_interval_seconds(
                    user_input.get(CONF_POLL_INTERVAL_SECONDS)
                )
            except ValueError:
                errors[CONF_POLL_INTERVAL_SECONDS] = "invalid_poll_interval"
            else:
                return self.async_create_entry(
                    title="",
                    data={CONF_POLL_INTERVAL_SECONDS: interval},
                )
        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_POLL_INTERVAL_SECONDS, default=current
                    ): selector.NumberSelector(
                        selector.NumberSelectorConfig(
                            min=MIN_POLL_INTERVAL_SECONDS,
                            max=MAX_POLL_INTERVAL_SECONDS,
                            step=1,
                            mode=selector.NumberSelectorMode.BOX,
                            unit_of_measurement="seconds",
                        )
                    )
                }
            ),
            errors=errors,
        )
