"""Private crash-recovery journal for managed Collector onboarding."""

from __future__ import annotations

from dataclasses import dataclass, field
import asyncio
import hmac
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.storage import Store

from .client import (
    METER_ID_PATTERN,
    TOKEN_PATTERN,
    CollectorConfigurationError,
    create_collector_ssl_context,
    normalize_collector_url,
)

STORAGE_VERSION = 1
STORAGE_KEY = "cez_pnd.pairing_recovery"
MANAGER_DATA_KEY = "cez_pnd_pairing_recovery_manager"
JOURNAL_PHASE = "onboarding"
MAX_CA_LENGTH = 8 * 1024


class PairingRecoveryError(Exception):
    """The private pairing recovery journal is unavailable or invalid."""


@dataclass(frozen=True)
class PairingRecoveryRecord:
    """Minimum long-term material required to recover initial pairing."""

    meter_id: str
    collector_url: str
    api_token: str = field(repr=False)
    ca_certificate: str
    phase: str = JOURNAL_PHASE

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": STORAGE_VERSION,
            "meter_id": self.meter_id,
            "collector_url": self.collector_url,
            "api_token": self.api_token,
            "ca_certificate": self.ca_certificate,
            "phase": self.phase,
        }

    @classmethod
    def from_dict(cls, raw: object) -> PairingRecoveryRecord:
        if not isinstance(raw, dict) or set(raw) != {
            "schema_version",
            "meter_id",
            "collector_url",
            "api_token",
            "ca_certificate",
            "phase",
        }:
            raise PairingRecoveryError("pairing_recovery_invalid")
        if type(raw["schema_version"]) is not int or raw["schema_version"] != 1:
            raise PairingRecoveryError("pairing_recovery_invalid")
        meter_id = raw["meter_id"]
        api_token = raw["api_token"]
        ca_certificate = raw["ca_certificate"]
        phase = raw["phase"]
        if (
            not isinstance(meter_id, str)
            or not METER_ID_PATTERN.fullmatch(meter_id)
            or not isinstance(api_token, str)
            or not TOKEN_PATTERN.fullmatch(api_token)
            or not isinstance(ca_certificate, str)
            or not 0 < len(ca_certificate) <= MAX_CA_LENGTH
            or phase != JOURNAL_PHASE
        ):
            raise PairingRecoveryError("pairing_recovery_invalid")
        try:
            collector_url = normalize_collector_url(raw["collector_url"])
            create_collector_ssl_context(ca_certificate)
        except (CollectorConfigurationError, TypeError):
            raise PairingRecoveryError("pairing_recovery_invalid") from None
        return cls(meter_id, collector_url, api_token, ca_certificate, phase)

    def matches(self, meter_id: str, collector_url: str, ca_certificate: str) -> bool:
        return (
            self.meter_id == meter_id
            and self.collector_url == collector_url
            and self.ca_certificate == ca_certificate
        )

    def matches_entry(
        self,
        meter_id: str,
        collector_url: str,
        api_token: str,
        ca_certificate: str,
    ) -> bool:
        return self.matches(meter_id, collector_url, ca_certificate) and hmac.compare_digest(
            self.api_token, api_token
        )


class PairingRecoveryManager:
    """Serialize ownership of the one private recovery record per HA instance."""

    def __init__(self, hass: HomeAssistant) -> None:
        self._hass = hass
        self._store = self._new_store()
        self.ownership_lock = asyncio.Lock()

    def _new_store(self) -> Store[dict[str, Any]]:
        return Store(
            self._hass,
            STORAGE_VERSION,
            STORAGE_KEY,
            private=True,
            atomic_writes=True,
        )

    async def async_load(self) -> PairingRecoveryRecord | None:
        try:
            raw = await self._store.async_load()
        except Exception:
            raise PairingRecoveryError("pairing_recovery_unavailable") from None
        if raw is None:
            return None
        return PairingRecoveryRecord.from_dict(raw)

    async def _async_save_unlocked(self, record: PairingRecoveryRecord) -> None:
        """Persist one record while the caller owns ownership_lock."""

        payload = PairingRecoveryRecord.from_dict(record.as_dict()).as_dict()
        try:
            await self._store.async_save(payload)
            persisted = await self._new_store().async_load()
        except Exception:
            raise PairingRecoveryError("pairing_recovery_unavailable") from None
        if persisted != payload:
            raise PairingRecoveryError("pairing_recovery_unavailable")

    async def _async_remove_unlocked(self) -> None:
        """Remove the record while the caller owns ownership_lock."""

        try:
            await self._store.async_remove()
            persisted = await self._new_store().async_load()
        except Exception:
            raise PairingRecoveryError("pairing_recovery_unavailable") from None
        if persisted is not None:
            raise PairingRecoveryError("pairing_recovery_unavailable")

    async def async_delete_if_matches(
        self,
        meter_id: str,
        collector_url: str,
        api_token: str,
        ca_certificate: str,
    ) -> bool:
        """Delete only the exact current owner under serialized ownership."""

        async with self.ownership_lock:
            record = await self.async_load()
            if record is None or not record.matches_entry(
                meter_id,
                collector_url,
                api_token,
                ca_certificate,
            ):
                return False
            await self._async_remove_unlocked()
            return True


def get_pairing_recovery_manager(hass: HomeAssistant) -> PairingRecoveryManager:
    """Return the HA-instance-owned recovery manager."""

    manager = hass.data.get(MANAGER_DATA_KEY)
    if manager is None:
        manager = PairingRecoveryManager(hass)
        hass.data[MANAGER_DATA_KEY] = manager
    if not isinstance(manager, PairingRecoveryManager):
        raise PairingRecoveryError("pairing_recovery_unavailable")
    return manager


_CREATED_THIS_PROCESS: set[str] = set()
_FINALIZED_THIS_PROCESS: set[str] = set()


def mark_created_this_process(meter_id: str) -> None:
    """Remember a non-secret provenance marker until this HA process exits."""

    if not METER_ID_PATTERN.fullmatch(meter_id):
        raise PairingRecoveryError("pairing_recovery_invalid")
    _CREATED_THIS_PROCESS.add(meter_id)


def created_this_process(meter_id: str) -> bool:
    """Return whether this managed entry originated in this HA process."""

    return meter_id in _CREATED_THIS_PROCESS


def mark_finalized_this_process(meter_id: str) -> None:
    """Prevent journal cleanup until a later HA process proves persistence."""

    if not METER_ID_PATTERN.fullmatch(meter_id):
        raise PairingRecoveryError("pairing_recovery_invalid")
    _FINALIZED_THIS_PROCESS.add(meter_id)


def finalized_this_process(meter_id: str) -> bool:
    """Return whether this process removed the persistent pending markers."""

    return meter_id in _FINALIZED_THIS_PROCESS
