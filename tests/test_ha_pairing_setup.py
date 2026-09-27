"""Managed pairing activation/finalization durability tests."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType, SimpleNamespace
import sys
import unittest
from unittest.mock import AsyncMock, Mock

ROOT = Path(__file__).parents[1]
INTEGRATION = ROOT / "custom_components" / "cez_pnd"
METER_ID = "mtr_" + "a" * 32
TOKEN = "T" * 43
URL = "https://606197c3-cez-pnd-collector:8443"
CA = "public-ca"


class _CollectorError(Exception): pass
class _CollectorAuthenticationError(_CollectorError): pass
class _PairingRejectedError(_CollectorError): pass
class _PairingUnavailableError(_CollectorError): pass
class _PairingRecoveryError(Exception): pass
class _ConfigEntryAuthFailed(Exception): pass
class _ConfigEntryNotReady(Exception): pass


class _CollectorClient:
    instances = []
    failure: Exception | None = None
    def __init__(self, *args):
        self.health_calls = self.status_calls = 0
        self.instances.append(self)
    async def async_health(self):
        self.health_calls += 1
        if self.failure is not None: raise self.failure
        return "ok"
    async def async_status(self):
        self.status_calls += 1
        return object()


class _PairingClient:
    instances = []
    activate_failure: Exception | None = None
    finalize_failure: Exception | None = None
    def __init__(self, *args):
        self.activations, self.finalizations = [], []
        self.instances.append(self)
    async def async_activate(self, token):
        self.activations.append(token)
        if self.activate_failure is not None: raise self.activate_failure
    async def async_finalize(self, token):
        self.finalizations.append(token)
        if self.finalize_failure is not None: raise self.finalize_failure


class _Recovery:
    matches = True
    def matches_entry(self, meter_id, url, token, ca):
        return self.matches and (meter_id, url, token, ca) == (METER_ID, URL, TOKEN, CA)


class _Journal:
    record = _Recovery()
    remove_calls = 0
    remove_failure: Exception | None = None
    def __init__(self, hass): pass
    async def async_load(self): return self.record
    async def async_delete_if_matches(self, meter_id, url, token, ca):
        if self.record is None or not self.record.matches_entry(meter_id, url, token, ca):
            return False
        if self.remove_failure is not None: raise self.remove_failure
        type(self).remove_calls += 1
        type(self).record = None
        return True


CREATED_THIS_PROCESS = False
FINALIZED_THIS_PROCESS = False


class _Coordinator:
    failure: Exception | None = None
    def __init__(self, hass, entry, client): self.data = SimpleNamespace(status=object())
    async def async_config_entry_first_refresh(self):
        if self.failure is not None: raise self.failure
    def async_add_listener(self, callback): return callback


class _StatisticsManager:
    def __init__(self, *args): self.schedule = Mock()


def _load_module():
    homeassistant = ModuleType("homeassistant")
    config_entries = ModuleType("homeassistant.config_entries")
    config_entries.ConfigEntry = object
    const = ModuleType("homeassistant.const")
    const.Platform = SimpleNamespace(SENSOR="sensor")
    core = ModuleType("homeassistant.core")
    core.HomeAssistant = object
    exceptions = ModuleType("homeassistant.exceptions")
    exceptions.ConfigEntryAuthFailed = _ConfigEntryAuthFailed
    exceptions.ConfigEntryNotReady = _ConfigEntryNotReady
    aiohttp_client = ModuleType("homeassistant.helpers.aiohttp_client")
    aiohttp_client.async_get_clientsession = lambda hass: hass.session
    sys.modules.update({
        "homeassistant": homeassistant, "homeassistant.config_entries": config_entries,
        "homeassistant.const": const, "homeassistant.core": core,
        "homeassistant.exceptions": exceptions,
        "homeassistant.helpers": ModuleType("homeassistant.helpers"),
        "homeassistant.helpers.aiohttp_client": aiohttp_client,
    })
    package_name = "cez_pnd_pairing_setup_test"
    client = ModuleType(f"{package_name}.client")
    for name, value in {
        "CollectorAuthenticationError": _CollectorAuthenticationError,
        "CollectorClient": _CollectorClient, "CollectorError": _CollectorError,
        "CollectorPairingClient": _PairingClient,
        "PairingRejectedError": _PairingRejectedError,
        "PairingUnavailableError": _PairingUnavailableError,
        "create_collector_ssl_context": lambda _value: "strict-context",
    }.items(): setattr(client, name, value)
    recovery = ModuleType(f"{package_name}.pairing_recovery")
    recovery.PairingRecoveryError = _PairingRecoveryError
    recovery.get_pairing_recovery_manager = lambda hass: _Journal(hass)
    recovery.created_this_process = lambda _meter: CREATED_THIS_PROCESS
    recovery.finalized_this_process = lambda _meter: FINALIZED_THIS_PROCESS
    def mark_finalized(_meter):
        global FINALIZED_THIS_PROCESS
        FINALIZED_THIS_PROCESS = True
    recovery.mark_finalized_this_process = mark_finalized
    coordinator = ModuleType(f"{package_name}.coordinator")
    coordinator.CezPndCoordinator = _Coordinator
    statistics = ModuleType(f"{package_name}.statistics")
    statistics.CezPndStatisticsManager = _StatisticsManager
    sys.modules.update({client.__name__: client, recovery.__name__: recovery,
                        coordinator.__name__: coordinator, statistics.__name__: statistics})
    spec = importlib.util.spec_from_file_location(
        package_name, INTEGRATION / "__init__.py",
        submodule_search_locations=[str(INTEGRATION)],
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[package_name] = module
    spec.loader.exec_module(module)
    return module


module = _load_module()


class _ConfigEntries:
    def __init__(self):
        self.updates = []
        self.async_forward_entry_setups = AsyncMock()
        self.async_unload_platforms = AsyncMock(return_value=True)
        self.async_reload = AsyncMock()
    def async_update_entry(self, entry, *, data):
        self.updates.append(dict(data))
        entry.data = dict(data)


class _Entry:
    def __init__(self, *, managed=True):
        self.entry_id = "entry-id"
        self.data = {"collector_url": URL, "meter_id": METER_ID,
                     "api_token": TOKEN, "ca_certificate": CA}
        if managed:
            self.data["pairing_managed"] = True
            self.data["pairing_activation_pending"] = True
            self.data["pairing_finalize_pending"] = True
        self.runtime_data = None
        self.unloads = []
    def async_on_unload(self, callback): self.unloads.append(callback)
    def add_update_listener(self, callback): return callback


class PairingSetupTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        global CREATED_THIS_PROCESS, FINALIZED_THIS_PROCESS
        CREATED_THIS_PROCESS = False
        FINALIZED_THIS_PROCESS = False
        _CollectorClient.instances.clear()
        _PairingClient.instances.clear()
        _CollectorClient.failure = None
        _Coordinator.failure = None
        _PairingClient.activate_failure = _PairingClient.finalize_failure = None
        _Journal.record, _Journal.remove_calls, _Journal.remove_failure = _Recovery(), 0, None
        _Recovery.matches = True
        self.hass = SimpleNamespace(session=object(), config_entries=_ConfigEntries())

    async def test_initial_setup_activates_but_defers_finalize_until_later_process(self):
        global CREATED_THIS_PROCESS
        CREATED_THIS_PROCESS = True
        entry = _Entry()
        self.assertTrue(await module.async_setup_entry(self.hass, entry))
        pairing = _PairingClient.instances[0]
        self.assertEqual(pairing.activations, [TOKEN])
        self.assertEqual(pairing.finalizations, [])
        self.assertNotIn("pairing_activation_pending", entry.data)
        self.assertTrue(entry.data["pairing_finalize_pending"])
        self.assertEqual(_Journal.remove_calls, 0)

    async def test_persisted_entry_finalizes_and_keeps_journal_until_next_process(self):
        global FINALIZED_THIS_PROCESS
        entry = _Entry()
        self.assertTrue(await module.async_setup_entry(self.hass, entry))
        pairing = _PairingClient.instances[0]
        self.assertEqual(pairing.activations, [TOKEN])
        self.assertEqual(pairing.finalizations, [TOKEN])
        self.assertEqual(_Journal.remove_calls, 0)
        self.assertNotIn("pairing_activation_pending", entry.data)
        self.assertNotIn("pairing_finalize_pending", entry.data)
        self.assertTrue(entry.data["pairing_managed"])

        # A same-process reload cannot prove persistence and retains the journal.
        self.assertTrue(await module.async_setup_entry(self.hass, entry))
        self.assertEqual(_Journal.remove_calls, 0)

        # Simulate a real process boundary; the durably clean entry may delete.
        FINALIZED_THIS_PROCESS = False
        self.assertTrue(await module.async_setup_entry(self.hass, entry))
        self.assertEqual(_Journal.remove_calls, 1)

    async def test_finalize_temporary_failure_keeps_marker_and_normal_operation(self):
        entry = _Entry()
        entry.data.pop("pairing_activation_pending")
        _PairingClient.finalize_failure = _PairingUnavailableError("fixed")
        self.assertTrue(await module.async_setup_entry(self.hass, entry))
        self.assertTrue(entry.data["pairing_finalize_pending"])
        self.assertEqual(_Journal.remove_calls, 0)

        _PairingClient.finalize_failure = None
        self.assertTrue(await module.async_setup_entry(self.hass, entry))
        self.assertNotIn("pairing_finalize_pending", entry.data)
        self.assertEqual(_Journal.remove_calls, 0)

    async def test_activation_failure_preserves_both_markers_and_journal(self):
        entry = _Entry()
        _PairingClient.activate_failure = _CollectorError("fixed")
        with self.assertRaises(_ConfigEntryNotReady):
            await module.async_setup_entry(self.hass, entry)
        self.assertTrue(entry.data["pairing_activation_pending"])
        self.assertTrue(entry.data["pairing_finalize_pending"])
        self.assertEqual(_Journal.remove_calls, 0)

    async def test_activation_requires_matching_durable_journal(self):
        for label, record, matches in (
            ("missing", None, True),
            ("mismatch", _Recovery(), False),
        ):
            with self.subTest(case=label):
                _Journal.record = record
                _Recovery.matches = matches
                entry = _Entry()
                with self.assertRaises(_ConfigEntryNotReady):
                    await module.async_setup_entry(self.hass, entry)
                self.assertEqual(_PairingClient.instances[-1].activations, [])
                self.assertTrue(entry.data["pairing_activation_pending"])
                self.assertEqual(_Journal.remove_calls, 0)

    async def test_journal_mismatch_fails_closed_before_finalize(self):
        entry = _Entry()
        entry.data.pop("pairing_activation_pending")
        _Recovery.matches = False
        with self.assertRaises(_ConfigEntryNotReady):
            await module.async_setup_entry(self.hass, entry)
        self.assertEqual(_PairingClient.instances[0].finalizations, [])
        self.assertEqual(_Journal.remove_calls, 0)

    async def test_journal_delete_failure_after_clean_markers_does_not_block(self):
        global FINALIZED_THIS_PROCESS
        entry = _Entry()
        entry.data.pop("pairing_activation_pending")
        self.assertTrue(await module.async_setup_entry(self.hass, entry))
        self.assertEqual(_PairingClient.instances[0].finalizations, [TOKEN])
        self.assertNotIn("pairing_finalize_pending", entry.data)
        FINALIZED_THIS_PROCESS = False
        _Journal.remove_failure = _PairingRecoveryError("fixed")
        self.assertTrue(await module.async_setup_entry(self.hass, entry))
        self.assertEqual(_Journal.remove_calls, 0)
        _Journal.remove_failure = None
        self.assertTrue(await module.async_setup_entry(self.hass, entry))
        self.assertEqual(_Journal.remove_calls, 1)

    async def test_cleanup_crash_window_retries_with_journal_intact(self):
        global FINALIZED_THIS_PROCESS
        persisted = _Entry()
        old_persisted_data = dict(persisted.data)
        self.assertTrue(await module.async_setup_entry(self.hass, persisted))
        self.assertEqual(_Journal.remove_calls, 0)
        # Same-process reload after finalize must not delete the journal.
        self.assertTrue(await module.async_setup_entry(self.hass, persisted))
        self.assertEqual(_Journal.remove_calls, 0)
        # Simulate crash before marker persistence and reconstruct old data.
        FINALIZED_THIS_PROCESS = False
        reconstructed = _Entry()
        reconstructed.data = old_persisted_data
        self.assertTrue(await module.async_setup_entry(self.hass, reconstructed))
        self.assertEqual(_Journal.remove_calls, 0)
        self.assertNotIn("pairing_finalize_pending", reconstructed.data)

    async def test_unload_and_options_reload_after_finalize_retain_journal(self):
        entry = _Entry()
        self.assertTrue(await module.async_setup_entry(self.hass, entry))
        self.assertTrue(await module.async_unload_entry(self.hass, entry))
        await module._async_update_listener(self.hass, entry)
        self.assertTrue(await module.async_setup_entry(self.hass, entry))
        self.assertEqual(_Journal.remove_calls, 0)

    async def test_setup_retry_after_finalize_retains_journal(self):
        entry = _Entry()
        _Coordinator.failure = _ConfigEntryNotReady("fixed")
        with self.assertRaises(_ConfigEntryNotReady):
            await module.async_setup_entry(self.hass, entry)
        self.assertEqual(_Journal.remove_calls, 0)
        _Coordinator.failure = None
        self.assertTrue(await module.async_setup_entry(self.hass, entry))
        self.assertEqual(_Journal.remove_calls, 0)

    async def test_clean_managed_entry_never_deletes_mismatched_journal(self):
        entry = _Entry()
        entry.data.pop("pairing_activation_pending")
        entry.data.pop("pairing_finalize_pending")
        _Recovery.matches = False
        self.assertTrue(await module.async_setup_entry(self.hass, entry))
        self.assertEqual(_Journal.remove_calls, 0)
        self.assertIsNotNone(_Journal.record)

    async def test_malformed_managed_markers_fail_closed(self):
        cases = (
            {"pairing_managed": 1},
            {"pairing_managed": True, "pairing_activation_pending": "true", "pairing_finalize_pending": True},
            {"pairing_managed": True, "pairing_finalize_pending": []},
            {"pairing_activation_pending": True, "pairing_finalize_pending": True},
            {"pairing_managed": True, "pairing_activation_pending": True},
        )
        for markers in cases:
            with self.subTest(markers=markers):
                entry = _Entry(managed=False)
                entry.data.update(markers)
                with self.assertRaises(_ConfigEntryNotReady):
                    await module.async_setup_entry(self.hass, entry)

    async def test_manual_entry_never_uses_pairing_or_journal(self):
        _Journal.record = _Recovery()
        entry = _Entry(managed=False)
        self.assertTrue(await module.async_setup_entry(self.hass, entry))
        self.assertEqual(_PairingClient.instances, [])
        self.assertEqual(_Journal.remove_calls, 0)
        self.assertEqual(self.hass.config_entries.updates, [])


if __name__ == "__main__":
    unittest.main()
