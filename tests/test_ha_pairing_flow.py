"""Focused Home Assistant managed-pairing flow and recovery tests."""

from __future__ import annotations

from dataclasses import dataclass
import asyncio
import hashlib
import importlib.util
from pathlib import Path
import re
from types import ModuleType, SimpleNamespace
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).parents[1]
INTEGRATION = ROOT / "custom_components" / "cez_pnd"
METER_ID = "mtr_" + "a" * 32
PAIRING_ID = "b" * 32
PAIRING_SECRET = "C" * 43
VALID_CA = "synthetic-valid-ca"
TOKEN = "T" * 43


class _Required:
    def __init__(self, key, *, default=None): self.key, self.default = key, default


class _Schema:
    def __init__(self, schema): self.schema = schema


class _Selector:
    def __init__(self, config): self.config = config


class _ConfigFlow:
    def __init_subclass__(cls, domain=None, **kwargs): super().__init_subclass__(**kwargs)
    def __init__(self):
        self.hass = SimpleNamespace(session=object(), data={})
        self.context = {"source": "hassio"}
        self.unique_id = None
        self.configured = False
        self.init_data = None
    async def async_set_unique_id(self, value): self.unique_id = value
    def _abort_if_unique_id_configured(self):
        if self.configured: raise RuntimeError("already_configured")
    def async_abort(self, *, reason): return {"type": "abort", "reason": reason}
    def async_show_form(self, *, step_id, data_schema, errors):
        return {"type": "form", "step_id": step_id, "errors": errors}
    def async_create_entry(self, *, title, data):
        return {"type": "create_entry", "title": title, "data": data}


class _OptionsFlow: pass
class _CollectorError(Exception): pass
class _CollectorAuthenticationError(_CollectorError): pass
class _CollectorConfigurationError(_CollectorError): pass
class _CollectorConnectionError(_CollectorError): pass
class _CollectorTlsError(_CollectorError): pass
class _PairingRejectedError(_CollectorError): pass
class _PairingUnavailableError(_CollectorError): pass

EVENTS: list[str] = []


class _PairingClient:
    calls: list[tuple[object, ...]] = []
    failure: Exception | None = None
    entered: asyncio.Event | None = None
    release: asyncio.Event | None = None
    def __init__(self, session, url, context): self.url, self.context = url, context
    async def async_claim(self, pairing_id, secret, verifier):
        EVENTS.append("claim")
        self.calls.append((self.url, pairing_id, secret, verifier, self.context))
        if self.entered is not None:
            self.entered.set()
        if self.release is not None:
            await self.release.wait()
        if self.failure is not None: raise self.failure


class _Store:
    data = None
    fail_readback = False
    options: list[dict[str, object]] = []
    def __init__(self, hass, version, key, **kwargs):
        self.options.append({"version": version, "key": key, **kwargs})
    async def async_load(self):
        if self.fail_readback: return {"corrupt": True}
        return None if self.data is None else dict(self.data)
    async def async_save(self, value):
        EVENTS.append("journal_save")
        type(self).data = dict(value)
    async def async_remove(self): type(self).data = None


@dataclass
class _HassioServiceInfo:
    config: dict[str, object]
    name: str
    slug: str
    uuid: str


def _load_module():
    voluptuous = ModuleType("voluptuous")
    voluptuous.Required, voluptuous.Schema = _Required, _Schema
    homeassistant = ModuleType("homeassistant")
    config_entries = ModuleType("homeassistant.config_entries")
    config_entries.ConfigEntry = object
    config_entries.ConfigFlow = _ConfigFlow
    config_entries.OptionsFlow = _OptionsFlow
    config_entries.ConfigFlowResult = dict
    hassio = ModuleType("homeassistant.helpers.service_info.hassio")
    hassio.HassioServiceInfo = _HassioServiceInfo
    core = ModuleType("homeassistant.core")
    core.HomeAssistant = object
    selector = ModuleType("homeassistant.helpers.selector")
    selector.TextSelector = _Selector
    selector.TextSelectorConfig = lambda **values: values
    selector.TextSelectorType = SimpleNamespace(URL="url", PASSWORD="password")
    selector.NumberSelector = _Selector
    selector.NumberSelectorConfig = lambda **values: values
    selector.NumberSelectorMode = SimpleNamespace(BOX="box")
    aiohttp_client = ModuleType("homeassistant.helpers.aiohttp_client")
    aiohttp_client.async_get_clientsession = lambda hass: hass.session
    storage = ModuleType("homeassistant.helpers.storage")
    storage.Store = _Store
    helpers = ModuleType("homeassistant.helpers")
    helpers.selector = selector
    sys.modules.update({
        "voluptuous": voluptuous, "homeassistant": homeassistant,
        "homeassistant.config_entries": config_entries, "homeassistant.core": core,
        "homeassistant.helpers": helpers, "homeassistant.helpers.selector": selector,
        "homeassistant.helpers.storage": storage,
        "homeassistant.helpers.aiohttp_client": aiohttp_client,
        "homeassistant.helpers.service_info": ModuleType("homeassistant.helpers.service_info"),
        "homeassistant.helpers.service_info.hassio": hassio,
    })
    package_name = "cez_pnd_pairing_flow_test"
    package = ModuleType(package_name)
    package.__path__ = [str(INTEGRATION)]
    sys.modules[package_name] = package
    client = ModuleType(f"{package_name}.client")
    values = {
        "CollectorAuthenticationError": _CollectorAuthenticationError,
        "CollectorClient": object, "CollectorConfigurationError": _CollectorConfigurationError,
        "CollectorConnectionError": _CollectorConnectionError, "CollectorError": _CollectorError,
        "CollectorPairingClient": _PairingClient, "CollectorTlsError": _CollectorTlsError,
        "PairingRejectedError": _PairingRejectedError,
        "PairingUnavailableError": _PairingUnavailableError,
        "METER_ID_PATTERN": re.compile(r"^mtr_[a-f0-9]{32}$"),
        "TOKEN_PATTERN": re.compile(r"^[A-Za-z0-9_-]{43,128}$"),
    }
    for name, value in values.items(): setattr(client, name, value)
    def create_context(value):
        if value != VALID_CA: raise _CollectorConfigurationError("invalid_ca")
        return "strict-context"
    client.create_collector_ssl_context = create_context
    client.normalize_collector_url = lambda value: value if value.startswith("https://") else (_ for _ in ()).throw(_CollectorConfigurationError())
    sys.modules[client.__name__] = client
    name = f"{package_name}.config_flow"
    spec = importlib.util.spec_from_file_location(name, INTEGRATION / "config_flow.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


module = _load_module()


def _discovery(*, expires_at="2099-01-01T00:00:00Z", config_changes=None):
    config = {
        "pairing_schema_version": 1, "meter_id": METER_ID,
        "ca_certificate": VALID_CA, "pairing_id": PAIRING_ID,
        "pairing_secret": PAIRING_SECRET, "expires_at": expires_at,
        "api_port": 8443, "addon": "CEZ PND Collector",
    }
    config.update(config_changes or {})
    return _HassioServiceInfo(config, "CEZ PND Collector", "606197c3_cez_pnd_collector", "safe_uuid")


class PairingFlowTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        _Store.data, _Store.fail_readback = None, False
        _Store.options.clear()
        _PairingClient.calls.clear()
        _PairingClient.failure = None
        _PairingClient.entered = _PairingClient.release = None
        EVENTS.clear()

    async def test_concurrent_different_collectors_cannot_overwrite_journal(self):
        first = module.CezPndConfigFlow()
        second = module.CezPndConfigFlow()
        second.hass = first.hass
        await first.async_step_hassio(_discovery())
        other_meter = "mtr_" + "d" * 32
        await second.async_step_hassio(
            _discovery(config_changes={"meter_id": other_meter})
        )
        _PairingClient.entered = asyncio.Event()
        _PairingClient.release = asyncio.Event()
        with mock.patch.object(module.secrets, "token_urlsafe", return_value=TOKEN) as generate:
            first_task = asyncio.create_task(first.async_step_hassio_confirm({}))
            await _PairingClient.entered.wait()
            second_task = asyncio.create_task(second.async_step_hassio_confirm({}))
            await asyncio.sleep(0)
            self.assertFalse(second_task.done())
            _PairingClient.release.set()
            first_result, second_result = await asyncio.gather(first_task, second_task)
        self.assertEqual(first_result["type"], "create_entry")
        self.assertEqual(second_result["errors"], {"base": "pairing_unavailable"})
        self.assertEqual(_Store.data["meter_id"], METER_ID)
        self.assertEqual(generate.call_count, 1)
        self.assertEqual(len(_PairingClient.calls), 1)

    async def test_concurrent_same_collector_reuses_one_token(self):
        first = module.CezPndConfigFlow()
        second = module.CezPndConfigFlow()
        second.hass = first.hass
        await first.async_step_hassio(_discovery())
        await second.async_step_hassio(_discovery())
        _PairingClient.entered = asyncio.Event()
        _PairingClient.release = asyncio.Event()
        with mock.patch.object(module.secrets, "token_urlsafe", return_value=TOKEN) as generate:
            first_task = asyncio.create_task(first.async_step_hassio_confirm({}))
            await _PairingClient.entered.wait()
            second_task = asyncio.create_task(second.async_step_hassio_confirm({}))
            await asyncio.sleep(0)
            _PairingClient.release.set()
            results = await asyncio.gather(first_task, second_task)
        self.assertTrue(all(result["type"] == "create_entry" for result in results))
        self.assertEqual(generate.call_count, 1)
        self.assertEqual(len(_PairingClient.calls), 2)
        self.assertEqual(_PairingClient.calls[0][3], _PairingClient.calls[1][3])
        self.assertTrue(all(result["data"]["api_token"] == TOKEN for result in results))

    async def test_cleanup_waits_reloads_and_preserves_changed_owner(self):
        hass = SimpleNamespace(session=object(), data={})
        manager = module.get_pairing_recovery_manager(hass)
        original = module.PairingRecoveryRecord(
            METER_ID, "https://collector:8443", TOKEN, VALID_CA
        )
        async with manager.ownership_lock:
            await manager._async_save_unlocked(original)
        other_meter = "mtr_" + "d" * 32
        replacement = module.PairingRecoveryRecord(
            other_meter, "https://other:8443", "U" * 43, VALID_CA
        )
        async with manager.ownership_lock:
            cleanup = asyncio.create_task(
                manager.async_delete_if_matches(
                    original.meter_id,
                    original.collector_url,
                    original.api_token,
                    original.ca_certificate,
                )
            )
            await asyncio.sleep(0)
            self.assertFalse(cleanup.done())
            _Store.data = replacement.as_dict()
        self.assertFalse(await cleanup)
        self.assertEqual(_Store.data, replacement.as_dict())

    async def test_cleanup_deletes_only_exact_identity_and_token(self):
        hass = SimpleNamespace(session=object(), data={})
        manager = module.get_pairing_recovery_manager(hass)
        record = module.PairingRecoveryRecord(
            METER_ID, "https://collector:8443", TOKEN, VALID_CA
        )
        mismatches = (
            ("meter", "mtr_" + "d" * 32, record.collector_url, TOKEN, VALID_CA),
            ("url", METER_ID, "https://other:8443", TOKEN, VALID_CA),
            ("ca", METER_ID, record.collector_url, TOKEN, "other-ca"),
            ("token", METER_ID, record.collector_url, "U" * 43, VALID_CA),
        )
        for label, *values in mismatches:
            with self.subTest(case=label):
                _Store.data = record.as_dict()
                self.assertFalse(await manager.async_delete_if_matches(*values))
                self.assertEqual(_Store.data, record.as_dict())
        _Store.data = record.as_dict()
        self.assertTrue(
            await manager.async_delete_if_matches(
                record.meter_id,
                record.collector_url,
                record.api_token,
                record.ca_certificate,
            )
        )
        self.assertIsNone(_Store.data)

    def test_core_addon_metadata_passes_but_unknown_field_fails(self):
        info = _discovery()
        value = module._validate_hassio_discovery(info.config, info.slug, info.name)
        self.assertEqual(value.meter_id, METER_ID)
        self.assertNotIn(PAIRING_SECRET, repr(value))
        attacker = _discovery(config_changes={"unexpected": "value"})
        with self.assertRaises(module.DiscoveryInvalidError):
            module._validate_hassio_discovery(attacker.config, attacker.slug, attacker.name)

    async def test_init_data_is_sanitized_and_journal_precedes_claim(self):
        flow = module.CezPndConfigFlow()
        result = await flow.async_step_hassio(_discovery())
        self.assertEqual(result["step_id"], "hassio_confirm")
        self.assertNotIn(PAIRING_SECRET, repr(flow.init_data))
        self.assertNotIn(PAIRING_SECRET, repr(flow._pairing_discovery))
        with mock.patch.object(module.secrets, "token_urlsafe", return_value=TOKEN):
            result = await flow.async_step_hassio_confirm({})
        self.assertEqual(EVENTS, ["journal_save", "claim"])
        self.assertEqual(result["type"], "create_entry")
        self.assertEqual(result["data"]["api_token"], TOKEN)
        self.assertTrue(result["data"]["pairing_activation_pending"])
        self.assertTrue(result["data"]["pairing_finalize_pending"])
        self.assertIsNone(flow._pairing_discovery)
        self.assertIsNone(flow._pairing_recovery)
        self.assertNotIn("pairing_secret", _Store.data)
        self.assertNotIn("pairing_id", _Store.data)
        self.assertNotIn("api_token_sha256", _Store.data)
        self.assertNotIn(PAIRING_SECRET, repr(_Store.data))
        self.assertTrue(_Store.options[-1]["private"])
        self.assertTrue(_Store.options[-1]["atomic_writes"])

    async def test_crash_recovery_reuses_durable_token_and_allows_expired_discovery(self):
        first = module.CezPndConfigFlow()
        await first.async_step_hassio(_discovery())
        _PairingClient.failure = _PairingUnavailableError("fixed")
        with mock.patch.object(module.secrets, "token_urlsafe", return_value=TOKEN):
            failed = await first.async_step_hassio_confirm({})
        self.assertEqual(failed["errors"], {"base": "pairing_unavailable"})
        self.assertEqual(_Store.data["api_token"], TOKEN)
        _PairingClient.failure = None
        recovered = module.CezPndConfigFlow()
        form = await recovered.async_step_hassio(_discovery(expires_at="2020-01-01T00:00:00Z"))
        self.assertEqual(form["step_id"], "hassio_confirm")
        with mock.patch.object(module.secrets, "token_urlsafe", side_effect=AssertionError("must reuse")):
            entry = await recovered.async_step_hassio_confirm({})
        self.assertEqual(entry["data"]["api_token"], TOKEN)
        self.assertEqual(_PairingClient.calls[-1][3], hashlib.sha256(TOKEN.encode()).hexdigest())

    async def test_fresh_expired_and_mismatched_recovery_fail_closed(self):
        result = await module.CezPndConfigFlow().async_step_hassio(
            _discovery(expires_at="2020-01-01T00:00:00Z")
        )
        self.assertEqual(result, {"type": "abort", "reason": "discovery_expired"})
        _Store.data = {
            "schema_version": 1, "meter_id": METER_ID,
            "collector_url": "https://other-cez-pnd-collector:8443",
            "api_token": TOKEN, "ca_certificate": VALID_CA, "phase": "onboarding",
        }
        result = await module.CezPndConfigFlow().async_step_hassio(_discovery())
        self.assertEqual(result, {"type": "abort", "reason": "discovery_invalid"})

    async def test_journal_readback_failure_prevents_claim(self):
        flow = module.CezPndConfigFlow()
        await flow.async_step_hassio(_discovery())
        _Store.fail_readback = True
        result = await flow.async_step_hassio_confirm({})
        self.assertEqual(result["errors"], {"base": "pairing_unavailable"})
        self.assertEqual(_PairingClient.calls, [])

    async def test_duplicate_aborts_before_journal_or_claim(self):
        flow = module.CezPndConfigFlow()
        flow.configured = True
        with self.assertRaisesRegex(RuntimeError, "already_configured"):
            await flow.async_step_hassio(_discovery())
        self.assertIsNone(_Store.data)
        self.assertEqual(_PairingClient.calls, [])

    def test_journal_record_is_bounded_repr_safe_and_matches_exact_identity(self):
        record = module.PairingRecoveryRecord(METER_ID, "https://collector:8443", TOKEN, VALID_CA)
        self.assertNotIn(TOKEN, repr(record))
        self.assertTrue(record.matches(METER_ID, "https://collector:8443", VALID_CA))
        self.assertFalse(record.matches("mtr_" + "d" * 32, "https://collector:8443", VALID_CA))
        self.assertFalse(record.matches(METER_ID, "https://other:8443", VALID_CA))
        self.assertFalse(record.matches(METER_ID, "https://collector:8443", "other-ca"))
        self.assertNotIn("pairing_secret", record.as_dict())
        self.assertNotIn("api_token_sha256", record.as_dict())
        self.assertFalse(any(key.startswith("cez_") for key in record.as_dict()))

    def test_malformed_journal_records_fail_closed(self):
        valid = module.PairingRecoveryRecord(
            METER_ID, "https://collector:8443", TOKEN, VALID_CA
        ).as_dict()
        cases = (
            None,
            {**valid, "unexpected": True},
            {**valid, "schema_version": True},
            {**valid, "meter_id": "invalid"},
            {**valid, "api_token": "short"},
            {**valid, "phase": "active"},
        )
        for label, candidate in enumerate(cases):
            with self.subTest(case=label), self.assertRaises(module.PairingRecoveryError):
                module.PairingRecoveryRecord.from_dict(candidate)


if __name__ == "__main__":
    unittest.main()
