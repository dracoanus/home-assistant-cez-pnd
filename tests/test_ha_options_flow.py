"""Focused tests for the Home Assistant polling options flow."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType, SimpleNamespace
import sys
import unittest
from unittest.mock import AsyncMock


ROOT = Path(__file__).parents[1]
INTEGRATION = ROOT / "custom_components" / "cez_pnd"


class _Required:
    def __init__(self, key, *, default=None) -> None:
        self.key = key
        self.default = default


class _Schema:
    def __init__(self, schema) -> None:
        self.schema = schema


class _SelectorConfig:
    def __init__(self, **kwargs) -> None:
        self.values = kwargs


class _Selector:
    def __init__(self, config) -> None:
        self.config = config


class _ConfigFlow:
    def __init_subclass__(cls, domain=None, **kwargs):
        super().__init_subclass__(**kwargs)


class _OptionsFlow:
    def async_create_entry(self, *, title, data):
        return {"type": "create_entry", "title": title, "data": data}

    def async_show_form(self, *, step_id, data_schema, errors):
        return {
            "type": "form",
            "step_id": step_id,
            "data_schema": data_schema,
            "errors": errors,
        }


def _install_ha_stubs() -> None:
    voluptuous = ModuleType("voluptuous")
    voluptuous.Required = _Required
    voluptuous.Schema = _Schema
    sys.modules["voluptuous"] = voluptuous

    homeassistant = ModuleType("homeassistant")
    config_entries = ModuleType("homeassistant.config_entries")
    config_entries.ConfigEntry = object
    config_entries.ConfigFlow = _ConfigFlow
    config_entries.OptionsFlow = _OptionsFlow
    config_entries.ConfigFlowResult = dict
    core = ModuleType("homeassistant.core")
    core.HomeAssistant = object
    helpers = ModuleType("homeassistant.helpers")
    selector = ModuleType("homeassistant.helpers.selector")
    selector.TextSelector = _Selector
    selector.TextSelectorConfig = _SelectorConfig
    selector.TextSelectorType = SimpleNamespace(URL="url", PASSWORD="password")
    selector.NumberSelector = _Selector
    selector.NumberSelectorConfig = _SelectorConfig
    selector.NumberSelectorMode = SimpleNamespace(BOX="box")
    aiohttp_client = ModuleType("homeassistant.helpers.aiohttp_client")
    aiohttp_client.async_get_clientsession = lambda _hass: object()
    helpers.selector = selector
    sys.modules.update(
        {
            "homeassistant": homeassistant,
            "homeassistant.config_entries": config_entries,
            "homeassistant.core": core,
            "homeassistant.helpers": helpers,
            "homeassistant.helpers.selector": selector,
            "homeassistant.helpers.aiohttp_client": aiohttp_client,
        }
    )


def _load_options_module():
    _install_ha_stubs()
    package_name = "cez_pnd_options_test_package"
    package = ModuleType(package_name)
    package.__path__ = [str(INTEGRATION)]
    sys.modules[package_name] = package
    client = ModuleType(f"{package_name}.client")
    for name in (
        "CollectorAuthenticationError",
        "CollectorConfigurationError",
        "CollectorConnectionError",
        "CollectorError",
        "CollectorTlsError",
    ):
        setattr(client, name, type(name, (Exception,), {}))
    client.CollectorClient = object
    client.create_collector_ssl_context = lambda _value: object()
    sys.modules[client.__name__] = client
    name = f"{package_name}.config_flow"
    spec = importlib.util.spec_from_file_location(name, INTEGRATION / "config_flow.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


options_module = _load_options_module()


class OptionsFlowTests(unittest.IsolatedAsyncioTestCase):
    async def test_default_minimum_and_maximum_are_accepted(self) -> None:
        flow = options_module.CezPndOptionsFlow()
        flow.config_entry = SimpleNamespace(options={})
        form = await flow.async_step_init()
        required = next(iter(form["data_schema"].schema))
        selector = form["data_schema"].schema[required]
        self.assertEqual(required.default, 60)
        self.assertEqual(selector.config.values["min"], 30)
        self.assertEqual(selector.config.values["max"], 3600)
        for value in (30, 3600):
            with self.subTest(value=value):
                result = await flow.async_step_init({"poll_interval_seconds": value})
                self.assertEqual(
                    result["data"], {"poll_interval_seconds": value}
                )
        normalized = await flow.async_step_init({"poll_interval_seconds": 60.0})
        self.assertEqual(normalized["data"], {"poll_interval_seconds": 60})

        flow.config_entry = SimpleNamespace(options={"poll_interval_seconds": 120})
        configured_form = await flow.async_step_init()
        configured_required = next(iter(configured_form["data_schema"].schema))
        self.assertEqual(configured_required.default, 120)

    async def test_invalid_poll_intervals_are_rejected(self) -> None:
        flow = options_module.CezPndOptionsFlow()
        flow.config_entry = SimpleNamespace(options={"poll_interval_seconds": 120})
        for value in (29, 3601, "60", 60.5, True):
            with self.subTest(value=value):
                result = await flow.async_step_init({"poll_interval_seconds": value})
                self.assertEqual(
                    result["errors"],
                    {"poll_interval_seconds": "invalid_poll_interval"},
                )

    def test_config_flow_registers_options_handler(self) -> None:
        flow = options_module.CezPndConfigFlow.async_get_options_flow(object())
        self.assertIsInstance(flow, options_module.CezPndOptionsFlow)

    async def test_update_listener_reloads_the_entry(self) -> None:
        package_name = "cez_pnd_init_test_package"
        package = ModuleType(package_name)
        package.__path__ = [str(INTEGRATION)]
        sys.modules[package_name] = package
        homeassistant_const = ModuleType("homeassistant.const")
        homeassistant_const.Platform = SimpleNamespace(SENSOR="sensor")
        sys.modules["homeassistant.const"] = homeassistant_const
        client = ModuleType(f"{package_name}.client")
        client.CollectorClient = object
        client.create_collector_ssl_context = lambda _value: object()
        coordinator = ModuleType(f"{package_name}.coordinator")
        coordinator.CezPndCoordinator = object
        sys.modules[client.__name__] = client
        sys.modules[coordinator.__name__] = coordinator
        name = f"{package_name}.__init__"
        spec = importlib.util.spec_from_file_location(
            name,
            INTEGRATION / "__init__.py",
            submodule_search_locations=[str(INTEGRATION)],
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        hass = SimpleNamespace(
            config_entries=SimpleNamespace(async_reload=AsyncMock())
        )
        entry = SimpleNamespace(entry_id="entry-id")

        await module._async_update_listener(hass, entry)

        hass.config_entries.async_reload.assert_awaited_once_with("entry-id")


if __name__ == "__main__":
    unittest.main()
