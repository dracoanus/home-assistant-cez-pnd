"""Offline ConfigEntry minor migration; the polling options flow is removed."""
from copy import deepcopy
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_ha_pairing_setup as setup


class MigrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_migration_preserves_data_identity_and_unrelated_options(self):
        entry = setup._Entry()
        entry.options = {"poll_interval_seconds": 120, "unrelated_future_option": "preserve"}
        data = deepcopy(entry.data)
        entry.title, entry.unique_id = "synthetic", "stable"
        hass = SimpleNamespace(config_entries=setup._ConfigEntries())
        self.assertTrue(await setup.module.async_migrate_entry(hass, entry))
        self.assertEqual(entry.options, {"unrelated_future_option": "preserve"})
        self.assertEqual((entry.version, entry.minor_version), (1, 2))
        self.assertEqual(entry.data, data)
        self.assertEqual((entry.title, entry.unique_id), ("synthetic", "stable"))
        self.assertTrue(await setup.module.async_migrate_entry(hass, entry))
        self.assertEqual(len(hass.config_entries.updates), 1)

    async def test_absent_poll_option_still_migrates_offline(self):
        entry = setup._Entry()
        hass = SimpleNamespace(config_entries=setup._ConfigEntries())
        with patch.object(setup.module, "CollectorClient", side_effect=AssertionError("network forbidden")):
            self.assertTrue(await setup.module.async_migrate_entry(hass, entry))
        self.assertEqual(entry.options, {})
        self.assertEqual(entry.minor_version, 2)

    async def test_unknown_major_version_is_rejected(self):
        entry = setup._Entry()
        entry.version = 2
        hass = SimpleNamespace(config_entries=setup._ConfigEntries())
        self.assertFalse(await setup.module.async_migrate_entry(hass, entry))
        self.assertEqual(hass.config_entries.updates, [])


if __name__ == "__main__":
    unittest.main()
