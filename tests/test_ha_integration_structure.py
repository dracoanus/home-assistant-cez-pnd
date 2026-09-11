"""Static regression checks for the narrow Home Assistant integration."""

from __future__ import annotations

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).parents[1]
INTEGRATION = ROOT / "custom_components" / "cez_pnd"


class IntegrationStructureTests(unittest.TestCase):
    def test_manifest_and_required_files(self) -> None:
        manifest = json.loads(
            (INTEGRATION / "manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(manifest["domain"], "cez_pnd")
        self.assertTrue(manifest["config_flow"])
        self.assertEqual(manifest["iot_class"], "local_polling")
        self.assertEqual(manifest["requirements"], [])
        for name in (
            "__init__.py",
            "client.py",
            "config_flow.py",
            "coordinator.py",
            "sensor.py",
        ):
            self.assertTrue((INTEGRATION / name).is_file())

    def test_security_constraints_are_explicit(self) -> None:
        executable = "\n".join(
            path.read_text(encoding="utf-8") for path in INTEGRATION.glob("*.py")
        )
        lowered = executable.lower()
        self.assertNotIn("verify_ssl=false", lowered)
        self.assertNotIn("ssl=false", lowered)
        self.assertNotIn("--no-sandbox", lowered)
        self.assertNotIn("selenium", lowered)
        self.assertNotIn("chromium", lowered)
        self.assertNotIn("cez_password", lowered)
        self.assertNotIn("cez_username", lowered)
        self.assertIn("allow_redirects=false", lowered)
        self.assertIn("cert_required", lowered)
        self.assertIn("check_hostname = true", lowered)

    def test_config_flow_collects_only_collector_configuration(self) -> None:
        source = (INTEGRATION / "config_flow.py").read_text(encoding="utf-8")
        for field in (
            "CONF_COLLECTOR_URL",
            "CONF_METER_ID",
            "CONF_API_TOKEN",
            "CONF_CA_CERTIFICATE",
        ):
            self.assertIn(field, source)
        self.assertNotIn(
            "password", source.lower().replace("textselectortype.password", "")
        )
        self.assertNotIn("username", source.lower())

    def test_polling_options_reload_without_collector_permissions(self) -> None:
        flow = (INTEGRATION / "config_flow.py").read_text(encoding="utf-8")
        setup = (INTEGRATION / "__init__.py").read_text(encoding="utf-8")
        self.assertIn("class CezPndOptionsFlow", flow)
        self.assertIn("CONF_POLL_INTERVAL_SECONDS", flow)
        self.assertIn("entry.add_update_listener(_async_update_listener)", setup)
        self.assertIn("async_reload(entry.entry_id)", setup)

    def test_required_entities_and_missing_semantics(self) -> None:
        source = (INTEGRATION / "sensor.py").read_text(encoding="utf-8")
        for key in (
            "collector_health",
            "source_status",
            "data_timestamp",
            "last_attempt",
            "last_success",
            "completeness",
            "valid_count",
            "missing_count",
            "dataset_revision",
            "grid_import",
        ):
            self.assertIn(f'key="{key}"', source)
        self.assertIn("else None", source)

    def test_sync_sensor_names_are_explicit_without_changing_keys(self) -> None:
        for name in ("strings.json", "translations/en.json"):
            payload = json.loads((INTEGRATION / name).read_text(encoding="utf-8"))
            sensors = payload["entity"]["sensor"]
            self.assertEqual(
                sensors["last_attempt"]["name"], "Last CEZ sync attempt"
            )
            self.assertEqual(
                sensors["last_success"]["name"], "Last CEZ sync success"
            )


if __name__ == "__main__":
    unittest.main()
