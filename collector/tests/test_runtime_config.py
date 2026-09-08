"""Regression tests for HA App configuration bootstrap."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import tempfile
import unittest
from unittest import mock
from urllib.error import URLError

from collector_service.api import SYNTHETIC_METER_ID
from collector_service import runtime_config


class _FakeResponse:
    status = 200

    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, amount: int) -> bytes:
        return self.payload[:amount]


class RuntimeConfigurationTest(unittest.TestCase):
    def test_supervisor_self_info_url_is_exact_v2_app_route(self) -> None:
        self.assertEqual(
            runtime_config.SUPERVISOR_SELF_INFO_URL,
            "http://supervisor/v2/apps/self/info",
        )
        executable_source = Path(runtime_config.__file__).read_text(encoding="utf-8")
        self.assertNotIn(
            '"http://supervisor/apps/self/info"', executable_source
        )

    def test_supervisor_redirect_is_rejected(self) -> None:
        handler = runtime_config._RejectRedirects()
        with self.assertRaisesRegex(ValueError, "redirected"):
            handler.redirect_request(
                None, None, 302, "Found", {}, "http://other.invalid"
            )

    def test_supervisor_options_use_fixed_bounded_authenticated_request(self) -> None:
        payload = json.dumps(
            {"result": "ok", "data": {"options": {"safe": "value"}}}
        ).encode()
        opener = mock.Mock()
        opener.open.return_value = _FakeResponse(payload)
        with mock.patch(
            "collector_service.runtime_config.build_opener", return_value=opener
        ) as build_opener_mock:
            options = runtime_config._read_supervisor_options("platform-token")
        self.assertEqual(options, {"safe": "value"})
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, "http://supervisor/v2/apps/self/info")
        self.assertEqual(request.get_header("Authorization"), "Bearer platform-token")
        self.assertEqual(opener.open.call_args.kwargs["timeout"], 5.0)
        redirect_handler = build_opener_mock.call_args.args[0]
        self.assertIsInstance(redirect_handler, runtime_config._RejectRedirects)

    def test_supervisor_transport_failure_does_not_expose_token(self) -> None:
        supervisor_token = "private-platform-token"
        opener = mock.Mock()
        opener.open.side_effect = URLError("offline")
        with mock.patch(
            "collector_service.runtime_config.build_opener", return_value=opener
        ), self.assertRaises(ValueError) as raised:
            runtime_config._read_supervisor_options(supervisor_token)
        self.assertNotIn(supervisor_token, str(raised.exception))

    def test_supervisor_response_limit_and_token_shape_fail_closed(self) -> None:
        self.assertEqual(runtime_config.MAX_SUPERVISOR_RESPONSE_BYTES, 256 * 1024)
        opener = mock.Mock()
        opener.open.return_value = _FakeResponse(
            b"x" * (runtime_config.MAX_SUPERVISOR_RESPONSE_BYTES + 1)
        )
        with mock.patch(
            "collector_service.runtime_config.build_opener", return_value=opener
        ):
            with self.assertRaisesRegex(ValueError, "size limit"):
                runtime_config._read_supervisor_options("platform-token")
        with self.assertRaisesRegex(ValueError, "token shape"):
            runtime_config._read_supervisor_options("must not contain spaces")

    def test_malformed_supervisor_payload_fails_closed(self) -> None:
        opener = mock.Mock()
        for payload in (b"{}", b'{"result":"ok","data":{}}', b"not-json"):
            opener.open.return_value = _FakeResponse(payload)
            with self.subTest(payload=payload), mock.patch(
                "collector_service.runtime_config.build_opener", return_value=opener
            ), self.assertRaises(ValueError):
                runtime_config._read_supervisor_options("platform-token")

    def test_ha_options_contain_verifier_not_plaintext_api_token(self) -> None:
        token = secrets.token_urlsafe(32)
        options = {
            "meter_id": SYNTHETIC_METER_ID,
            "api_token_sha256": hashlib.sha256(token.encode("ascii")).hexdigest(),
            "tls_certificate_b64": base64.b64encode(b"certificate").decode("ascii"),
            "tls_private_key_b64": base64.b64encode(b"private-key").decode("ascii"),
        }
        fake_context = mock.Mock()
        with (
            mock.patch.dict(
                os.environ, {"SUPERVISOR_TOKEN": "platform-token"}, clear=True
            ),
            mock.patch(
                "collector_service.runtime_config._read_supervisor_options",
                return_value=options,
            ),
            mock.patch(
                "collector_service.runtime_config._context_from_memory",
                return_value=fake_context,
            ) as context_from_memory,
        ):
            configuration = runtime_config.load_runtime_configuration()
        self.assertEqual(configuration.source, "supervisor_self_info")
        self.assertEqual(
            configuration.verifier.token_sha256, options["api_token_sha256"]
        )
        self.assertNotEqual(configuration.verifier.token_sha256, token)
        context_from_memory.assert_called_once_with(b"certificate", b"private-key")

    def test_tls_option_decoding_is_strict_and_bounded(self) -> None:
        self.assertEqual(
            runtime_config._decode_tls_option({"material": "c2FmZQ=="}, "material"), b"safe"
        )
        for value in (None, "", "***", "A" * (128 * 1024 + 1)):
            with self.subTest(value_type=type(value).__name__), self.assertRaises(ValueError):
                runtime_config._decode_tls_option({"material": value}, "material")

    @unittest.skipUnless(hasattr(os, "fchmod"), "Linux descriptor mode API required")
    def test_temporary_tls_file_is_private_and_removed(self) -> None:
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            runtime_config, "TMP_DIRECTORY", Path(directory)
        ):
            with runtime_config._temporary_private_file(b"private") as path:
                material_path = Path(path)
                self.assertEqual(material_path.read_bytes(), b"private")
                self.assertEqual(stat.S_IMODE(material_path.stat().st_mode), 0o600)
            self.assertFalse(material_path.exists())


if __name__ == "__main__":
    unittest.main()
