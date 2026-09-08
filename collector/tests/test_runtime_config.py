"""Regression tests for HA App configuration bootstrap."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import ssl
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
    def assert_private_code(self, expected: str, callable_, *args, **kwargs) -> None:
        with self.assertRaises(runtime_config.PrivateConfigurationError) as raised:
            callable_(*args, **kwargs)
        self.assertEqual(raised.exception.code, expected)
        self.assertEqual(str(raised.exception), expected)

    def test_private_configuration_codes_are_fixed_and_allowlisted(self) -> None:
        self.assertEqual(
            runtime_config.PRIVATE_CONFIGURATION_ERROR_CODES,
            {
                "private_config_invalid_supervisor_token",
                "private_config_supervisor_request_failed",
                "private_config_supervisor_response_too_large",
                "private_config_supervisor_response_invalid",
                "private_config_invalid_token_verifier",
                "private_config_missing_tls_certificate",
                "private_config_invalid_certificate_encoding",
                "private_config_invalid_certificate_size",
                "private_config_missing_tls_private_key",
                "private_config_invalid_private_key_encoding",
                "private_config_invalid_private_key_size",
                "private_config_ssl_context_create_failed",
                "private_config_tls_temporary_file_failed",
                "private_config_key_mismatch",
                "private_config_ssl_context_load_failed",
                "private_config_file_verifier_failed",
                "private_config_file_tls_load_failed",
            },
        )
        with self.assertRaisesRegex(ValueError, "unknown private configuration"):
            runtime_config.PrivateConfigurationError("untrusted-dynamic-value")

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
        ), self.assertRaises(runtime_config.PrivateConfigurationError) as raised:
            runtime_config._read_supervisor_options(supervisor_token)
        self.assertEqual(
            raised.exception.code, "private_config_supervisor_request_failed"
        )
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
            with self.assertRaises(runtime_config.PrivateConfigurationError) as raised:
                runtime_config._read_supervisor_options("platform-token")
            self.assertEqual(
                raised.exception.code,
                "private_config_supervisor_response_too_large",
            )
        with self.assertRaises(runtime_config.PrivateConfigurationError) as raised:
            runtime_config._read_supervisor_options("must not contain spaces")
        self.assertEqual(
            raised.exception.code, "private_config_invalid_supervisor_token"
        )

    def test_malformed_supervisor_payload_fails_closed(self) -> None:
        opener = mock.Mock()
        for payload in (b"{}", b'{"result":"ok","data":{}}', b"not-json"):
            opener.open.return_value = _FakeResponse(payload)
            with self.subTest(payload=payload), mock.patch(
                "collector_service.runtime_config.build_opener", return_value=opener
            ), self.assertRaises(runtime_config.PrivateConfigurationError) as raised:
                runtime_config._read_supervisor_options("platform-token")
            self.assertEqual(
                raised.exception.code, "private_config_supervisor_response_invalid"
            )

    def test_supervisor_non_200_fails_with_fixed_request_code(self) -> None:
        response = _FakeResponse(b"{}")
        response.status = 403
        opener = mock.Mock()
        opener.open.return_value = response
        with mock.patch(
            "collector_service.runtime_config.build_opener", return_value=opener
        ):
            self.assert_private_code(
                "private_config_supervisor_request_failed",
                runtime_config._read_supervisor_options,
                "platform-token",
            )

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
            runtime_config._decode_tls_option(
                {"tls_certificate_b64": "c2FmZQ=="}, "tls_certificate_b64"
            ),
            b"safe",
        )
        cases = (
            ("tls_certificate_b64", None, "private_config_missing_tls_certificate"),
            ("tls_certificate_b64", "", "private_config_missing_tls_certificate"),
            ("tls_certificate_b64", 1, "private_config_invalid_certificate_encoding"),
            ("tls_certificate_b64", "***", "private_config_invalid_certificate_encoding"),
            (
                "tls_certificate_b64",
                "A" * (128 * 1024 + 1),
                "private_config_invalid_certificate_size",
            ),
            ("tls_private_key_b64", None, "private_config_missing_tls_private_key"),
            ("tls_private_key_b64", "", "private_config_missing_tls_private_key"),
            ("tls_private_key_b64", 1, "private_config_invalid_private_key_encoding"),
            ("tls_private_key_b64", "***", "private_config_invalid_private_key_encoding"),
            (
                "tls_private_key_b64",
                "A" * (128 * 1024 + 1),
                "private_config_invalid_private_key_size",
            ),
        )
        for name, value, code in cases:
            with self.subTest(name=name, value_type=type(value).__name__, code=code):
                self.assert_private_code(
                    code, runtime_config._decode_tls_option, {name: value}, name
                )

    def test_invalid_token_verifier_has_fixed_non_secret_code(self) -> None:
        options = {
            "meter_id": "not-an-identifier",
            "api_token_sha256": "not-a-verifier",
            "tls_certificate_b64": "Y2VydA==",
            "tls_private_key_b64": "a2V5",
        }
        with mock.patch.dict(
            os.environ, {"SUPERVISOR_TOKEN": "platform-token"}, clear=True
        ), mock.patch(
            "collector_service.runtime_config._read_supervisor_options",
            return_value=options,
        ):
            self.assert_private_code(
                "private_config_invalid_token_verifier",
                runtime_config.load_runtime_configuration,
            )

    def test_tls_context_creation_failure_has_fixed_code(self) -> None:
        with mock.patch(
            "collector_service.runtime_config.ssl.SSLContext",
            side_effect=OSError("non-secret platform failure"),
        ):
            self.assert_private_code(
                "private_config_ssl_context_create_failed",
                runtime_config._new_tls_context,
            )

    def test_tls_temporary_file_failure_has_fixed_code(self) -> None:
        with mock.patch(
            "collector_service.runtime_config._new_tls_context",
            return_value=mock.Mock(),
        ), mock.patch(
            "collector_service.runtime_config._temporary_private_file",
            side_effect=OSError("non-secret temporary-file failure"),
        ):
            self.assert_private_code(
                "private_config_tls_temporary_file_failed",
                runtime_config._context_from_memory,
                b"certificate",
                b"private-key",
            )

    def test_ssl_context_load_and_key_mismatch_have_fixed_codes(self) -> None:
        class _KeyMismatchError(ssl.SSLError):
            reason = "KEY_VALUES_MISMATCH"

        for error, code in (
            (
                ssl.SSLError("non-secret parse failure"),
                "private_config_ssl_context_load_failed",
            ),
            (_KeyMismatchError("non-secret mismatch"), "private_config_key_mismatch"),
            (
                OSError("non-secret load failure"),
                "private_config_ssl_context_load_failed",
            ),
        ):
            context = mock.Mock()
            context.load_cert_chain.side_effect = error
            with self.subTest(code=code, error_type=type(error).__name__), mock.patch(
                "collector_service.runtime_config._new_tls_context",
                return_value=context,
            ), mock.patch(
                "collector_service.runtime_config._temporary_private_file"
            ) as temporary_file:
                temporary_file.side_effect = [
                    mock.MagicMock(__enter__=mock.Mock(return_value="certificate")),
                    mock.MagicMock(__enter__=mock.Mock(return_value="private-key")),
                ]
                self.assert_private_code(
                    code,
                    runtime_config._context_from_memory,
                    b"certificate",
                    b"private-key",
                )

    def test_fixed_file_failures_have_fixed_codes(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch(
            "collector_service.runtime_config.TokenVerifier.from_file",
            side_effect=OSError("non-secret verifier failure"),
        ):
            self.assert_private_code(
                "private_config_file_verifier_failed",
                runtime_config.load_runtime_configuration,
            )

        verifier = mock.Mock()
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch(
            "collector_service.runtime_config.TokenVerifier.from_file",
            return_value=verifier,
        ), mock.patch(
            "collector_service.runtime_config._new_tls_context",
            return_value=mock.Mock(),
        ), mock.patch(
            "collector_service.runtime_config.open_verified_file",
            side_effect=OSError("non-secret TLS file failure"),
        ):
            self.assert_private_code(
                "private_config_file_tls_load_failed",
                runtime_config.load_runtime_configuration,
            )

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
