"""Fail-closed loading of Collector runtime configuration."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import base64
import binascii
import json
import os
from pathlib import Path
import ssl
import tempfile
from typing import Iterator
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .api import EXPECTED_SCOPES, TokenVerifier
from .security_files import descriptor_path, open_verified_file


SUPERVISOR_SELF_INFO_URL = "http://supervisor/addons/self/info"
TOKEN_VERIFIER_FILE = Path("/data/auth/client.json")
TLS_CERT_FILE = Path("/data/tls/server.crt")
TLS_KEY_FILE = Path("/data/tls/server.key")
MAX_SUPERVISOR_RESPONSE_BYTES = 256 * 1024
MAX_TLS_MATERIAL_BYTES = 64 * 1024
TMP_DIRECTORY = Path("/tmp")

PRIVATE_CONFIGURATION_ERROR_CODES = frozenset(
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
    }
)


class PrivateConfigurationError(ValueError):
    """Fail-closed configuration error containing only an allowlisted code."""

    def __init__(self, code: str) -> None:
        if code not in PRIVATE_CONFIGURATION_ERROR_CODES:
            raise ValueError("unknown private configuration error code")
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class RuntimeConfiguration:
    """Validated API verifier and an initialized TLS server context."""

    verifier: TokenVerifier
    tls_context: ssl.SSLContext
    source: str


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(  # type: ignore[no-untyped-def]
        self, req, fp, code, msg, headers, newurl
    ):
        raise ValueError("Supervisor configuration endpoint redirected")


def load_runtime_configuration() -> RuntimeConfiguration:
    """Load HA App options through Supervisor, or fixed files outside HA OS."""

    supervisor_token = os.environ.get("SUPERVISOR_TOKEN")
    if supervisor_token:
        options = _read_supervisor_options(supervisor_token)
        try:
            verifier = TokenVerifier.from_mapping(
                {
                    "schema_version": "1",
                    "token_sha256": options.get("api_token_sha256"),
                    "meter_id": options.get("meter_id"),
                    "scopes": sorted(EXPECTED_SCOPES),
                }
            )
        except (TypeError, ValueError) as error:
            raise PrivateConfigurationError(
                "private_config_invalid_token_verifier"
            ) from error
        certificate = _decode_tls_option(options, "tls_certificate_b64")
        private_key = _decode_tls_option(options, "tls_private_key_b64")
        return RuntimeConfiguration(
            verifier=verifier,
            tls_context=_context_from_memory(certificate, private_key),
            source="supervisor_self_info",
        )

    try:
        verifier = TokenVerifier.from_file(TOKEN_VERIFIER_FILE)
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise PrivateConfigurationError("private_config_file_verifier_failed") from error
    try:
        context = _new_tls_context()
        with open_verified_file(TLS_CERT_FILE, private=False) as cert_descriptor:
            with open_verified_file(TLS_KEY_FILE, private=True) as key_descriptor:
                context.load_cert_chain(
                    descriptor_path(cert_descriptor), descriptor_path(key_descriptor)
                )
    except (OSError, ValueError, ssl.SSLError) as error:
        raise PrivateConfigurationError("private_config_file_tls_load_failed") from error
    return RuntimeConfiguration(verifier=verifier, tls_context=context, source="files")


def _read_supervisor_options(supervisor_token: str) -> dict[str, object]:
    if len(supervisor_token) > 8192 or any(
        character.isspace() for character in supervisor_token
    ):
        raise PrivateConfigurationError("private_config_invalid_supervisor_token")
    try:
        request = Request(
            SUPERVISOR_SELF_INFO_URL,
            headers={
                "Authorization": f"Bearer {supervisor_token}",
                "Accept": "application/json",
            },
            method="GET",
        )
        opener = build_opener(_RejectRedirects())
        with opener.open(request, timeout=5.0) as response:
            if response.status != 200:
                raise PrivateConfigurationError(
                    "private_config_supervisor_request_failed"
                )
            body = response.read(MAX_SUPERVISOR_RESPONSE_BYTES + 1)
    except PrivateConfigurationError:
        raise
    except (HTTPError, URLError, TimeoutError, OSError, TypeError, ValueError) as error:
        raise PrivateConfigurationError(
            "private_config_supervisor_request_failed"
        ) from error
    if len(body) > MAX_SUPERVISOR_RESPONSE_BYTES:
        raise PrivateConfigurationError(
            "private_config_supervisor_response_too_large"
        )
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise PrivateConfigurationError(
            "private_config_supervisor_response_invalid"
        ) from error
    if not isinstance(payload, dict) or payload.get("result") != "ok":
        raise PrivateConfigurationError("private_config_supervisor_response_invalid")
    data = payload.get("data")
    if not isinstance(data, dict):
        raise PrivateConfigurationError("private_config_supervisor_response_invalid")
    options = data.get("options")
    if not isinstance(options, dict):
        raise PrivateConfigurationError("private_config_supervisor_response_invalid")
    return options


def _decode_tls_option(options: dict[str, object], name: str) -> bytes:
    if name == "tls_certificate_b64":
        missing_code = "private_config_missing_tls_certificate"
        encoding_code = "private_config_invalid_certificate_encoding"
        size_code = "private_config_invalid_certificate_size"
    elif name == "tls_private_key_b64":
        missing_code = "private_config_missing_tls_private_key"
        encoding_code = "private_config_invalid_private_key_encoding"
        size_code = "private_config_invalid_private_key_size"
    else:
        raise ValueError("unsupported TLS option name")
    encoded = options.get(name)
    if encoded is None or encoded == "":
        raise PrivateConfigurationError(missing_code)
    if not isinstance(encoded, str):
        raise PrivateConfigurationError(encoding_code)
    if len(encoded) > 128 * 1024:
        raise PrivateConfigurationError(size_code)
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as error:
        raise PrivateConfigurationError(encoding_code) from error
    if not decoded or len(decoded) > MAX_TLS_MATERIAL_BYTES:
        raise PrivateConfigurationError(size_code)
    return decoded


def _new_tls_context() -> ssl.SSLContext:
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    except (OSError, ValueError, ssl.SSLError) as error:
        raise PrivateConfigurationError(
            "private_config_ssl_context_create_failed"
        ) from error
    return context


def _context_from_memory(certificate: bytes, private_key: bytes) -> ssl.SSLContext:
    context = _new_tls_context()
    try:
        with _temporary_private_file(certificate) as certificate_path:
            with _temporary_private_file(private_key) as private_key_path:
                try:
                    context.load_cert_chain(certificate_path, private_key_path)
                except ssl.SSLError as error:
                    code = (
                        "private_config_key_mismatch"
                        if getattr(error, "reason", None) == "KEY_VALUES_MISMATCH"
                        else "private_config_ssl_context_load_failed"
                    )
                    raise PrivateConfigurationError(code) from error
                except (OSError, ValueError) as error:
                    raise PrivateConfigurationError(
                        "private_config_ssl_context_load_failed"
                    ) from error
    except PrivateConfigurationError:
        raise
    except OSError as error:
        raise PrivateConfigurationError(
            "private_config_tls_temporary_file_failed"
        ) from error
    return context


@contextmanager
def _temporary_private_file(content: bytes) -> Iterator[str]:
    descriptor, path = tempfile.mkstemp(prefix="collector-tls-", dir=TMP_DIRECTORY)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(content)
            stream.flush()
        descriptor = -1
        yield path
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
