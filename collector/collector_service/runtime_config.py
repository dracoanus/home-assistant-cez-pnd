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


SUPERVISOR_SELF_INFO_URL = "http://supervisor/apps/self/info"
TOKEN_VERIFIER_FILE = Path("/data/auth/client.json")
TLS_CERT_FILE = Path("/data/tls/server.crt")
TLS_KEY_FILE = Path("/data/tls/server.key")
MAX_SUPERVISOR_RESPONSE_BYTES = 256 * 1024
MAX_TLS_MATERIAL_BYTES = 64 * 1024
TMP_DIRECTORY = Path("/tmp")


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
        verifier = TokenVerifier.from_mapping(
            {
                "schema_version": "1",
                "token_sha256": options.get("api_token_sha256"),
                "meter_id": options.get("meter_id"),
                "scopes": sorted(EXPECTED_SCOPES),
            }
        )
        certificate = _decode_tls_option(options, "tls_certificate_b64")
        private_key = _decode_tls_option(options, "tls_private_key_b64")
        return RuntimeConfiguration(
            verifier=verifier,
            tls_context=_context_from_memory(certificate, private_key),
            source="supervisor_self_info",
        )

    verifier = TokenVerifier.from_file(TOKEN_VERIFIER_FILE)
    context = _new_tls_context()
    with open_verified_file(TLS_CERT_FILE, private=False) as cert_descriptor:
        with open_verified_file(TLS_KEY_FILE, private=True) as key_descriptor:
            context.load_cert_chain(
                descriptor_path(cert_descriptor), descriptor_path(key_descriptor)
            )
    return RuntimeConfiguration(verifier=verifier, tls_context=context, source="files")


def _read_supervisor_options(supervisor_token: str) -> dict[str, object]:
    if len(supervisor_token) > 8192 or any(
        character.isspace() for character in supervisor_token
    ):
        raise ValueError("invalid Supervisor token shape")
    request = Request(
        SUPERVISOR_SELF_INFO_URL,
        headers={
            "Authorization": f"Bearer {supervisor_token}",
            "Accept": "application/json",
        },
        method="GET",
    )
    opener = build_opener(_RejectRedirects())
    try:
        with opener.open(request, timeout=5.0) as response:
            if response.status != 200:
                raise ValueError("Supervisor self-info request failed")
            body = response.read(MAX_SUPERVISOR_RESPONSE_BYTES + 1)
    except (HTTPError, URLError, TimeoutError) as error:
        raise ValueError("Supervisor self-info request failed") from error
    if len(body) > MAX_SUPERVISOR_RESPONSE_BYTES:
        raise ValueError("Supervisor self-info response exceeds size limit")
    payload = json.loads(body.decode("utf-8"))
    if not isinstance(payload, dict) or payload.get("result") != "ok":
        raise ValueError("invalid Supervisor self-info response")
    data = payload.get("data")
    if not isinstance(data, dict):
        raise ValueError("invalid Supervisor self-info data")
    options = data.get("options")
    if not isinstance(options, dict):
        raise ValueError("missing Supervisor App options")
    return options


def _decode_tls_option(options: dict[str, object], name: str) -> bytes:
    encoded = options.get(name)
    if not isinstance(encoded, str) or not encoded or len(encoded) > 128 * 1024:
        raise ValueError("invalid TLS option")
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValueError("invalid TLS option encoding") from error
    if not decoded or len(decoded) > MAX_TLS_MATERIAL_BYTES:
        raise ValueError("invalid TLS option size")
    return decoded


def _new_tls_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def _context_from_memory(certificate: bytes, private_key: bytes) -> ssl.SSLContext:
    context = _new_tls_context()
    with _temporary_private_file(certificate) as certificate_path:
        with _temporary_private_file(private_key) as private_key_path:
            context.load_cert_chain(certificate_path, private_key_path)
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
