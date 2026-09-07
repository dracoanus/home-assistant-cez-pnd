"""Regression tests for pull-request validation policy."""

from __future__ import annotations

from pathlib import PurePosixPath
import unittest

from ci_validate import validate_content, validate_path


class PullRequestPolicyTest(unittest.TestCase):
    def test_allowed_collector_source(self) -> None:
        validate_path(PurePosixPath("collector/collector_service/api.py"))
        validate_content(PurePosixPath("collector/example.py"), "token = generated_at_runtime")

    def test_frozen_phase2a_path_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "frozen Phase 2A"):
            validate_path(PurePosixPath("poc/phase2a-runtime/runtime_probe.py"))

    def test_smoke_runtime_and_private_files_are_rejected(self) -> None:
        for path in (
            "collector/smoke/runtime/client/token",
            "collector/smoke/runtime/data/tls/server.key",
            "collector/generated/server.crt",
            "collector/__pycache__/api.pyc",
        ):
            with self.subTest(path=path), self.assertRaises(ValueError):
                validate_path(PurePosixPath(path))

    def test_recognizable_secret_values_are_rejected(self) -> None:
        samples = (
            "-----BEGIN PRIVATE " + "KEY-----",
            "-----BEGIN " + "CERTIFICATE-----",
            "Bearer " + "A" * 43,
            "CEZ_" + "PASSWORD=definitely-not-allowed",
            "123456789" + "012345678",
        )
        for sample in samples:
            with self.subTest(sample=sample), self.assertRaises(ValueError):
                validate_content(PurePosixPath("collector/example.txt"), sample)


if __name__ == "__main__":
    unittest.main()
