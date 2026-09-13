"""Direct regression tests for descriptor-relative private file replacement."""

from __future__ import annotations

import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

from collector_service import security_files


def _supports_descriptor_relative_atomic_write() -> bool:
    """Return whether atomic_write_private's descriptor primitives are available."""

    return (
        all(hasattr(os, name) for name in ("O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW"))
        and all(hasattr(os, name) for name in ("fchmod", "fsync"))
        and all(
            operation in os.supports_dir_fd
            for operation in (os.open, os.stat, os.rename, os.unlink)
        )
        and os.stat in os.supports_follow_symlinks
    )


class AtomicWriteCapabilityTests(unittest.TestCase):
    def test_guard_uses_renameat_capability_for_replace_semantics(self) -> None:
        with (
            mock.patch.object(
                os,
                "supports_dir_fd",
                {os.open, os.stat, os.rename, os.unlink},
            ),
            mock.patch.object(os, "supports_follow_symlinks", {os.stat}),
            mock.patch.object(os, "O_CLOEXEC", 1, create=True),
            mock.patch.object(os, "O_DIRECTORY", 1, create=True),
            mock.patch.object(os, "O_NOFOLLOW", 1, create=True),
            mock.patch.object(os, "fchmod", mock.Mock(), create=True),
            mock.patch.object(os, "fsync", mock.Mock(), create=True),
        ):
            self.assertTrue(_supports_descriptor_relative_atomic_write())


@unittest.skipUnless(
    _supports_descriptor_relative_atomic_write(),
    "descriptor-relative atomic writes require open/stat/rename/unlink dir_fd, "
    "stat no-follow, fchmod, fsync, O_DIRECTORY and O_NOFOLLOW",
)
class AtomicPrivateWriteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name) / "identity"
        self.directory.mkdir(mode=0o700)
        self.directory.chmod(0o700)
        self.path = self.directory / "identity.json"
        self.real_fstat = os.fstat
        self.real_stat = os.stat

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _uid_2000(metadata: os.stat_result) -> os.stat_result:
        values = list(metadata)
        values[4] = 2000
        return os.stat_result(values)

    def _fstat(self, descriptor: int) -> os.stat_result:
        return self._uid_2000(self.real_fstat(descriptor))

    def _stat(self, path: str, **kwargs: object) -> os.stat_result:
        return self._uid_2000(self.real_stat(path, **kwargs))

    def _write(self, content: bytes) -> None:
        with (
            mock.patch.object(security_files.os, "fstat", side_effect=self._fstat),
            mock.patch.object(security_files.os, "stat", side_effect=self._stat),
        ):
            security_files.atomic_write_private(
                self.path, content, maximum_bytes=1024
            )

    def test_creates_and_atomically_replaces_mode_0600_file(self) -> None:
        self._write(b"first")
        first_inode = self.path.stat().st_ino
        self._write(b"second")
        self.assertEqual(self.path.read_bytes(), b"second")
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        self.assertNotEqual(self.path.stat().st_ino, first_inode)
        self.assertEqual(list(self.directory.glob(".*.tmp")), [])

    def test_symlink_target_is_rejected_and_not_replaced(self) -> None:
        target = self.directory / "target"
        target.write_bytes(b"unchanged")
        self.path.symlink_to(target)
        with self.assertRaises(ValueError):
            self._write(b"replacement")
        self.assertTrue(self.path.is_symlink())
        self.assertEqual(target.read_bytes(), b"unchanged")
        self.assertEqual(list(self.directory.glob(".*.tmp")), [])

    def test_failed_fsync_leaves_no_target_or_temporary_file(self) -> None:
        with (
            mock.patch.object(security_files.os, "fstat", side_effect=self._fstat),
            mock.patch.object(security_files.os, "fsync", side_effect=OSError("synthetic")),
        ):
            with self.assertRaises(OSError):
                security_files.atomic_write_private(
                    self.path, b"private", maximum_bytes=1024
                )
        self.assertFalse(self.path.exists())
        self.assertEqual(list(self.directory.glob(".*.tmp")), [])

    def test_failed_replace_preserves_existing_target_and_cleans_temporary(self) -> None:
        self._write(b"existing")
        with (
            mock.patch.object(security_files.os, "fstat", side_effect=self._fstat),
            mock.patch.object(security_files.os, "stat", side_effect=self._stat),
            mock.patch.object(
                security_files.os, "replace", side_effect=OSError("synthetic")
            ),
        ):
            with self.assertRaises(OSError):
                security_files.atomic_write_private(
                    self.path, b"replacement", maximum_bytes=1024
                )
        self.assertEqual(self.path.read_bytes(), b"existing")
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        self.assertEqual(list(self.directory.glob(".*.tmp")), [])


if __name__ == "__main__":
    unittest.main()
