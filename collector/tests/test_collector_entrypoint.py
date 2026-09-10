"""Focused tests for the root-only Collector storage bootstrap."""

from __future__ import annotations

import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

import collector_entrypoint


class CollectorEntrypointTests(unittest.TestCase):
    def test_bootstrap_creates_only_private_probe_directory(self) -> None:
        ownership: list[tuple[Path, int, int, bool]] = []
        modes: list[tuple[Path, int, bool]] = []

        def chown(path: Path, uid: int, gid: int, *, follow_symlinks: bool) -> None:
            ownership.append((path, uid, gid, follow_symlinks))

        def chmod(path: Path, mode: int, *, follow_symlinks: bool) -> None:
            self.assertFalse(follow_symlinks)
            modes.append((path, mode, follow_symlinks))
            os.chmod(path, mode)

        with tempfile.TemporaryDirectory() as temporary:
            data = Path(temporary) / "data"
            data.mkdir()
            marker = data / "existing-private-file"
            marker.write_text("unchanged")
            probe = collector_entrypoint.prepare_probe_directory(
                data, chown=chown, chmod=chmod
            )
            self.assertEqual(
                {path.name for path in data.iterdir()},
                {"existing-private-file", "cez-pnd-probe"},
            )
            self.assertEqual(marker.read_text(), "unchanged")
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(probe.stat().st_mode), 0o700)
            self.assertEqual(ownership, [(probe, 2000, 2000, False)])
            self.assertEqual(modes, [(probe, 0o700, False)])

    def test_bootstrap_rejects_symlinked_probe_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data = Path(temporary) / "data"
            target = Path(temporary) / "target"
            data.mkdir()
            target.mkdir()
            try:
                (data / "cez-pnd-probe").symlink_to(target, target_is_directory=True)
            except OSError:
                self.skipTest("directory symlinks are unavailable")
            with self.assertRaisesRegex(RuntimeError, "unsafe probe directory"):
                collector_entrypoint.prepare_probe_directory(
                    data, chown=mock.Mock(), chmod=mock.Mock()
                )

    def test_privileges_are_dropped_in_required_order(self) -> None:
        calls: list[tuple[str, object]] = []
        with mock.patch.object(
            collector_entrypoint.os,
            "setgroups",
            side_effect=lambda groups: calls.append(("setgroups", groups)),
            create=True,
        ), mock.patch.object(
            collector_entrypoint.os,
            "setgid",
            side_effect=lambda gid: calls.append(("setgid", gid)),
            create=True,
        ), mock.patch.object(
            collector_entrypoint.os,
            "setuid",
            side_effect=lambda uid: calls.append(("setuid", uid)),
            create=True,
        ), mock.patch.object(
            collector_entrypoint.os, "getuid", return_value=2000, create=True
        ), mock.patch.object(
            collector_entrypoint.os, "geteuid", return_value=2000, create=True
        ), mock.patch.object(
            collector_entrypoint.os, "getgid", return_value=2000, create=True
        ), mock.patch.object(
            collector_entrypoint.os, "getegid", return_value=2000, create=True
        ), mock.patch.object(
            collector_entrypoint.os, "getgroups", return_value=[], create=True
        ):
            collector_entrypoint.drop_privileges()
        self.assertEqual(
            calls,
            [("setgroups", []), ("setgid", 2000), ("setuid", 2000)],
        )

    def test_bootstrap_executes_server_only_after_privilege_drop(self) -> None:
        calls: list[str] = []
        with mock.patch.object(
            collector_entrypoint.os, "getuid", return_value=0, create=True
        ), mock.patch.object(
            collector_entrypoint.os, "geteuid", return_value=0, create=True
        ), mock.patch.object(
            collector_entrypoint,
            "prepare_probe_directory",
            side_effect=lambda: calls.append("prepare"),
        ), mock.patch.object(
            collector_entrypoint,
            "drop_privileges",
            side_effect=lambda: calls.append("drop"),
        ), mock.patch.object(
            collector_entrypoint.os,
            "execv",
            side_effect=lambda *_args: (calls.append("exec"), (_ for _ in ()).throw(OSError()))[1],
        ):
            self.assertEqual(collector_entrypoint.main(), 1)
        self.assertEqual(calls, ["prepare", "drop", "exec"])

    def test_bootstrap_refuses_non_root_start(self) -> None:
        with mock.patch.object(
            collector_entrypoint.os, "getuid", return_value=2000, create=True
        ), mock.patch.object(
            collector_entrypoint.os, "geteuid", return_value=2000, create=True
        ), mock.patch.object(collector_entrypoint.os, "execv") as execute:
            self.assertEqual(collector_entrypoint.main(), 1)
        execute.assert_not_called()


if __name__ == "__main__":
    unittest.main()
