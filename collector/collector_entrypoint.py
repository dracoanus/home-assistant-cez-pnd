"""Minimal root bootstrap for the Collector-owned probe storage."""

from __future__ import annotations

import os
from pathlib import Path
import stat
import sys
from typing import Callable


RUNTIME_UID = 2000
RUNTIME_GID = 2000
DATA_DIRECTORY = Path("/data")
PROBE_DIRECTORY_NAME = "cez-pnd-probe"
SERVER_ARGV = (
    "/opt/collector-venv/bin/python",
    "-m",
    "collector_service.server",
)


def prepare_probe_directory(
    data_directory: Path = DATA_DIRECTORY,
    *,
    chown: Callable[..., None] | None = None,
    chmod: Callable[..., None] | None = None,
) -> Path:
    """Create and secure only the Collector probe directory below /data."""

    if data_directory.is_symlink() or not data_directory.is_dir():
        raise RuntimeError("unsafe data directory")
    probe_directory = data_directory / PROBE_DIRECTORY_NAME
    if probe_directory.is_symlink():
        raise RuntimeError("unsafe probe directory")
    probe_directory.mkdir(mode=0o700, exist_ok=True)
    metadata = probe_directory.stat(follow_symlinks=False)
    if not stat.S_ISDIR(metadata.st_mode) or probe_directory.is_symlink():
        raise RuntimeError("unsafe probe directory")
    owner_setter = chown or os.chown
    mode_setter = chmod or os.chmod
    owner_setter(
        probe_directory,
        RUNTIME_UID,
        RUNTIME_GID,
        follow_symlinks=False,
    )
    mode_setter(probe_directory, 0o700, follow_symlinks=False)
    return probe_directory


def drop_privileges() -> None:
    """Irreversibly enter the non-root Collector runtime identity."""

    os.setgroups([])
    os.setgid(RUNTIME_GID)
    os.setuid(RUNTIME_UID)
    if (
        os.getuid() != RUNTIME_UID
        or os.geteuid() != RUNTIME_UID
        or os.getgid() != RUNTIME_GID
        or os.getegid() != RUNTIME_GID
        or os.getgroups()
    ):
        raise RuntimeError("privilege drop failed")


def main() -> int:
    """Initialize the one allowed writable directory and exec the service."""

    if os.getuid() != 0 or os.geteuid() != 0:
        return 1
    try:
        prepare_probe_directory()
        drop_privileges()
        os.execv(SERVER_ARGV[0], list(SERVER_ARGV))
    except (OSError, RuntimeError):
        return 1
    return 1


if __name__ == "__main__":
    sys.exit(main())
