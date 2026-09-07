"""Race-resistant access to fixed private Collector files."""

from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import stat
from typing import Iterator


@contextmanager
def open_verified_file(path: Path, *, private: bool) -> Iterator[int]:
    """Open a regular file without following its final symlink component."""

    if (
        not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_CLOEXEC")
        or not Path("/proc/self/fd").is_dir()
    ):
        raise OSError("required secure file-opening mechanism is unavailable")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        _validate_file_metadata(os.fstat(descriptor), private=private)
        yield descriptor
    finally:
        os.close(descriptor)


def read_private_file(path: Path, *, maximum_bytes: int) -> bytes:
    """Read one bounded UID-2000 private regular file."""

    with open_verified_file(path, private=True) as descriptor:
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 4096))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > maximum_bytes:
            raise ValueError("private file exceeds size limit")
        return data


def descriptor_path(descriptor: int) -> str:
    """Return the already-open Linux descriptor path used by OpenSSL."""

    return f"/proc/self/fd/{descriptor}"


def _validate_file_metadata(metadata: os.stat_result, *, private: bool) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("security material must be a regular file")
    if private and metadata.st_uid != 2000:
        raise ValueError("private file must be owned by UID 2000")
    forbidden_mode = 0o077 if private else 0o022
    if stat.S_IMODE(metadata.st_mode) & forbidden_mode:
        raise ValueError("unsafe security file mode")
