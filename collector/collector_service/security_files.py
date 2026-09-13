"""Race-resistant access to fixed private Collector files."""

from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import stat
import secrets
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


def atomic_write_private(path: Path, content: bytes, *, maximum_bytes: int) -> None:
    """Atomically replace one bounded UID-2000 private file using a directory FD."""

    if not content or len(content) > maximum_bytes:
        raise ValueError("private file content is invalid")
    if path.name in {"", ".", ".."} or path.parent == path:
        raise ValueError("unsafe private file")
    required = ("O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW")
    if any(not hasattr(os, name) for name in required):
        raise OSError("required secure file-writing mechanism is unavailable")
    directory = path.parent
    directory_descriptor = os.open(
        directory,
        os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    temporary_name = f".{path.name}.{secrets.token_hex(16)}.tmp"
    try:
        directory_metadata = os.fstat(directory_descriptor)
        if (
            not stat.S_ISDIR(directory_metadata.st_mode)
            or directory_metadata.st_uid != 2000
            or stat.S_IMODE(directory_metadata.st_mode) != 0o700
        ):
            raise ValueError("unsafe private directory")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
        descriptor = os.open(temporary_name, flags, 0o600, dir_fd=directory_descriptor)
        try:
            try:
                view = memoryview(content)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise OSError("private file write failed")
                    view = view[written:]
                os.fchmod(descriptor, 0o600)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            try:
                existing = os.stat(
                    path.name,
                    dir_fd=directory_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                pass
            else:
                _validate_file_metadata(existing, private=True)
            os.replace(
                temporary_name,
                path.name,
                src_dir_fd=directory_descriptor,
                dst_dir_fd=directory_descriptor,
            )
            os.fsync(directory_descriptor)
        finally:
            try:
                os.unlink(temporary_name, dir_fd=directory_descriptor)
            except FileNotFoundError:
                pass
    finally:
        os.close(directory_descriptor)


def _validate_file_metadata(metadata: os.stat_result, *, private: bool) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("security material must be a regular file")
    if private and metadata.st_uid != 2000:
        raise ValueError("private file must be owned by UID 2000")
    forbidden_mode = 0o077 if private else 0o022
    if stat.S_IMODE(metadata.st_mode) & forbidden_mode:
        raise ValueError("unsafe security file mode")
