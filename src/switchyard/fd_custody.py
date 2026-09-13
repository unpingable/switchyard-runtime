"""Strictly relative access below an explicitly inherited directory descriptor."""
from __future__ import annotations

import os
from pathlib import PurePosixPath
import sqlite3
import stat


class FdCustodyError(ValueError):
    pass


def relative_parts(value: str) -> tuple[str, ...]:
    if not isinstance(value, str) or not value or value.startswith("/") or "\x00" in value:
        raise FdCustodyError("fd-relative path must be nonempty and relative")
    raw_parts = value.split("/")
    if any(part in {"", ".", ".."} for part in raw_parts):
        raise FdCustodyError("fd-relative path contains a refused component")
    parts = PurePosixPath(value).parts
    if tuple(raw_parts) != parts:
        raise FdCustodyError("fd-relative path spelling is not canonical")
    return tuple(raw_parts)


def duplicate_directory(root_fd: int) -> int:
    try:
        result = os.dup(root_fd)
    except OSError as error:
        raise FdCustodyError("inherited root descriptor is unavailable") from error
    if not stat.S_ISDIR(os.fstat(result).st_mode):
        os.close(result)
        raise FdCustodyError("inherited root descriptor is not a directory")
    return result


def open_parent(root_fd: int, relative: str) -> tuple[int, str]:
    parts = relative_parts(relative)
    descriptor = duplicate_directory(root_fd)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor, parts[-1]
    except BaseException:
        os.close(descriptor)
        raise


def read_bounded_regular_at(root_fd: int, relative: str, maximum: int, label: str) -> bytes:
    if type(maximum) is not int or maximum < 1:
        raise FdCustodyError(f"invalid {label} bound")
    parent, name = open_parent(root_fd, relative)
    descriptor = None
    try:
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            raise FdCustodyError(f"{label} is not a bounded regular file")
        chunks: list[bytes] = []
        total = 0
        while True:
            block = os.read(descriptor, min(65536, maximum + 1 - total))
            if not block:
                break
            total += len(block)
            if total > maximum:
                raise FdCustodyError(f"{label} exceeds bound")
            chunks.append(block)
        after = os.fstat(descriptor)
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(before, field) != getattr(after, field) for field in fields):
            raise FdCustodyError(f"{label} changed while read")
        return b"".join(chunks)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)


def write_exclusive_at(root_fd: int, relative: str, raw: bytes) -> None:
    parent, name = open_parent(root_fd, relative)
    descriptor = None
    try:
        descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=parent)
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise FdCustodyError("fd-relative write made no progress")
            view = view[written:]
        os.fsync(descriptor)
        os.fsync(parent)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)


class RelativePath:
    """Minimal path projection whose I/O stays relative to a held root."""
    def __init__(self, root_fd: int, relative: str):
        checked = duplicate_directory(root_fd)
        os.close(checked)  # validate without taking ownership
        self.root_fd = root_fd
        self.relative = "/".join(relative_parts(relative))

    def __truediv__(self, child: str) -> "RelativePath":
        return RelativePath(self.root_fd, self.relative + "/" + child)

    def __str__(self) -> str:
        return f"/proc/{os.getpid()}/fd/{self.root_fd}/{self.relative}"

    def __fspath__(self) -> str:
        return str(self)

    def exists(self) -> bool:
        parent, name = open_parent(self.root_fd, self.relative)
        try:
            try:
                os.stat(name, dir_fd=parent, follow_symlinks=False)
                return True
            except FileNotFoundError:
                return False
        finally:
            os.close(parent)

    def read_bytes(self) -> bytes:
        return read_bounded_regular_at(self.root_fd, self.relative, 16 * 1024 * 1024,
                                       "closeout artifact")

    def write_bytes(self, raw: bytes) -> int:
        write_exclusive_at(self.root_fd, self.relative, raw)
        return len(raw)

    def write_text(self, text: str, encoding: str = "utf-8") -> int:
        return self.write_bytes(text.encode(encoding))

    def mkdir(self, mode: int = 0o777, parents: bool = False, exist_ok: bool = False) -> None:
        if parents or exist_ok:
            raise FdCustodyError("fd-relative mkdir requires one absent child")
        parent, name = open_parent(self.root_fd, self.relative)
        try:
            os.mkdir(name, mode, dir_fd=parent)
            os.fsync(parent)
        finally:
            os.close(parent)

    def resolve(self) -> "RelativePath":
        parent, name = open_parent(self.root_fd, self.relative)
        try:
            value = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if not stat.S_ISDIR(value.st_mode):
                raise FdCustodyError("fd-relative resolved path is not a directory")
        finally:
            os.close(parent)
        return self


class HeldSqlite:
    """A SQLite main file held by inode; sidecars remain below its held parent."""

    def __init__(self, root_fd: int, relative: str, *, create: bool):
        self.parent_fd, self.name = open_parent(root_fd, relative)
        flags = (os.O_RDWR | os.O_CREAT) if create else os.O_RDONLY
        try:
            self.fd = os.open(self.name, flags | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                              dir_fd=self.parent_fd)
            if not stat.S_ISREG(os.fstat(self.fd).st_mode):
                raise FdCustodyError("SQLite state is not regular")
            for suffix in ("-wal", "-shm", "-journal"):
                try:
                    value = os.stat(self.name + suffix, dir_fd=self.parent_fd, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                if not stat.S_ISREG(value.st_mode):
                    raise FdCustodyError("SQLite sidecar is not regular")
        except BaseException:
            if hasattr(self, "fd"):
                os.close(self.fd)
            os.close(self.parent_fd)
            raise

    def connect(self, *, readonly: bool = False) -> sqlite3.Connection:
        # The held main-file descriptor binds the final inode. SQLite resolves
        # its actual location for ordinary same-directory WAL/SHM custody.
        path = f"/proc/self/fd/{self.fd}"
        return sqlite3.connect("file:" + path + "?mode=ro", uri=True) if readonly else sqlite3.connect(path)

    def close(self) -> None:
        os.close(self.fd)
        os.close(self.parent_fd)
