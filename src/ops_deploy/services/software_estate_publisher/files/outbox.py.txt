"""Private local outbox primitives shared by emitter and one-shot sender."""

from __future__ import annotations

import fcntl
import json
import os
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path
from uuid import UUID

MAX_BYTES = 8 * 1024 * 1024
MAX_REPORTS = 32
INTERNAL = {".lock", ".delivery.json"}


class Busy(ValueError):
    """Another process holds the private outbox or whole-run lock."""


def report_name(identifier):
    return str(UUID(identifier)) + ".ndjson"


def report_id(name):
    try:
        identifier = name.removesuffix(".ndjson")
        if report_name(identifier) == name:
            return identifier
    except ValueError:
        pass
    return None


def private_directory(path):
    path = Path(path).absolute()
    # Do not silently resolve a symlink to a different spool or credential parent.
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("private path must not contain symlinks")
    info = path.stat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o077
    ):
        raise ValueError("directory must be private and owned by current user")
    return path


def private_read(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o077
            or info.st_nlink != 1
            or info.st_size > limit
        ):
            raise ValueError(
                "file must be private, regular, without hard links and within limit"
            )
        data = stream.read(limit + 1)
        if len(data) > limit:
            raise ValueError("file exceeds size limit")
        return data


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


@contextmanager
def locked(spool):
    spool = private_directory(spool)
    fd = os.open(
        spool / ".lock", os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600
    )
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o077
            or info.st_nlink != 1
        ):
            raise ValueError("unsafe outbox lock")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Busy("outbox is busy") from None
        yield spool
    finally:
        os.close(fd)


def entries(spool):
    return sorted(p for p in spool.iterdir() if p.name not in INTERNAL)


def atomic_state(spool, state):
    fd, temporary = tempfile.mkstemp(prefix=".state-", dir=spool)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(state, output, allow_nan=False)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, spool / ".delivery.json")
        sync_directory(spool)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
