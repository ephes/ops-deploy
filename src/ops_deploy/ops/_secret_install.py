"""Host-side installer for ``secret_file``; shipped as ``python3 -I -c <source>``.

This module is self-contained (standard library only, Python 3.8+) because its
source runs on the host. It reads base64 on stdin and installs the decoded
bytes at ``<directory>/<name>``:

1. Opens the destination directory one component at a time from ``/`` with
   ``O_NOFOLLOW``, so no symlink anywhere on the path is followed, and keeps
   the descriptor. Every later step is relative to it.
2. Reads and decodes the whole stream and checks its length before anything
   is created: an interrupted upload never touches the directory.
3. Removes staging directories an earlier killed run left behind.
4. Creates a private 0700 staging directory ``.ops-secret.<tag>.<random>``
   next to the destination and pins it by descriptor; users who may write the
   destination directory cannot change its entries. Inside it creates
   ``content`` with ``O_CREAT | O_EXCL | O_NOFOLLOW`` and mode 0600, writes,
   ``fchown``/``fchmod``/``fsync``, then renames it over the destination.

Any exception or SIGHUP/SIGINT/SIGTERM before the rename removes the staging
directory and leaves the destination as it was. The rename is the commit
point; the directory ``fsync`` and staging cleanup after it are best effort.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import os
import secrets
import signal
import stat
import sys
from typing import Any, NoReturn

TEMP_PREFIX = ".ops-secret."
STAGED = "content"
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


class InstallError(Exception):
    pass


def _on_signal(signum: int, frame: Any) -> NoReturn:
    raise SystemExit(128 + signum)


def open_directory(path: str) -> int:
    """Descriptor for absolute ``path``, refusing symlinks in every component."""

    if not path.startswith("/"):
        raise InstallError("directory must be absolute")
    flags = DIR_FLAGS
    fd = os.open("/", flags)
    try:
        for part in path.split("/"):
            if part in ("", "."):
                continue
            if part == "..":
                raise InstallError("directory must not contain '..'")
            try:
                child = os.open(part, flags, dir_fd=fd)
            except OSError as exc:
                raise InstallError(f"cannot open directory component {part!r}: {exc.strerror}") from None
            os.close(fd)
            fd = child
    except BaseException:
        os.close(fd)
        raise
    return fd


def read_payload(stream: Any, size: int) -> bytes:
    try:
        data = base64.b64decode(stream.read(), validate=False)
    except (binascii.Error, ValueError):
        raise InstallError("payload is not valid base64") from None
    if len(data) != size:
        raise InstallError(f"payload is {len(data)} bytes, expected {size} (interrupted upload?)")
    return data


def open_private_dir(dir_fd: int, entry: str, expect: os.stat_result | None = None) -> int | None:
    """Descriptor for ``entry`` if it is a private directory of this user.

    The checks run on the opened descriptor, so a swap between any earlier
    ``stat`` and the open is caught: it must be a directory owned by the
    effective user with no group or other permissions and, with ``expect``,
    the same file as ``expect``. Returns ``None`` otherwise.
    """

    try:
        fd = os.open(entry, DIR_FLAGS, dir_fd=dir_fd)
    except OSError:
        return None
    info = os.fstat(fd)
    private = (
        stat.S_ISDIR(info.st_mode)
        and info.st_uid == os.geteuid()
        and info.st_mode & 0o077 == 0
        and (expect is None or (info.st_dev, info.st_ino) == (expect.st_dev, expect.st_ino))
    )
    if not private:
        os.close(fd)
        return None
    return fd


def remove_stage(dir_fd: int, entry: str) -> None:
    """Remove staging directory ``entry`` if it is ours; never follow symlinks."""

    info = os.stat(entry, dir_fd=dir_fd, follow_symlinks=False)
    if not stat.S_ISDIR(info.st_mode):
        return
    stage_fd = open_private_dir(dir_fd, entry, expect=info)
    if stage_fd is None:
        return  # not ours, or replaced since the stat
    try:
        # Only this user can change entries of its own private directory.
        for child in os.listdir(stage_fd):
            os.unlink(child, dir_fd=stage_fd)
    finally:
        os.close(stage_fd)
    with contextlib.suppress(OSError):
        os.rmdir(entry, dir_fd=dir_fd)


def remove_leftovers(dir_fd: int, prefix: str) -> None:
    for entry in os.listdir(dir_fd):
        if entry.startswith(prefix):
            remove_stage(dir_fd, entry)


def resolve_owner(user: str | None, group: str | None) -> tuple[int, int]:
    uid = gid = -1
    if user is not None:
        import pwd

        uid = pwd.getpwnam(user).pw_uid
    if group is not None:
        import grp

        gid = grp.getgrnam(group).gr_gid
    return uid, gid


def install(
    directory: str,
    name: str,
    tag: str,
    size: int,
    mode: int,
    user: str | None,
    group: str | None,
    stream: Any,
) -> None:
    if not name or "/" in name or name in (".", ".."):
        raise InstallError("invalid file name")
    uid, gid = resolve_owner(user, group)
    data = read_payload(stream, size)
    dir_fd = open_directory(directory)
    stage = None
    try:
        prefix = f"{TEMP_PREFIX}{tag}."
        remove_leftovers(dir_fd, prefix)
        stage = prefix + secrets.token_hex(8)
        # A private 0700 directory, pinned by descriptor: other users who may
        # write the destination directory cannot swap the staged file.
        os.mkdir(stage, 0o700, dir_fd=dir_fd)
        opened = open_private_dir(dir_fd, stage)
        if opened is None or os.listdir(opened):
            if opened is not None:
                os.close(opened)
            stage = None  # not ours: never clean it up
            raise InstallError("staging directory was replaced")
        stage_fd = opened
        try:
            write_staged(stage_fd, data, uid, gid, mode)
            # The commit point: after this rename the new content is installed.
            os.rename(STAGED, name, src_dir_fd=stage_fd, dst_dir_fd=dir_fd)
        finally:
            os.close(stage_fd)
        # Best effort after the commit: failures here do not undo the install.
        with contextlib.suppress(OSError):
            os.fsync(dir_fd)
        with contextlib.suppress(OSError):
            remove_stage(dir_fd, stage)
        stage = None
    finally:
        if stage is not None:
            with contextlib.suppress(OSError):
                remove_stage(dir_fd, stage)
        os.close(dir_fd)


def write_staged(stage_fd: int, data: bytes, uid: int, gid: int, mode: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(STAGED, flags, 0o600, dir_fd=stage_fd)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view) :]
        if uid != -1 or gid != -1:
            os.fchown(fd, uid, gid)
        os.fchmod(fd, mode)
        os.fsync(fd)
    finally:
        os.close(fd)


def main(argv: list[str]) -> int:
    for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, _on_signal)
    directory, name, tag, size, mode, user, group = argv
    try:
        install(
            directory,
            name,
            tag,
            int(size),
            int(mode, 8),
            user or None,
            group or None,
            sys.stdin.buffer,
        )
    except (InstallError, KeyError, OSError) as exc:
        message = exc.args[0] if isinstance(exc, KeyError) else exc
        sys.stderr.write(f"secret_file: {message}\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
