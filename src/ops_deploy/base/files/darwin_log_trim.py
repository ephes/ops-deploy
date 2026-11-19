"""Copy-and-truncate rotation for launchd-written logs (ops-deploy darwin_log_trim).

Usage: python3 -I log-trim MAX_BYTES KEEP FILE...

Runs as root, so it refuses whatever another user could steer:

- Each FILE must be given by its canonical path (no symbolic link, ``.`` or
  ``..`` component, no repeated ``/``), and its directory and every ancestor
  must be a directory owned by root (or, outside root's runs, by the running
  user: the tests), not writable by group or others and without an access
  control list.
- The file is opened without following a symbolic link and must be a regular
  file with one link and no access control list.
- One rotation per directory at a time: an exclusive ``flock`` on the
  directory; a directory held by another run is skipped.

A file of at least MAX_BYTES is compressed completely into
``<file>.trim-tmp`` (exclusive create, root's alone, 0600), synced and
renamed to ``<file>.trim-done``; only then is the file truncated in place
through a descriptor of the same inode, the generations moved up, the copy
published as ``<file>.1.gz`` and only then given the file's owner and mode
(without group/other write). The next run
finishes or undoes an interrupted one (see ``leftovers``). Generations only
move into the first free slot from ``.1`` up, so an interrupted shift is
completed without deleting a generation; ``.KEEP.gz`` goes only when every
slot is taken, and a slot holding anything but a regular file stops the
rotation before the copy. Lines written between the end of the copy and the truncation are lost, as
with logrotate's ``copytruncate``. Standard
library only, Python 3.9 (macOS's /usr/bin/python3).
"""

from __future__ import annotations

import contextlib
import errno
import fcntl
import gzip
import os
import re
import stat
import subprocess
import sys
import time

CHUNK = 1024 * 1024
ACL_ENTRY = re.compile(r"^\s*[0-9]+: ")


def say(message: str) -> None:
    print(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()) + " " + message, flush=True)


def has_acl(path: str) -> bool:
    """``ls -lde`` lists each ACL entry on a line of its own (`` 0: ...``) after the entry.

    The character after the mode is ``+`` only without extended attributes
    (with them it is ``@``), so the entry lines are what counts.
    """

    out = subprocess.run(["/bin/ls", "-lde", path], capture_output=True, text=True, timeout=30, check=True).stdout
    lines = out.splitlines()
    return (len(lines[0]) > 10 and lines[0][10] == "+") or any(ACL_ENTRY.match(line) for line in lines[1:])


def canonical(path: str) -> bool:
    return (
        path.startswith("/") and os.path.normpath(path) == path and "//" not in path and os.path.realpath(path) == path
    )


def trusted_directory(directory: str) -> bool:
    if not canonical(directory):
        return False
    current = "/"
    for part in [""] + [p for p in directory.split("/") if p]:
        current = os.path.join(current, part) if part else "/"
        info = os.lstat(current)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o022:
            return False
        if has_acl(current):
            return False
    return True


def exists(name: str, dfd: int) -> bool:
    try:
        os.lstat(name, dir_fd=dfd)
    except FileNotFoundError:
        return False
    return True


def make_room(name: str, keep: int, dfd: int) -> None:
    """Free ``name.1.gz``: move the generations below the first free slot up by one.

    Every existing generation must be a regular file; anything else stops the
    rotation before it changes anything.
    """

    for n in range(1, keep + 1):
        regular(f"{name}.{n}.gz", dfd)
    free = next((n for n in range(1, keep + 1) if not exists(f"{name}.{n}.gz", dfd)), None)
    if free is None:
        os.unlink(f"{name}.{keep}.gz", dir_fd=dfd)
        free = keep
    for n in range(free - 1, 0, -1):
        os.rename(f"{name}.{n}.gz", f"{name}.{n + 1}.gz", src_dir_fd=dfd, dst_dir_fd=dfd)


def make_room_check(name: str, keep: int, dfd: int) -> None:
    """Refuse before copying when a generation slot holds something other than a file."""

    for n in range(1, keep + 1):
        regular(f"{name}.{n}.gz", dfd)


def publish(done: str, name: str, keep: int, dfd: int) -> None:
    make_room(name, keep, dfd)
    os.rename(done, f"{name}.1.gz", src_dir_fd=dfd, dst_dir_fd=dfd)


def regular(name: str, dfd: int) -> bool:
    """False when missing; raises when the entry is not a regular file."""

    try:
        info = os.lstat(name, dir_fd=dfd)
    except FileNotFoundError:
        return False
    if not stat.S_ISREG(info.st_mode):
        raise RuntimeError(f"{name} is not a regular file")
    return True


def leftovers(name: str, keep: int, dfd: int) -> bool:
    """Finish or undo what an interrupted run left; True when a copy was published.

    The generated names are looked up as spelled, so the filesystem decides
    which spellings are the same entry. ``.trim-tmp``: the compression did not
    finish and nothing was truncated: delete it. ``.trim-done``: a complete
    copy; whether the file was truncated cannot always be told afterwards, so
    the copy is published (at worst one generation repeats entries; none is
    lost) and this run rotates nothing more for the file.
    """

    if regular(f"{name}.trim-tmp", dfd):
        os.unlink(f"{name}.trim-tmp", dir_fd=dfd)
        say(f"{name}: removed an interrupted copy")
    if regular(f"{name}.trim-done", dfd):
        finish(f"{name}.trim-done", dfd)
        publish(f"{name}.trim-done", name, keep, dfd)
        say(f"{name}: published a copy left by an interrupted run")
        return True
    return False


def finish(done: str, dfd: int, info: os.stat_result | None = None) -> None:
    """Hand a published generation to the log's owner and mode.

    Copies are root's alone (0600) until then; without ``info`` (a copy left
    by an interrupted run) it stays so.
    """

    if info is not None:
        os.chown(done, info.st_uid, info.st_gid, dir_fd=dfd, follow_symlinks=False)
        os.chmod(done, stat.S_IMODE(info.st_mode) & ~0o022, dir_fd=dfd, follow_symlinks=False)


def compress(source: int, name: str, info: os.stat_result, dfd: int) -> str:
    """The name of the complete copy (``<name>.trim-done``)."""

    tmp = f"{name}.trim-tmp"
    done = f"{name}.trim-done"
    out = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dfd)
    try:
        with os.fdopen(out, "wb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=int(info.st_mtime)) as packed:
                while True:
                    block = os.read(source, CHUNK)
                    if not block:
                        break
                    packed.write(block)
            raw.flush()
            os.fsync(raw.fileno())
        os.rename(tmp, done, src_dir_fd=dfd, dst_dir_fd=dfd)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp, dir_fd=dfd)
        raise
    return done


def trim(path: str, name: str, max_bytes: int, keep: int, dfd: int) -> str | None:
    if leftovers(name, keep, dfd):
        return "rotated by publishing the interrupted copy"
    try:
        source = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
    except FileNotFoundError:
        return None
    except OSError as error:
        if error.errno == errno.ELOOP:
            return "skipped: a symbolic link"
        raise
    try:
        info = os.fstat(source)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            return "skipped: not a regular file with one link"
        if info.st_size < max_bytes:
            return None
        # The directory is root's alone, so nobody else can swap the name meanwhile.
        if has_acl(path):
            return "skipped: has an access control list"
        # The size the copy is tagged with is the size read; the writer may
        # have appended meanwhile, so read to the end, then tag what was read.
        make_room_check(name, keep, dfd)
        done = compress(source, name, info, dfd)
        writer = os.open(name, os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
        try:
            now = os.fstat(writer)
            if (now.st_dev, now.st_ino) != (info.st_dev, info.st_ino):
                os.unlink(done, dir_fd=dfd)
                raise RuntimeError("replaced while it was copied")
            os.ftruncate(writer, 0)
        finally:
            os.close(writer)
        publish(done, name, keep, dfd)
        # Only the published generation gets the log's owner: a copy waiting
        # for recovery stays root's alone.
        finish(f"{name}.1.gz", dfd, info)
        return f"trimmed size={info.st_size}"
    finally:
        os.close(source)


def rotate(path: str, max_bytes: int, keep: int) -> str | None:
    directory, name = os.path.split(path)
    if not canonical(path) or not trusted_directory(directory):
        raise RuntimeError("refused: not a canonical path in a root-owned directory closed to others")
    dfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        try:
            fcntl.flock(dfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return "skipped: another rotation holds the directory"
        return trim(path, name, max_bytes, keep, dfd)
    finally:
        os.close(dfd)


def main(argv: list[str]) -> int:
    if len(argv) < 4:
        print("usage: log-trim MAX_BYTES KEEP FILE...", file=sys.stderr)
        return 2
    max_bytes, keep = int(argv[1]), int(argv[2])
    if max_bytes < 1 or keep < 1:
        print("MAX_BYTES and KEEP must be positive", file=sys.stderr)
        return 2
    status = 0
    for path in argv[3:]:
        try:
            result = rotate(path, max_bytes, keep)
        except Exception as error:  # one log's failure must not stop the others
            say(f"{path}: failed: {error}")
            status = 1
            continue
        if result is not None:
            say(f"{path}: {result}")
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv))
