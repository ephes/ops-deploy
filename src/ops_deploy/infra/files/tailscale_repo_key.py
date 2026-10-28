"""Ordinary upstream rotation detection, validation and compare-before-write.

Check fetches only the configured PUBLIC repository key and parses it in memory;
no temporary home/keyring/cache is created. Apply refetches and validates before
atomic replacement, preserving an existing valid key on HTTP/parser failure.
"""

import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.request

LIMIT = 1024 * 1024


class Refused(Exception):
    pass


def existing(path):
    for parent in reversed(path.parents):
        if parent.is_symlink():
            raise Refused("repository key parent is linked")
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > LIMIT:
        raise Refused("repository key must be a bounded ordinary single-link file")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        now = os.fstat(fd)
        if (now.st_ino, now.st_dev) != (info.st_ino, info.st_dev):
            raise Refused("repository key changed before open")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            body = stream.read(LIMIT + 1)
        after = os.fstat(fd)
        if len(body) > LIMIT or any(
            getattr(info, k) != getattr(after, k) for k in ("st_size", "st_mtime_ns", "st_ctime_ns")
        ):
            raise Refused("repository key changed during read")
    finally:
        os.close(fd)
    return info, body


def upstream(url):
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            body = response.read(LIMIT + 1)
    except OSError as error:
        raise Refused("public repository key refresh failed; existing key preserved") from error
    if not body or len(body) > LIMIT:
        raise Refused("public repository key size is invalid")
    # --show-keys with no keyring/trust database and /dev/null as home does
    # not create a gnupg directory. A real native positive/invalid control is
    # qualified separately; a parser failure never becomes absence/current.
    try:
        result = subprocess.run(
            [
                "gpg",
                "--no-options",
                "--batch",
                "--homedir",
                "/dev/null",
                "--no-keyring",
                "--trust-model",
                "always",
                "--no-auto-check-trustdb",
                "--show-keys",
                "--with-colons",
            ],
            input=body,
            capture_output=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise Refused("native public repository key parser unavailable") from error
    lines = result.stdout.splitlines()
    if (
        result.returncode
        or len(result.stdout) > LIMIT
        or not any(row.startswith(b"pub:") for row in lines)
        or not any(row.startswith(b"fpr:") for row in lines)
    ):
        raise Refused("upstream repository key is invalid; existing key preserved")
    return body


def main():
    if os.geteuid() != 0:
        raise Refused("repository key maintenance requires the existing root connection")
    action = sys.argv[1]
    if action not in ("check", "apply"):
        raise Refused("unknown repository key action")
    cfg = json.load(sys.stdin)
    path = Path(cfg["path"])
    old = existing(path)
    body = upstream(cfg["url"])
    current = (
        old is not None
        and old[1] == body
        and stat.S_IMODE(old[0].st_mode) == 0o644
        and (old[0].st_uid, old[0].st_gid) == (0, 0)
    )
    if action == "check":
        print("current" if current else "pending")
        return
    if current:
        print("current")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix="." + path.name + ".ops-deploy-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        if old is not None:
            shutil.copystat(path, temporary, follow_symlinks=False)
        os.chown(temporary, 0, 0)
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    print("current")


if __name__ == "__main__":
    try:
        main()
    except (Refused, OSError, ValueError, KeyError, TypeError) as error:
        print(str(error) if isinstance(error, Refused) else "repository key metadata/payload failed", file=sys.stderr)
        raise SystemExit(2) from None
