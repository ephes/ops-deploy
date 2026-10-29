"""Validate the scanner drop-in before atomic publication; no SSH restart here.

Candidate validation is standalone sshd syntax/algorithm validation. The deploy
also validates the combined global configuration before a changed-file restart.
It does not claim that standalone validation proves every cross-file interaction.
"""

import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

TARGET = Path("/etc/ssh/sshd_config.d/sftp-scanner.conf")


class Refusal(ValueError):
    pass


def current(content):
    try:
        fd = os.open(TARGET, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return False
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 65536:
            raise Refusal("scanner SSH drop-in is not a bounded regular file")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            body = stream.read(65537)
        return (body == content.encode() and stat.S_IMODE(metadata.st_mode) == 0o644
                and metadata.st_uid == 0 and metadata.st_gid == 0)
    finally:
        os.close(fd)


def reconcile(settings):
    if not isinstance(settings, dict) or set(settings) != {"content", "apply"}:
        raise Refusal("invalid scanner SSH payload")
    content = settings["content"]
    if not isinstance(content, str) or not content or len(content.encode()) > 65536 or "\0" in content:
        raise Refusal("invalid scanner SSH configuration")
    if type(settings["apply"]) is not bool:
        raise Refusal("invalid scanner SSH apply selector")
    if current(content):
        return "current"
    if not settings["apply"]:
        return "pending"
    if TARGET.parent.is_symlink() or not TARGET.parent.is_dir():
        raise Refusal("scanner SSH drop-in directory is missing or unsafe")
    temporary = None
    try:
        fd, temporary = tempfile.mkstemp(prefix=".paperless-scanner-ssh-", dir=TARGET.parent)
        with os.fdopen(fd, "wb") as stream:
            stream.write(content.encode())
            stream.flush()
            os.fsync(stream.fileno())
        result = subprocess.run(
            ["sshd", "-t", "-f", temporary], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, check=False,
        )
        if result.returncode:
            raise Refusal("scanner SSH candidate validation failed")
        os.chown(temporary, 0, 0)
        os.chmod(temporary, 0o644)
        os.replace(temporary, TARGET)
    finally:
        if temporary is not None and os.path.exists(temporary):
            os.unlink(temporary)
    return "changed"


def main():
    try:
        body = sys.stdin.buffer.read(131073)
        if len(body) > 131072:
            raise Refusal("scanner SSH payload exceeds size limit")
        result = reconcile(json.loads(body))
    except (ValueError, OSError, RecursionError):
        print("Paperless scanner SSH check/update failed", file=sys.stderr)
        return 1
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
