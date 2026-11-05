"""Remove exactly the scanner bind line from /etc/fstab; every other line stays byte for byte.

A line is the scanner's when its fields (comment stripped) are exactly
``<source> <target> none bind 0 0``. Lines that differ in any field (another
source, options such as ``nofail``, other dump/pass numbers) and commented-out
lines stay; so does a missing line (nothing to do).
"""

import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

FSTAB = Path("/etc/fstab")
LIMIT = 1024 * 1024


class Refusal(ValueError):
    pass


def wanted(settings):
    if not isinstance(settings, dict) or set(settings) != {"source", "target", "apply"}:
        raise Refusal("invalid scanner fstab payload")
    if type(settings["apply"]) is not bool:
        raise Refusal("invalid scanner fstab payload")
    for name in ("source", "target"):
        value = settings[name]
        if not isinstance(value, str) or not re.fullmatch(r"(?:/[A-Za-z0-9_.+-]+)+", value):
            raise Refusal("invalid scanner fstab path")
        if any(part in {".", ".."} for part in value.split("/")[1:]):
            raise Refusal("invalid scanner fstab path")
    return [settings["source"], settings["target"], "none", "bind", "0", "0"]


def fstab_absent(path, fields, apply):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > LIMIT:
            raise Refusal("fstab must be a bounded regular file")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            body = stream.read(LIMIT + 1)
        if len(body) > LIMIT:
            raise Refusal("fstab exceeded size limit")
    finally:
        os.close(fd)
    lines = body.decode().splitlines(keepends=True)
    kept = [line for line in lines if line.split("#", 1)[0].split() != fields]
    if len(kept) == len(lines):
        return False
    if not apply:
        return True
    temporary = None
    try:
        descriptor, temporary = tempfile.mkstemp(prefix=".paperless-fstab-", dir=path.parent)
        with os.fdopen(descriptor, "wb") as stream:
            os.fchown(stream.fileno(), metadata.st_uid, metadata.st_gid)
            os.fchmod(stream.fileno(), stat.S_IMODE(metadata.st_mode))
            stream.write("".join(kept).encode())
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None and os.path.exists(temporary):
            os.unlink(temporary)
    return True


def main():
    try:
        body = sys.stdin.buffer.read(65537)
        if len(body) > 65536:
            raise Refusal("scanner fstab payload exceeds size limit")
        settings = json.loads(body)
        change = fstab_absent(FSTAB, wanted(settings), settings["apply"])
    except (ValueError, OSError, RecursionError):
        print("Paperless scanner fstab line check/removal failed", file=sys.stderr)
        return 1
    print(json.dumps({"change": change}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
