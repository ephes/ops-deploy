"""Declared scanner bind mount/fstab only; healthy mounts are never remounted."""

import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile


class Refusal(ValueError):
    pass


def paths(settings):
    if not isinstance(settings, dict) or set(settings) != {"source", "target", "apply"}:
        raise Refusal("invalid scanner mount payload")
    for name in ("source", "target"):
        value = settings[name]
        if not isinstance(value, str) or not re.fullmatch(r"(?:/[A-Za-z0-9_.+-]+)+", value):
            raise Refusal("invalid scanner mount path")
        if any(part in {".", ".."} for part in value.split("/")[1:]):
            raise Refusal("invalid scanner mount path")
    source, target = Path(settings["source"]), Path(settings["target"])
    if source == target or source in target.parents or target in source.parents or type(settings["apply"]) is not bool:
        raise Refusal("scanner source and target must be disjoint")
    return source, target


def mounted(source, target):
    result = subprocess.run(
        ["findmnt", "-rn", "--mountpoint", str(target), "-o", "TARGET"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, check=False,
    )
    if result.returncode == 1 and not result.stdout.strip():
        return False
    if result.returncode or result.stdout.strip() != str(target):
        raise Refusal("scanner mount identity query failed")
    a, b = source.stat(), target.stat()
    if (a.st_dev, a.st_ino) != (b.st_dev, b.st_ino):
        raise Refusal("scanner inbox has a foreign mount")
    return True


def fstab_change(path, source, target, apply):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 1024 * 1024:
            raise Refusal("fstab must be a bounded regular file")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            body = stream.read(1024 * 1024 + 1)
        if len(body) > 1024 * 1024:
            raise Refusal("fstab exceeded size limit")
    finally:
        os.close(fd)
    lines = body.decode().splitlines(keepends=True)
    wanted = [str(source), str(target), "none", "bind", "0", "0"]
    selected = []
    for index, line in enumerate(lines):
        fields = line.split("#", 1)[0].split()
        if len(fields) > 1 and fields[1] == str(target):
            if fields[0] != str(source):
                raise Refusal("scanner fstab target belongs to another source")
            selected.append((index, fields))
    if len(selected) > 1:
        raise Refusal("scanner fstab target has duplicate entries")
    if selected and selected[0][1] == wanted:
        return False
    if not apply:
        return True
    replacement = " ".join(wanted) + "\n"
    if selected:
        lines[selected[0][0]] = replacement
    else:
        if lines and not lines[-1].endswith("\n"):
            lines[-1] += "\n"
        lines.append(replacement)
    temporary = None
    try:
        descriptor, temporary = tempfile.mkstemp(prefix=".paperless-fstab-", dir=path.parent)
        with os.fdopen(descriptor, "wb") as stream:
            os.fchown(stream.fileno(), metadata.st_uid, metadata.st_gid)
            os.fchmod(stream.fileno(), stat.S_IMODE(metadata.st_mode))
            stream.write("".join(lines).encode())
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None and os.path.exists(temporary):
            os.unlink(temporary)
    return True


def reconcile(settings):
    source, target = paths(settings)
    for path in (source, target):
        if path.is_symlink():
            raise Refusal("scanner mount roots must not be symlinks")
        if not path.is_dir():
            if not path.exists() and not settings["apply"]:
                return {"fstab": True, "mount": True}
            raise Refusal("scanner mount directories must exist")
    active = mounted(source, target)
    config_change = fstab_change(Path("/etc/fstab"), source, target, settings["apply"])
    if not settings["apply"]:
        return {"fstab": config_change, "mount": not active}
    if not active:
        result = subprocess.run(
            ["mount", "--bind", str(source), str(target)], stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
        )
        if result.returncode or not mounted(source, target):
            raise Refusal("scanner bind mount failed after fstab convergence")
    return {"fstab_changed": config_change, "mount_changed": not active}


def main():
    try:
        body = sys.stdin.buffer.read(65537)
        if len(body) > 65536:
            raise Refusal("scanner mount payload exceeds size limit")
        result = reconcile(json.loads(body))
    except (ValueError, OSError, RecursionError):
        print("Paperless scanner bind mount check/update failed", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
