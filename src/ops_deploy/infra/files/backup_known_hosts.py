"""Refresh one original peer/type, preserving every unrelated known_hosts byte."""

import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys
import tempfile


def admit(path):
    if not path.is_absolute() or str(path) != os.path.normpath(str(path)) or ".." in path.parts:
        raise ValueError("invalid known_hosts path")
    for part in [*reversed(path.parents), path]:
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise ValueError("linked known_hosts path")
        if part == path and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 4 * 1024 * 1024):
            raise ValueError("invalid known_hosts metadata")


def matches(name, host):
    if name.startswith("|1|"):
        fields = name.split("|")
        if len(fields) != 4:
            raise ValueError("invalid hashed host field")
        salt = base64.b64decode(fields[2], validate=True)
        expected = base64.b64decode(fields[3], validate=True)
        return hmac.compare_digest(hmac.digest(salt, host.encode(), "sha1"), expected)
    return name.lower() == host.lower()


def scanned(v):
    host = v["host"]
    kind = v["key_type"]
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]*", host) or kind not in ("ed25519", "rsa", "ecdsa"):
        raise ValueError("invalid peer/type")
    p = subprocess.run(["ssh-keyscan", "-T", "30", "-t", kind, host], capture_output=True, text=True, timeout=40)
    if p.returncode or not p.stdout.strip():
        raise ValueError("source peer keyscan failed")
    keys = set()
    for line in p.stdout.splitlines():
        fields = line.split()
        if len(fields) != 3 or fields[0].lower() != host.lower():
            raise ValueError("unexpected scanned host")
        raw = base64.b64decode(fields[2], validate=True)
        if len(raw) < 4:
            raise ValueError("invalid public key wire shape")
        length = struct.unpack(">I", raw[:4])[0]
        if raw[4 : 4 + length] != fields[1].encode():
            raise ValueError("invalid public key wire type")
        allowed = {"ed25519": "ssh-ed25519", "rsa": "ssh-rsa", "ecdsa": "ecdsa-sha2-nistp256"}
        if fields[1] != allowed[kind]:
            raise ValueError("unexpected scanned public key type")
        keys.add((fields[1], fields[2]))
    return keys


def candidate(original, host, keys):
    selected = {item[0] for item in keys}
    present = []
    preserved = []
    for line in original.splitlines(keepends=True):
        fields = line.split()
        offset = 1 if fields and fields[0].startswith("@") else 0
        if len(fields) < offset + 3 or fields[0].startswith("#"):
            preserved.append(line)
            continue
        names = fields[offset].split(",")
        target = [name for name in names if matches(name, host)]
        if not target or fields[offset + 1] not in selected:
            preserved.append(line)
            continue
        if offset:
            raise ValueError("marked target host trust policy requires explicit original configuration repair")
        present.append((fields[1], fields[2]))
        other = [name for name in names if not matches(name, host)]
        if other:
            # Preserve the same key/comment for the unrelated names on this row.
            preserved.append(line.replace(fields[0], ",".join(other), 1))
    if len(present) == len(keys) and set(present) == keys:
        return original
    prefix = "".join(preserved)
    if prefix and not prefix.endswith("\n"):
        prefix += "\n"
    return prefix + "".join(host + " " + kind + " " + value + "\n" for kind, value in sorted(keys))


def state(v):
    path = Path(v["path"])
    admit(path)
    keys = scanned(v)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        original = ""
        info = None
    else:
        try:
            info = os.fstat(fd)
            original = os.read(fd, 4 * 1024 * 1024 + 1).decode()
        finally:
            os.close(fd)
    desired = candidate(original, v["host"], keys)
    metadata = info is not None and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (0, 0, 0o644)
    return path, original, desired, metadata


def main():
    if os.geteuid() != 0:
        raise ValueError("existing root identity required")
    v = json.load(sys.stdin)
    path, original, desired, metadata = state(v)
    action = sys.argv[1]
    if action == "check":
        print("current" if original == desired and metadata else "pending")
        return
    if action != "apply":
        raise ValueError("unknown known_hosts action")
    if original == desired and metadata:
        print("current")
        return
    admit(path)
    if original == desired:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fchown(fd, 0, 0)
            os.fchmod(fd, 0o644)
        finally:
            os.close(fd)
    else:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd, temporary = tempfile.mkstemp(prefix=".backup-known-hosts-", dir=path.parent)
        try:
            with os.fdopen(fd, "w") as stream:
                stream.write(desired)
                stream.flush()
                os.fsync(stream.fileno())
                os.fchown(stream.fileno(), 0, 0)
                os.fchmod(stream.fileno(), 0o644)
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    print("current")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("Declared backup peer host-key refresh failed; no broader trust/file export", file=sys.stderr)
        raise SystemExit(2) from None
