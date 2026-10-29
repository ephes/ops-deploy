"""One declared backup key: RAM equality, atomic private stdin install, no digest/export."""

import grp
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile


def admit(target):
    if not target.is_absolute() or str(target) != os.path.normpath(str(target)) or ".." in target.parts:
        raise ValueError("invalid key path")
    for part in [*reversed(target.parents), target]:
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise ValueError("linked key path/ancestor")
        if part == target and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 65536):
            raise ValueError("invalid existing key metadata")


def desired(v):
    value = v["content"]
    if not isinstance(value, str) or not value or value in ("CHANGE_ME", "CHANGEME") or "\0" in value:
        raise ValueError("missing/invalid source key")
    data = value.encode()
    if len(data) > 65536:
        raise ValueError("source key too large")
    if v["kind"] == "ssh":
        if not shutil.which("ssh-keygen"):
            raise ValueError("SSH prerequisite unavailable")
        # Native validation through an anonymous private RAM descriptor; never a
        # durable temporary key or argv/environment/log representation.
        fd = os.memfd_create("backup-key-validation", os.MFD_CLOEXEC)
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, data)
            os.lseek(fd, 0, os.SEEK_SET)
            p = subprocess.run(
                ["ssh-keygen", "-y", "-f", "/proc/self/fd/" + str(fd)], pass_fds=(fd,), capture_output=True, timeout=15
            )
            if p.returncode or not p.stdout:
                raise ValueError("native source SSH key invalid")
        finally:
            os.close(fd)
    elif v["kind"] == "zfs":
        if not 8 <= len(data.split(b"\n", 1)[0]) <= 512:
            raise ValueError("invalid source pool key")
    else:
        raise ValueError("unknown declared key kind")
    mode = {"ssh": 0o600, "zfs": 0o400}[v["kind"]]
    return data, mode, grp.getgrnam("root").gr_gid


def current(target, data, mode, gid):
    admit(target)
    try:
        fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return False, False
    try:
        info = os.fstat(fd)
        content = os.read(fd, 65537)
        return content == data, (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (0, gid, mode)
    finally:
        os.close(fd)


def pending(target, data, mode, gid):
    same, metadata = current(target, data, mode, gid)
    try:
        parent = target.parent.lstat()
    except FileNotFoundError:
        return True
    if not stat.S_ISDIR(parent.st_mode):
        raise ValueError("key parent is not a directory")
    return not (same and metadata and (parent.st_uid, parent.st_gid, stat.S_IMODE(parent.st_mode)) == (0, 0, 0o700))


def apply(target, data, mode, gid):
    admit(target)
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chown(target.parent, 0, 0)
    os.chmod(target.parent, 0o700)
    same, _metadata = current(target, data, mode, gid)
    if same:
        fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fchown(fd, 0, gid)
            os.fchmod(fd, mode)
        finally:
            os.close(fd)
        return
    fd, temporary = tempfile.mkstemp(prefix=".backup-key-", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchown(stream.fileno(), 0, gid)
            os.fchmod(stream.fileno(), mode)
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main():
    if os.geteuid() != 0:
        raise ValueError("existing root connection required")
    v = json.load(sys.stdin)
    target = Path(v["path"])
    admit(target)
    data, mode, gid = desired(v)
    action = sys.argv[1]
    if action == "apply":
        if pending(target, data, mode, gid):
            apply(target, data, mode, gid)
        if pending(target, data, mode, gid):
            raise ValueError("key did not converge")
        print("current")
    elif action == "check":
        print("pending" if pending(target, data, mode, gid) else "current")
    else:
        raise ValueError("unknown key action")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print(
            "Declared backup key validation/reconciliation failed; all key material/output suppressed", file=sys.stderr
        )
        raise SystemExit(2) from None
