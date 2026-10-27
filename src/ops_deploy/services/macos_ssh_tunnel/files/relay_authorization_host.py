"""Original unprivileged restricted-key line management; no credential provisioning."""

import hashlib
import json
import os
import re
import stat
import sys
import uuid
from pathlib import Path


def main():
    data = json.load(sys.stdin)
    home = Path(data["home"])
    if not home.is_absolute() or home.resolve(strict=True) != home:
        raise RuntimeError("relay home must be an existing canonical directory")
    own = os.geteuid()
    info = home.stat()
    if own == 0 or info.st_uid != own or stat.S_IMODE(info.st_mode) & 0o022:
        raise RuntimeError("relay authorization requires its original unprivileged home owner")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    parent = os.open(home / ".ssh", flags)
    temporary = None
    try:
        info = os.fstat(parent)
        if info.st_uid != own or stat.S_IMODE(info.st_mode) & 0o022:
            raise RuntimeError("relay SSH directory has unsafe ownership or permissions")
        name = "authorized_keys"
        old = None
        raw = b""
        try:
            descriptor = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        except FileNotFoundError:
            pass
        else:
            with os.fdopen(descriptor, "rb") as stream:
                old = os.fstat(stream.fileno())
                if not stat.S_ISREG(old.st_mode) or old.st_nlink != 1 or old.st_uid != own or old.st_size > 1024 * 1024:
                    raise RuntimeError("relay authorized_keys has an unsafe type, owner or size")
                raw = stream.read(1024 * 1024 + 1)
                again = os.fstat(stream.fileno())
                if (old.st_ino, old.st_size, old.st_mtime_ns, old.st_ctime_ns) != (again.st_ino, again.st_size, again.st_mtime_ns, again.st_ctime_ns):
                    raise RuntimeError("relay authorization changed during inspection")
        line = data["line"]
        comment = data["comment"]
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._@+-]{0,127}", comment) or "\n" in line or "\r" in line:
            raise RuntimeError("relay authorization requires a single managed public line")
        desired = line.encode() + b"\n"
        lines = raw.splitlines(keepends=True)
        matches = [i for i, value in enumerate(lines) if value.rstrip(b"\r\n").endswith(b" " + comment.encode())]
        if matches:
            lines[matches[-1]] = desired
        else:
            if lines and not lines[-1].endswith(b"\n"):
                lines[-1] += b"\n"
            lines.append(desired)
        result = b"".join(lines)
        changed = result != raw or old is None or stat.S_IMODE(old.st_mode) != 0o600
        if changed and not data["check"]:
            temporary = ".forwarding-authorization-" + uuid.uuid4().hex
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
            with os.fdopen(fd, "wb") as stream:
                stream.write(result)
                stream.flush()
                os.fsync(stream.fileno())
                os.fchmod(stream.fileno(), 0o600)
                if old is not None and old.st_gid != os.getgid():
                    os.fchown(stream.fileno(), -1, old.st_gid)
            current = None
            try:
                current = os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                pass
            if (old is None) != (current is None) or old is not None and (
                old.st_dev, old.st_ino, old.st_size, old.st_mtime_ns, old.st_ctime_ns
            ) != (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns, current.st_ctime_ns):
                raise RuntimeError("relay authorization changed before publication")
            os.replace(temporary, name, src_dir_fd=parent, dst_dir_fd=parent)
            temporary = None
            os.fsync(parent)
        print(json.dumps({"current": not changed, "changed": changed, "managed_line_sha256": hashlib.sha256(desired).hexdigest()}))
    finally:
        if temporary is not None:
            os.unlink(temporary, dir_fd=parent)
        os.close(parent)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("original relay public authorization could not be reconciled", file=sys.stderr)
        sys.exit(1)
