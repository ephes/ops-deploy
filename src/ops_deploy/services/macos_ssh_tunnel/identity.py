"""Read an existing forwarding identity without making a temporary private copy.

The mutation/recovery path remains the separately vendored ops-library helper.
This probe uses OpenSSH itself, through a pinned regular-file descriptor; it
does not implement key parsing or cryptography and never creates a file.
"""

from __future__ import annotations

import base64
import os
import stat
import subprocess
from pathlib import PurePosixPath
from typing import Any


class IdentityProbeError(ValueError):
    """An unsafe or unusable identity; messages never contain private material."""


def _binding(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_gid,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _regular(info: os.stat_result, uid: int, mode: int) -> None:
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != uid:
        raise IdentityProbeError("identity entry must be an owner-owned single-link regular file")
    if stat.S_IMODE(info.st_mode) != mode or not 0 < info.st_size <= 65536:
        raise IdentityProbeError("identity entry has an invalid mode or size")


def probe_identity(
    home: str, path: str, uid: int, comment: str, *, keygen: str = "/usr/bin/ssh-keygen"
) -> dict[str, Any]:
    """Return missing/drift/current and only public material; never stage or write.

    Pending creation intents require the existing durable reconciliation path.
    Missing private and public files need no prospective dry-run generation;
    an orphan public file and exact-mode violations retain the original
    mutation algorithm's refusal contract. Missing public material is drift.
    """
    home_path, identity_path = PurePosixPath(home), PurePosixPath(path)
    for value in (home, path):
        if not value.startswith("/") or os.path.normpath(value) != value or "\x00" in value:
            raise IdentityProbeError("identity paths must be absolute and normalized")
    if home_path not in identity_path.parents or os.geteuid() not in (0, uid):
        raise IdentityProbeError("identity must be below its configured owner's home")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    parent = os.open("/", flags | os.O_DIRECTORY)
    private = -1
    try:
        for index, component in enumerate(identity_path.parent.parts[1:], start=1):
            try:
                child = os.open(component, flags | os.O_DIRECTORY, dir_fd=parent)
            except FileNotFoundError:
                return {"state": "missing"}
            except OSError:
                raise IdentityProbeError("identity ancestor is not a no-follow directory") from None
            os.close(parent)
            parent = child
            info = os.fstat(parent)
            if index >= len(home_path.parts) - 1 and (info.st_uid != uid or stat.S_IMODE(info.st_mode) & 0o022):
                raise IdentityProbeError("identity home and descendant directories require safe ownership and modes")
        parent_info = os.fstat(parent)
        if parent_info.st_uid != uid or stat.S_IMODE(parent_info.st_mode) != 0o700:
            raise IdentityProbeError("identity parent must be owner-owned mode 0700")
        name = identity_path.name
        try:
            os.stat(f".{name}.creation.json", dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            return {"state": "drift"}
        try:
            private = os.open(name, flags, dir_fd=parent)
        except FileNotFoundError:
            try:
                os.stat(name + ".pub", dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                return {"state": "missing"}
            raise IdentityProbeError("public identity exists without its private identity") from None
        except OSError:
            raise IdentityProbeError("private identity cannot be opened without following links") from None
        before = os.fstat(private)
        _regular(before, uid, 0o600)
        # pass_fds preserves only this descriptor through exec. No private bytes
        # enter stdin, argv, environment, Python memory, temporary files or logs.
        try:
            result = subprocess.run(
                [keygen, "-y", "-P", "", "-f", f"/dev/fd/{private}"],
                pass_fds=(private,),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=15,
                env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "SSH_ASKPASS_REQUIRE": "never"},
            )
        except (OSError, subprocess.SubprocessError, UnicodeError):
            raise IdentityProbeError("could not derive the forwarding public identity") from None
        if _binding(before) != _binding(os.fstat(private)) or _binding(before) != _binding(
            os.stat(name, dir_fd=parent, follow_symlinks=False)
        ):
            raise IdentityProbeError("private identity changed during inspection")
        fields = result.stdout.strip().split()
        if result.returncode or len(fields) < 2 or fields[0] != "ssh-ed25519":
            raise IdentityProbeError("forwarding identity must be passphrase-free Ed25519")
        try:
            base64.b64decode(fields[1], validate=True)
        except ValueError:
            raise IdentityProbeError("OpenSSH returned an invalid public identity") from None
        public = " ".join(fields[:2])
        desired = f"{public} {comment}\n".encode()
        try:
            descriptor = os.open(name + ".pub", flags, dir_fd=parent)
        except FileNotFoundError:
            return {"state": "drift", "public_key": public}
        except OSError:
            raise IdentityProbeError("public identity cannot be opened without following links") from None
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            _regular(info, uid, 0o644)
            actual = stream.read(65537)
            if _binding(info) != _binding(os.fstat(stream.fileno())) or _binding(info) != _binding(
                os.stat(name + ".pub", dir_fd=parent, follow_symlinks=False)
            ):
                raise IdentityProbeError("public identity changed during inspection")
        return {"state": "current" if actual == desired else "drift", "public_key": public}
    finally:
        if private >= 0:
            os.close(private)
        os.close(parent)
