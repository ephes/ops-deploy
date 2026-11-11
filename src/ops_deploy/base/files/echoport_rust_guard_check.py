"""Check an installed Rust guard before its forced command may name it.

Host side of ``ops_deploy.base.echoport_command_guard`` (the role's
``rust.yml`` "Check the installed binary" block), run as root by
``/usr/bin/python3 -I - BINARY POLICY_B64`` with this file on stdin (standard
library only)::

    BINARY       <install root>/<version>/echoport-command-guard
    POLICY_B64   the policy the deploy is about to install, base64 of its text

1. sshd runs BINARY as root, so nobody but root may be able to replace it or
   any directory above it: every component of its path exists, is no symlink,
   belongs to root and is neither group- nor world-writable.
2. The binary, its version directory and the install root are root:root and
   mode 0755 (a regular file, then two directories).
3. ``BINARY --check-policy <scratch copy of the policy>`` exits 0, so a policy
   the Rust guard would refuse never reaches the host with impl shadow or rust
   and shows as a warning with impl python. The scratch copy is root-only
   (0600) and removed afterwards.

Exit 0 when every check passes; otherwise the reason on stderr and exit 1.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import os
import posixpath
import stat
import subprocess
import sys
import tempfile
from collections.abc import Callable


class Refused(Exception):
    pass


def path_chain(path: str) -> list[str]:
    """``/a/b/c`` -> ``['/a/b/c', '/a/b', '/a', '/']``."""

    if not path.startswith("/") or posixpath.normpath(path) != path:
        raise Refused(f"not a normalised absolute path: {path!r}")
    chain = [path]
    while chain[-1] != "/":
        chain.append(posixpath.dirname(chain[-1]))
    return chain


def check_path(binary: str, lstat: Callable[[str], os.stat_result] = os.lstat) -> None:
    for index, component in enumerate(path_chain(binary)):
        try:
            info = lstat(component)
        except OSError as error:
            raise Refused(f"{component} cannot be read ({error.strerror}); sshd runs {binary} as root") from None
        mode = stat.S_IMODE(info.st_mode)
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or mode & 0o022:
            raise Refused(
                f"{component} must exist, be no symlink, belong to root and not be group- or "
                f"world-writable (uid {info.st_uid}, mode {mode:04o}): sshd runs {binary} as root"
            )
        if index < 3:
            kind_ok = stat.S_ISREG(info.st_mode) if index == 0 else stat.S_ISDIR(info.st_mode)
            if info.st_gid != 0 or mode != 0o755 or not kind_ok:
                raise Refused(f"{component} must be root:root and 0755 (gid {info.st_gid}, mode {mode:04o})")


def check_policy(binary: str, policy: bytes) -> None:
    fd, scratch = tempfile.mkstemp(suffix=".echoport-guard-policy.json")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(policy)
        os.chmod(scratch, 0o600)
        try:
            done = subprocess.run(
                [binary, "--check-policy", scratch],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise Refused(f"cannot run {binary} --check-policy: {error}") from None
    finally:
        os.unlink(scratch)
    if done.returncode != 0:
        raise Refused(f"the Rust guard refuses the policy (exit {done.returncode}): {done.stderr.strip()}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="echoport-rust-guard-check")
    parser.add_argument("binary")
    parser.add_argument("policy_b64")
    args = parser.parse_args(argv)
    try:
        try:
            policy = base64.b64decode(args.policy_b64, validate=True)
        except (binascii.Error, ValueError):
            raise Refused("the policy argument is not base64") from None
        check_path(args.binary)
        check_policy(args.binary, policy)
    except Refused as error:
        print(f"echoport-command-guard check: {error}", file=sys.stderr)
        return 1
    print(f"checked {args.binary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
