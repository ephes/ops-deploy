"""Explicit Darwin uv installation helper, compatible with the target's Python 3.9.

The read-only path creates no staging directory and repairs no metadata. Both
release binaries are validated before either installed binary is replaced.
"""

from __future__ import annotations

import base64
import grp
import hashlib
import json
import os
import platform
import pwd
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path
from typing import Any


def version(path: Path) -> str:
    try:
        result = subprocess.run([str(path), "--version"], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    match = re.match(r"^uv ([0-9.]+)", result.stdout) if result.returncode == 0 else None
    return match[1] if match else ""


def regular(path: Path) -> bool:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise RuntimeError("uv installation has an unsafe binary type")
    return True


def needed(cfg: dict[str, Any]) -> bool:
    directory = Path(cfg["install_dir"])
    if directory.is_symlink() or (directory.exists() and not directory.is_dir()):
        raise RuntimeError("uv installation directory must be a real directory")
    binary = directory / "uv"
    if binary.is_symlink():
        return True
    current = version(binary) if regular(binary) else ""
    uvx = directory / "uvx"
    # Replacing either legacy symlink is an explicit installation transition.
    if uvx.is_symlink() or not regular(uvx):
        return True
    return not current or bool(cfg["force_reinstall"]) or bool(cfg["update_existing"] and current != cfg["version"])


def target(cfg: dict[str, Any]) -> str:
    arch = {"arm64": "aarch64", "aarch64": "aarch64", "x86_64": "x86_64"}.get(platform.machine(), "unsupported")
    name = arch + "-apple-darwin"
    if name not in cfg["checksums"]:
        raise RuntimeError("uv_install: no pinned checksum for " + name)
    return name


def install(cfg: dict[str, Any]) -> None:
    if not needed(cfg):
        return
    release_target = target(cfg)
    uid = pwd.getpwnam(cfg["owner"]).pw_uid
    gid = grp.getgrnam(cfg["group"]).gr_gid
    directory = Path(cfg["install_dir"])
    # Stage beside the destination so publication uses same-filesystem renames.
    # No directory is changed until the release checksum and staged executables pass.
    parent = directory
    while not parent.exists():
        parent = parent.parent
    with tempfile.TemporaryDirectory(prefix=".ops-uv-", dir=parent) as temporary:
        stage = Path(temporary)
        archive = stage / "release.tar.gz"
        url = f"https://github.com/astral-sh/uv/releases/download/{cfg['version']}/uv-{release_target}.tar.gz"
        digest = hashlib.sha256()
        with urllib.request.urlopen(url, timeout=30) as response, archive.open("xb") as output:
            while block := response.read(1024 * 1024):
                digest.update(block)
                output.write(block)
        if digest.hexdigest() != cfg["checksums"][release_target]:
            raise RuntimeError("uv release checksum mismatch; existing installation retained")
        with tarfile.open(archive, "r:gz") as bundle:
            for name in ("uv", "uvx"):
                member = bundle.getmember(f"uv-{release_target}/{name}")
                if not member.isfile() or member.size <= 0 or member.size > 200 * 1024 * 1024:
                    raise RuntimeError("uv release has an invalid executable")
                source = bundle.extractfile(member)
                if source is None:
                    raise RuntimeError("uv release is incomplete")
                with source, (stage / name).open("xb") as output:
                    while block := source.read(1024 * 1024):
                        output.write(block)
                os.chmod(stage / name, 0o755)
                os.chown(stage / name, uid, gid)
        if version(stage / "uv") != cfg["version"]:
            raise RuntimeError("uv staged release version mismatch; existing installation retained")
        result = subprocess.run([str(stage / "uvx"), "--version"], capture_output=True, timeout=30)
        if result.returncode != 0:
            raise RuntimeError("uv staged uvx is unusable; existing installation retained")
        directory.mkdir(mode=0o755, parents=True, exist_ok=True)
        os.chmod(directory, 0o755)
        for name in ("uv", "uvx"):
            destination = directory / name
            # Legacy symlinks are replaced, never followed. Reject other types.
            if not destination.is_symlink():
                regular(destination)
            os.replace(stage / name, destination)


def main() -> None:
    if platform.system() != "Darwin":
        raise RuntimeError("explicit Darwin uv installation requires Darwin")
    action, encoded = sys.argv[1:]
    cfg = json.loads(base64.b64decode(encoded))
    if action == "status":
        drift = needed(cfg)
        if drift:
            target(cfg)
        print("drift" if drift else "current")
    elif action == "apply":
        install(cfg)
    else:
        raise RuntimeError("unknown uv installation action")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Downloads and subprocess diagnostics are not part of operator output.
        print("native uv operation failed; existing release is retained until validated publication", file=sys.stderr)
        raise SystemExit(1) from None
