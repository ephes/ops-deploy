"""Install a pinned, checksum-verified uv system-wide (the ``uv_install`` role)."""

from __future__ import annotations

import re

from pydantic import Field, field_validator
from pyinfra import host
from pyinfra.api import DeployError, deploy
from pyinfra.facts.files import File, Link
from pyinfra.facts.server import Arch
from pyinfra.operations import files, server

from ops_deploy.base._common import (
    AbsolutePath,
    RoleConfig,
    Sha256,
    Version,
    ensure_curl,
    output,
    release_install_script,
    require_linux,
)
from ops_deploy.core.config import UnixUser

ARCHES = {"x86_64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}


class UvInstallConfig(RoleConfig):
    # Version and checksums change together (the role's defaults).
    version: Version = "0.13.0"
    checksums: dict[str, Sha256] = Field(
        default_factory=lambda: {
            "x86_64-unknown-linux-gnu": "1468ebd5a5541121837c5a2817b9972ba6090fa6caa3d142620850a47fb75154",
            "aarch64-unknown-linux-gnu": "3ccfb6af6e242433eb552f7d9676abd5412c6595c497e990d9c8cb7b5bd4d2c3",
        }
    )
    # Must be world-readable: every service user runs uv from here.
    install_dir: AbsolutePath = "/usr/local/bin"
    owner: UnixUser = "root"
    group: UnixUser = "root"
    # Replace an installed uv of another version (else only install a missing one).
    update_existing: bool = True
    force_reinstall: bool = False

    @field_validator("install_dir")
    @classmethod
    def _not_root(cls, value: str) -> str:
        if value.rstrip("/") == "":
            raise ValueError("install_dir must not be /")
        return value.rstrip("/")


def installed_version(binary: str) -> str:
    """``uv 0.13.0 (...)`` -> ``0.13.0``; empty when missing or broken."""

    match = re.match(r"^uv ([0-9.]+)", output(f"{binary} --version"))
    return match.group(1) if match else ""


@deploy("Install uv")
def deploy_uv_install(cfg: UvInstallConfig) -> None:
    require_linux("uv_install")
    uv = f"{cfg.install_dir}/uv"
    files.directory(name=f"Ensure {cfg.install_dir}", path=cfg.install_dir, mode="0755")

    # An older setup symlinked uv into place; such a link is always replaced
    # (the install renames over it).
    is_link = bool(host.get_fact(Link, path=uv))
    current = "" if is_link else installed_version(uv)
    # uvx too: an interrupted install may have renamed uv but not uvx.
    if current and not host.get_fact(File, path=f"{cfg.install_dir}/uvx"):
        current = ""
    needed = not current or cfg.force_reinstall or (cfg.update_existing and current != cfg.version)
    if not needed:
        return

    arch = ARCHES.get(host.get_fact(Arch) or "", "unsupported")
    target = f"{arch}-unknown-linux-gnu"
    if target not in cfg.checksums:
        raise DeployError(f"uv_install: no pinned checksum for {target}")
    ensure_curl("uv_install")
    script = release_install_script(
        url=f"https://github.com/astral-sh/uv/releases/download/{cfg.version}/uv-{target}.tar.gz",
        sha256=cfg.checksums[target],
        binaries={f"uv-{target}/uv": "uv", f"uv-{target}/uvx": "uvx"},
        install_dir=cfg.install_dir,
        owner=cfg.owner,
        group=cfg.group,
    )
    server.shell(
        name=f"Install uv {cfg.version} to {cfg.install_dir}",
        # Fails the deploy unless the installed binary runs.
        commands=[f"{script} && {uv} --version"],
    )
