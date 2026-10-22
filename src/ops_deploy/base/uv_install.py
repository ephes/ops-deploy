"""Install a pinned, checksum-verified uv system-wide (the ``uv_install`` role)."""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Literal

from pydantic import Field, field_validator, model_validator
from pyinfra import host
from pyinfra.api import DeployError, deploy
from pyinfra.facts.files import Directory, File, FileDict, Link, Sha256File
from pyinfra.facts.server import Arch, Which
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


def _safe_path(value: str) -> str:
    if (
        value == "/"
        or "//" in value
        or str(PurePosixPath(value)) != value
        or any(part in {".", ".."} for part in value.split("/"))
    ):
        raise ValueError("use a normalized absolute path other than /")
    return value


class UvAliasConfig(RoleConfig):
    """One explicitly approved compatibility path; never a discovery pattern."""

    path: AbsolutePath
    binary: Literal["uv", "uvx"]
    # Required to replace an existing regular file; links are never followed.
    replace_sha256: Sha256 | None = None
    replace_owner: UnixUser = "root"

    _path = field_validator("path")(_safe_path)


class UvInstallConfig(RoleConfig):
    # Version and checksums change together (the role's defaults).
    version: Version = "0.13.4"
    checksums: dict[str, Sha256] = Field(
        default_factory=lambda: {
            "x86_64-unknown-linux-gnu": "2b428396f12572d4429cf210ca234dd599a33b3af0958a4d5ed569d63e3f344f",
            "aarch64-unknown-linux-gnu": "1ae72b4718729e2ccc4f1ae2c6d1e531ca8467800e0546e9130b3886023a60ab",
        }
    )
    # Must be world-readable: every service user runs uv from here.
    install_dir: AbsolutePath = "/usr/local/bin"
    owner: UnixUser = "root"
    group: UnixUser = "root"
    # Replace an installed uv of another version (else only install a missing one).
    update_existing: bool = True
    force_reinstall: bool = False

    # Additional previous owners are a deliberate adoption decision, not discovery.
    previous_owners: tuple[UnixUser, ...] = ()
    aliases: tuple[UvAliasConfig, ...] = ()

    _path = field_validator("install_dir")(_safe_path)

    @model_validator(mode="after")
    def _alias_paths(self) -> UvInstallConfig:
        paths = [alias.path for alias in self.aliases]
        protected = {
            f"{self.install_dir}/{name}" for name in ("uv", "uvx", ".uv.ops-deploy-new", ".uvx.ops-deploy-new")
        }
        if len(set(paths)) != len(paths) or protected.intersection(paths):
            raise ValueError("aliases must be unique and distinct from canonical/staging paths")
        return self


def installed_version(binary: str) -> str:
    """Read a version only after checking the explicitly managed file's provenance."""
    match = re.match(rf"^{PurePosixPath(binary).name} ([0-9]+(?:\.[0-9]+)*)(?: |$)", output(f"{binary} --version"))
    return match.group(1) if match else ""


def _directory(path: str, *, allow_missing: bool = False) -> None:
    # Check every ancestor: a safe leaf beneath a writable/link parent is unsafe.
    for item in (*reversed(PurePosixPath(path).parents), PurePosixPath(path)):
        directory = str(item)
        fact = host.get_fact(Directory, path=directory)
        if fact is None and directory == path and allow_missing:
            continue
        if not fact or fact["user"] != "root" or int(str(fact["mode"]), 8) & 0o022:
            raise DeployError(f"uv_install: unsafe directory {directory}; require root-owned non-writable ancestors")


def _canonical(path: str, cfg: UvInstallConfig) -> FileDict | None:
    fact = host.get_fact(File, path=path)
    if fact is False or host.get_fact(Link, path=path):
        raise DeployError(f"uv_install: refusing non-regular canonical/staging path {path}")
    if fact and fact["user"] not in {"root", cfg.owner, *cfg.previous_owners}:
        raise DeployError(f"uv_install: unapproved owner at {path}")
    return fact


def _require_unowned(path: str, manager: str) -> None:
    # Query only explicitly managed leaves. Unknown/failed provenance is not permission to overwrite.
    if manager == "dpkg-query":
        command = (
            f"if dpkg-query -S -- {path} >/dev/null 2>&1; then printf owned; "
            'else code=$?; if [ "$code" = 1 ]; then printf unowned; else printf unknown; fi; fi'
        )
    else:
        command = (
            f"result=$(LC_ALL=C rpm -qf -- {path} 2>&1); code=$?; "
            'if [ "$code" = 0 ]; then printf owned; '
            f'elif [ "$code" = 1 ] && [ "$result" = \'file {path} is not owned by any package\' ]; '
            "then printf unowned; "
            # rpm queries ownership first, then stats an unowned path. Its missing-file
            # fallback is safe only when the exact diagnostic and absence both agree.
            f'elif [ "$code" = 1 ] && [ "$result" = \'error: file {path}: No such file or directory\' ] '
            f"&& [ ! -e {path} ] && [ ! -L {path} ]; "
            "then printf unowned; else printf unknown; fi"
        )
    if output(command) != "unowned":
        raise DeployError(f"uv_install: package-owned or unknown package provenance at {path}")


def _check_alias(alias: UvAliasConfig, target: str) -> None:
    _directory(str(PurePosixPath(alias.path).parent))
    link = host.get_fact(Link, path=alias.path)
    if link:
        # Only an already-correct root-owned link is accepted automatically.
        if link["link_target"] != target or link["user"] != "root":
            raise DeployError(f"uv_install: refusing unexpected alias symlink {alias.path}")
        return
    fact = host.get_fact(File, path=alias.path)
    if fact is False:
        raise DeployError(f"uv_install: refusing non-regular alias {alias.path}")
    if fact and (
        alias.replace_sha256 is None
        or fact["user"] != alias.replace_owner
        or host.get_fact(Sha256File, path=alias.path) != alias.replace_sha256
    ):
        raise DeployError(f"uv_install: legacy alias needs approved owner and sha256: {alias.path}")


@deploy("Install uv")
def deploy_uv_install(cfg: UvInstallConfig) -> None:
    require_linux("uv_install")  # Homebrew owns Darwin bytes; never follow/chown its links.
    _directory(cfg.install_dir, allow_missing=True)
    paths = {name: f"{cfg.install_dir}/{name}" for name in ("uv", "uvx")}
    managers = tuple(name for name in ("dpkg-query", "rpm") if host.get_fact(Which, command=name))
    if not managers:
        raise DeployError("uv_install: dpkg-query or rpm required to establish package provenance")
    for path in (*paths.values(), *(alias.path for alias in cfg.aliases)):
        for manager in managers:
            _require_unowned(path, manager)
    facts = {name: _canonical(path, cfg) for name, path in paths.items()}
    for name in paths:
        staged = f"{cfg.install_dir}/.{name}.ops-deploy-new"
        if _canonical(staged, cfg):
            raise DeployError(f"uv_install: staging path already exists: {staged}")
    for alias in cfg.aliases:
        _check_alias(alias, paths[alias.binary])

    versions = {}
    for name, path in paths.items():
        fact = facts[name]
        # Never execute a binary writable by an untrusted group/other user.
        mode = int(str(fact["mode"]), 8) if fact else 0
        versions[name] = installed_version(path) if fact and mode & 0o111 and not mode & 0o022 else ""
    if cfg.update_existing or cfg.force_reinstall:
        for version in versions.values():
            if version and tuple(map(int, version.split("."))) > tuple(map(int, cfg.version.split("."))):
                raise DeployError("uv_install: installed version is newer than controller pin; refusing downgrade")
    needed = (
        cfg.force_reinstall
        or any(not version for version in versions.values())
        or (cfg.update_existing and any(version != cfg.version for version in versions.values()))
    )
    if not (cfg.update_existing or cfg.force_reinstall) and len(set(versions.values()) - {""}) > 1:
        raise DeployError("uv_install: mismatched uv/uvx with updates disabled")
    if (
        needed
        and not (cfg.update_existing or cfg.force_reinstall)
        and any(version and version != cfg.version for version in versions.values())
    ):
        raise DeployError("uv_install: cannot repair pair at controller pin with updates disabled")

    if needed:
        arch = ARCHES.get(host.get_fact(Arch) or "", "unsupported")
        target = f"{arch}-unknown-linux-gnu"
        if target not in cfg.checksums:
            raise DeployError(f"uv_install: no pinned checksum for {target}")
        ensure_curl("uv_install")
        files.directory(name=f"Ensure {cfg.install_dir}", path=cfg.install_dir, user="root", group="root", mode="0755")
        script = release_install_script(
            url=f"https://github.com/astral-sh/uv/releases/download/{cfg.version}/uv-{target}.tar.gz",
            sha256=cfg.checksums[target],
            binaries={f"uv-{target}/uv": "uv", f"uv-{target}/uvx": "uvx"},
            install_dir=cfg.install_dir,
            owner=cfg.owner,
            group=cfg.group,
        )
        verify = " && ".join(
            f"test \"$({path} --version | cut -d ' ' -f 2)\" = {cfg.version}" for path in paths.values()
        )
        server.shell(name=f"Install uv {cfg.version} to {cfg.install_dir}", commands=[f"{script} && {verify}"])
    else:
        files.directory(name=f"Ensure {cfg.install_dir}", path=cfg.install_dir, user="root", group="root", mode="0755")
        for name, path in paths.items():
            files.file(
                name=f"Converge {name} ownership and mode", path=path, user=cfg.owner, group=cfg.group, mode="0755"
            )
    # These operations run after the install's paired version verification succeeds.
    for alias in cfg.aliases:
        files.link(
            name=f"Compatibility alias {alias.path}",
            path=alias.path,
            target=paths[alias.binary],
            user="root",
            group="root",
            force=True,
        )
