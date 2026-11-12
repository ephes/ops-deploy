"""Install a pinned, checksum-verified uv system-wide (the ``uv_install`` role)."""

from __future__ import annotations

import base64
import json
import re
import shlex
from importlib.resources import files as resources
from pathlib import PurePosixPath
from typing import Literal

from pydantic import Field, field_validator, model_validator
from pyinfra import host
from pyinfra.api import DeployError, deploy
from pyinfra.facts.files import Directory, File, FileDict, Link, Sha256File
from pyinfra.facts.server import Arch, Command
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


def _normalized(value: str) -> str:
    if value == "/" or str(PurePosixPath(value)) != value or any(p in {".", ".."} for p in value.split("/")):
        raise ValueError("use a normalized absolute path other than /")
    return value


class UvAliasConfig(RoleConfig):
    """One approved compatibility path that becomes a root-owned link to ``uv``/``uvx``.

    Never a discovery pattern: each path is named explicitly. An existing
    regular file there is replaced only when its owner and sha256 are the
    approved ones (a copy an earlier install left behind); any other file,
    directory or link to somewhere else fails the deploy.
    """

    path: AbsolutePath
    binary: Literal["uv", "uvx"]
    replace_sha256: Sha256 | None = None
    replace_owner: UnixUser = "root"

    _path = field_validator("path")(_normalized)


class UvInstallConfig(RoleConfig):
    # Explicit opt-in: Linux defaults and its existing installation path remain unchanged.
    darwin: bool = False
    # Version and checksums change together (the role's defaults).
    version: Version = "0.13.5"
    checksums: dict[str, Sha256] = Field(
        default_factory=lambda: {
            "x86_64-unknown-linux-gnu": "f68d291c75783122dad58ab77def0e13f3233f358731db5d6d7e8715603b928f",
            "aarch64-unknown-linux-gnu": "4bb69cf95ed13f23713bb7bc09f241896ea0c75b7c557e615a20604b82f9c403",
        }
    )
    # Must be world-readable: every service user runs uv from here.
    install_dir: AbsolutePath = "/usr/local/bin"
    owner: UnixUser = "root"
    group: UnixUser = "root"
    # Replace an installed uv of another version (else only install a missing one).
    update_existing: bool = True
    force_reinstall: bool = False

    # Linux only: approved compatibility paths, linked to the canonical pair.
    aliases: tuple[UvAliasConfig, ...] = ()

    @field_validator("install_dir")
    @classmethod
    def _not_root(cls, value: str) -> str:
        if value.rstrip("/") == "":
            raise ValueError("install_dir must not be /")
        return value.rstrip("/")

    @model_validator(mode="after")
    def _distinct_aliases(self) -> UvInstallConfig:
        if self.aliases and self.darwin:
            raise ValueError("aliases are Linux only (Homebrew owns the Darwin links)")
        paths = [alias.path for alias in self.aliases]
        own = {f"{self.install_dir}/{name}" for name in ("uv", "uvx", ".uv.ops-deploy-new", ".uvx.ops-deploy-new")}
        if len(set(paths)) != len(paths) or own & set(paths):
            raise ValueError("aliases must be unique and outside the canonical and staging paths")
        return self


def installed_version(binary: str) -> str:
    """``uv 0.13.5 (...)`` -> ``0.13.5`` (``uvx 0.13.5`` for uvx); empty when missing or broken."""

    name = re.escape(PurePosixPath(binary).name)
    match = re.match(rf"^{name} ([0-9]+(?:\.[0-9]+)*)(?: |$)", output(f"{binary} --version"))
    return match.group(1) if match else ""


def release(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def trusted_version(path: str, owner: str) -> str | None:
    """Version of the canonical binary at ``path``, or ``None`` when it must be reinstalled.

    A symlink (an older setup linked uv into place) and a file owned by
    someone other than root/``owner`` or writable by group/others are never
    executed: the install renames fresh, checksum-verified bytes over them.
    Anything else (a directory, a fifo) fails the deploy.
    """

    if host.get_fact(Link, path=path):
        return None
    fact = host.get_fact(File, path=path)
    if fact is False:
        raise DeployError(f"uv_install: {path} is not a regular file; refusing to replace it")
    if not fact or not _trusted(fact, owner):
        return None
    return installed_version(path) or None


def _trusted(fact: FileDict, owner: str) -> bool:
    mode = int(str(fact["mode"]), 8)
    return fact["user"] in {"root", owner} and not mode & 0o022 and bool(mode & 0o111)


def trusted_file(path: str, owner: str) -> bool:
    """``path`` is a regular file owned by root/``owner``, executable and not group/other-writable."""

    fact = host.get_fact(File, path=path)
    return _trusted(fact, owner) if fact else False


def _check_alias(alias: UvAliasConfig, target: str) -> bool:
    """True when ``alias`` is already the root-owned link to ``target``; refuse anything unapproved."""

    parent = str(PurePosixPath(alias.path).parent)
    fact = host.get_fact(Directory, path=parent)
    if not fact or fact["user"] != "root" or int(str(fact["mode"]), 8) & 0o022:
        raise DeployError(
            f"uv_install: alias directory {parent} must exist, be root-owned and not group/other-writable"
        )
    link = host.get_fact(Link, path=alias.path)
    if link:
        if link["link_target"] != target or link["user"] != "root":
            raise DeployError(f"uv_install: refusing unexpected symlink at alias {alias.path}")
        return True
    existing = host.get_fact(File, path=alias.path)
    if existing is False:
        raise DeployError(f"uv_install: alias {alias.path} is not a regular file; refusing to replace it")
    if existing and (
        alias.replace_sha256 is None
        or existing["user"] != alias.replace_owner
        or host.get_fact(Sha256File, path=alias.path) != alias.replace_sha256
    ):
        raise DeployError(
            f"uv_install: {alias.path} is not the approved file (owner and sha256); refusing to replace it"
        )
    return False


@deploy("Install uv")
def deploy_uv_install(cfg: UvInstallConfig) -> None:
    if cfg.darwin:
        data = cfg.model_dump(mode="json", exclude={"darwin"})
        native_script = resources("ops_deploy.base").joinpath("uv_install_darwin.py").read_bytes()
        launcher = (
            "import base64;exec(compile(base64.b64decode('"
            + base64.b64encode(native_script).decode()
            + "'),'<uv-install-darwin>','exec'))"
        )
        command = shlex.join(["/usr/bin/python3", "-B", "-c", launcher])
        encoded = shlex.quote(base64.b64encode(json.dumps(data).encode()).decode())
        if host.get_fact(Command, command=f"{command} status {encoded}") != "current":
            server.shell(name=f"Install native uv {cfg.version}", commands=[f"{command} apply {encoded}"])
        return
    require_linux("uv_install")
    paths = {name: f"{cfg.install_dir}/{name}" for name in ("uv", "uvx")}
    files.directory(name=f"Ensure {cfg.install_dir}", path=cfg.install_dir, mode="0755")

    # uv and uvx are checked independently: an interrupted install or a
    # partial manual fix can leave one current and the other missing or old.
    versions = {name: trusted_version(path, cfg.owner) for name, path in paths.items()}
    linked = {alias.path: _check_alias(alias, paths[alias.binary]) for alias in cfg.aliases}
    # Never downgrade (a stale pin, or a service pinning an older uv than the
    # host's shared one): a consistent newer pair is kept as it is; one that
    # could only be repaired by installing the older pin fails instead.
    newer = [f"{name} {v}" for name, v in versions.items() if v and release(v) > release(cfg.version)]
    if newer:
        if cfg.force_reinstall or len(set(versions.values())) != 1:
            raise DeployError(
                f"uv_install: {', '.join(newer)} is newer than the pinned {cfg.version} and the pair "
                "needs a reinstall; refusing to downgrade"
            )
        needed = False
    else:
        needed = (
            cfg.force_reinstall
            or any(v is None for v in versions.values())
            or (cfg.update_existing and any(v != cfg.version for v in versions.values()))
        )

    if needed:
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
        # Fails the deploy unless both installed binaries run and report the pin.
        verify = " && ".join(
            f'test "$({shlex.quote(path)} --version | cut -d " " -f 2)" = {cfg.version}' for path in paths.values()
        )
        server.shell(name=f"Install uv {cfg.version} to {cfg.install_dir}", commands=[f"{script} && {verify}"])
    else:
        # A kept pair (current, or another version with updates off) still gets
        # its owner and mode back; only trusted files reach this point.
        for name, path in paths.items():
            files.file(
                name=f"{name} owner and mode", path=path, user=cfg.owner, group=cfg.group, mode="0755", touch=False
            )
    for alias in cfg.aliases:
        if linked[alias.path]:
            continue
        # A replaced approved file is moved aside (``<path>.<timestamp>``), not deleted.
        files.link(
            name=f"Link {alias.path} to {paths[alias.binary]}",
            path=alias.path,
            target=paths[alias.binary],
            user="root",
            group="root",
            create_remote_dir=False,
            force=True,
            force_backup=True,
        )
