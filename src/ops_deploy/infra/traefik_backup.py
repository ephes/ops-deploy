"""Traefik dynamic-config backup and optional ACME backup/restore.

A backup holds ``metadata.yml``, the whole ``dynamic/`` tree (default on)
and optional ``acme/`` state, under one ``<prefix>-<timestamp>/`` archive
entry. Dynamic files may contain authentication hashes or other credentials;
the containing directory and archive stay private even without ACME.

Only regular files/directories are supported for dynamic snapshots: symlinks
and special entries refuse rather than follow data outside the selected tree.
Restore is unchanged, ACME-only, has no dry-run contract and refuses
transaction-managed hosts. It never publishes archived dynamic routes.
"""

from __future__ import annotations

import os
import shlex
import stat
from io import StringIO
from pathlib import Path, PurePosixPath
from typing import Annotated, Self

from pydantic import Field, model_validator
from pyinfra import host
from pyinfra.api import DeployError, deploy
from pyinfra.operations import files, python, server

from ops_deploy.base._common import AbsolutePath, RoleConfig, output
from ops_deploy.infra._common import directory
from ops_deploy.infra.traefik_deploy import refuse_transaction_managed

Prefix = Annotated[str, Field(pattern=r"^[A-Za-z0-9._-]+$")]
# An archive name below the backup root, or an absolute path.
ArchiveName = Annotated[str, Field(pattern=r"^(latest|/?[A-Za-z0-9._/+-]+\.tar\.gz)$")]


class TraefikBackupConfig(RoleConfig):
    root: AbsolutePath = "/opt/backups/traefik"
    prefix: Prefix = "manual"
    acme_path: AbsolutePath = "/etc/traefik/acme/acme.json"
    include_acme: bool = False
    dynamic_dir: AbsolutePath = "/etc/traefik/dynamic"
    include_dynamic: bool = True
    create_archive: bool = True
    fetch_local: bool = True
    # None: ``~/backups/traefik`` on the controller.
    local_dir: Path | None = None

    @model_validator(mode="after")
    def separate_dynamic_source(self) -> Self:
        if self.include_dynamic:
            root, source = PurePosixPath(self.root), PurePosixPath(self.dynamic_dir)
            if ".." in root.parts or ".." in source.parts:
                raise ValueError("dynamic backup paths cannot contain parent traversal")
            if root.is_relative_to(source) or source.is_relative_to(root):
                raise ValueError("dynamic source and backup root must not overlap")
        return self


class TraefikRestoreConfig(RoleConfig):
    # ``latest``: the newest ``*.tar.gz`` in ``root`` by modification time.
    archive: ArchiveName = "latest"
    root: AbsolutePath = "/opt/backups/traefik"
    staging_dir: AbsolutePath = "/tmp/traefik-restore"
    acme_path: AbsolutePath = "/etc/traefik/acme/acme.json"
    include_acme: bool = False
    # Transaction-managed hosts are refused, as by the role.
    transaction_required: bool = False


def _exists(path: str) -> bool:
    return output(f"test -e {shlex.quote(path)} && echo yes").strip() == "yes"


def _private_local_dir(path: str) -> None:
    try:
        os.makedirs(path, mode=0o700, exist_ok=True)
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        raise DeployError(
            "traefik_backup: local backup directory must be an accessible real directory (no link)"
        ) from None
    try:
        os.fchmod(descriptor, 0o700)
    finally:
        os.close(descriptor)


def _private_local_file(path: str, missing_ok: bool = False) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        if missing_ok:
            return
        raise
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
            raise DeployError("traefik_backup: local archive destination must be a regular, singly-linked file")
        os.fchmod(descriptor, 0o600)
    finally:
        os.close(descriptor)


def _dynamic_tree_check(path: str) -> str:
    source = shlex.quote(path.rstrip("/"))
    return (
        f"test -d {source} && test ! -L {source} "
        f'&& unsafe=$(find {source} ! -type d ! -type f -print -quit) && test -z "$unsafe"'
    )


def _dynamic_copy(source: str, destination: str) -> str:
    # cp -a preserves modes and copies dot/nested files without following links.
    # Check again after copying: a newly introduced link must not produce an
    # apparently complete archive. The containing backup directory stays0700.
    return (
        f"{_dynamic_tree_check(source)} && "
        f"cp -a {shlex.quote(source.rstrip('/') + '/.')} {shlex.quote(destination + '/')} && "
        f"{_dynamic_tree_check(destination)}"
    )


@deploy("Traefik backup")
def deploy_traefik_backup(cfg: TraefikBackupConfig) -> None:
    """Write a backup directory and archive under ``root`` and fetch the archive."""

    if cfg.include_acme and not _exists(cfg.acme_path):
        raise DeployError(f"traefik_backup: ACME state file not found: {cfg.acme_path}")
    if cfg.include_dynamic and output(_dynamic_tree_check(cfg.dynamic_dir) + " && echo yes").strip() != "yes":
        raise DeployError("traefik_backup: dynamic source must be a directory of regular files (no links)")
    # Ansible's ``ansible_date_time.iso8601_basic_short``: the host's local time.
    stamp = output("date +%Y%m%dT%H%M%S").strip()
    if len(stamp) != 15:
        raise DeployError("traefik_backup: cannot read the host's time")
    name = f"{cfg.prefix}-{stamp}"
    backup_dir = f"{cfg.root}/{name}"
    archive = f"{backup_dir}.tar.gz"

    root = shlex.quote(cfg.root)
    if output(f"if [ -L {root} ] || {{ [ -e {root} ] && [ ! -d {root} ]; }}; then echo unsafe; fi").strip():
        raise DeployError("traefik_backup: backup root must be a real directory, not a link or special file")
    for target in (backup_dir, archive):
        quoted = shlex.quote(target)
        if output(f"if [ -e {quoted} ] || [ -L {quoted} ]; then echo exists; fi").strip():
            raise DeployError("traefik_backup: backup attempt already exists; choose another prefix or timestamp")

    for path in (cfg.root, backup_dir, f"{backup_dir}/acme", f"{backup_dir}/dynamic"):
        directory(path, user="root", group="root", mode="0700")
    if cfg.include_acme:
        dest = f"{backup_dir}/acme/{PurePosixPath(cfg.acme_path).name}"
        server.shell(
            name="Copy the ACME state",
            commands=[f"install -o root -g root -m 0600 {shlex.quote(cfg.acme_path)} {shlex.quote(dest)}"],
        )
    if cfg.include_dynamic:
        server.shell(
            name="Copy the dynamic config tree",
            commands=[_dynamic_copy(cfg.dynamic_dir, f"{backup_dir}/dynamic")],
        )
    files.put(
        name="Write the backup metadata",
        src=StringIO(
            f"timestamp: {stamp}\nacme_path: {cfg.acme_path}\n"
            f"include_acme: {str(cfg.include_acme).lower()}\n"
            f"dynamic_dir: {cfg.dynamic_dir}\ninclude_dynamic: {str(cfg.include_dynamic).lower()}\n"
        ),
        dest=f"{backup_dir}/metadata.yml",
        user="root",
        group="root",
        mode="0600",
    )
    if not cfg.create_archive:
        return
    server.shell(
        name=f"Create {archive}",
        commands=[
            f"(umask 077 && tar -czf {shlex.quote(archive)} -C {shlex.quote(cfg.root)} -- {shlex.quote(name)} "
            f"&& chmod 0600 {shlex.quote(archive)})"
        ],
    )
    if cfg.fetch_local:
        local_dir = str(cfg.local_dir or Path.home() / "backups" / "traefik")
        python.call(name=f"Ensure {local_dir} (0700)", function=_private_local_dir, path=local_dir)
        python.call(
            name="Check the local archive destination",
            function=_private_local_file,
            path=f"{local_dir}/{name}.tar.gz",
            missing_ok=True,
        )
        files.get(name="Fetch the backup archive", src=archive, dest=f"{local_dir}/{name}.tar.gz")
        python.call(
            name="Restrict fetched archive permissions (0600)",
            function=_private_local_file,
            path=f"{local_dir}/{name}.tar.gz",
        )


def _selected_archive(cfg: TraefikRestoreConfig) -> str:
    if cfg.archive != "latest":
        path = cfg.archive if cfg.archive.startswith("/") else f"{cfg.root}/{cfg.archive}"
        if not _exists(path):
            raise DeployError(f"traefik_restore: archive not found: {path}")
        return path
    newest = output(
        f"find {shlex.quote(cfg.root)} -maxdepth 1 -type f -name '*.tar.gz' -printf '%T@ %p\\n' | sort -rn | head -n 1"
    ).strip()
    if not newest:
        raise DeployError(f"traefik_restore: no Traefik backup archives found in {cfg.root}")
    return newest.partition(" ")[2]


@deploy("Traefik restore")
def deploy_traefik_restore(cfg: TraefikRestoreConfig) -> None:
    """Unpack a backup archive in ``staging_dir`` and put its ACME state back."""

    refuse_transaction_managed(cfg.transaction_required, "traefik_restore")
    archive = _selected_archive(cfg)
    staging = shlex.quote(cfg.staging_dir)
    acme = PurePosixPath(cfg.acme_path)
    put_back = ""
    if cfg.include_acme:
        source = f'"$payload"/acme/{shlex.quote(acme.name)}'
        put_back = (
            f'[ -f {source} ] || {{ echo "ACME state file not found in archive payload" >&2; exit 1; }}; '
            f"install -d -o root -g root -m 0700 {shlex.quote(str(acme.parent))}; "
            f"install -o root -g root -m 0600 {source} {shlex.quote(cfg.acme_path)}; "
        )
    server.shell(
        name=f"Restore from {archive}",
        commands=[
            f"set -e; rm -rf {staging}; mkdir -m 0700 {staging}; "
            f"tar -xzf {shlex.quote(archive)} -C {staging}; "
            f"payload=$(find {staging} -mindepth 1 -maxdepth 1 -type d | head -n 1); "
            '[ -n "$payload" ] || { echo "no payload directory in the archive" >&2; exit 1; }; '
            f"{put_back}rm -rf {staging}"
        ],
    )
    if not cfg.include_acme:
        host.noop("include_acme is off; nothing restored")
