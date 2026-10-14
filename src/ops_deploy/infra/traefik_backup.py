"""Traefik ACME backup and restore (the ``traefik_backup`` and ``traefik_restore`` roles).

A backup is a directory ``<root>/<prefix>-<timestamp>`` with ``metadata.yml``
and, when ``include_acme`` is set, ``acme/acme.json``, packed as
``<root>/<prefix>-<timestamp>.tar.gz`` with that directory as the archive's
only top-level entry, as the role's ``archive`` task packs it. Either tool can
restore the other's archives.

Like the roles, ACME state is left out unless ``include_acme`` is set; then
the archive holds the private keys of every certificate Traefik obtained, so
it is created root-only (directories 0700, files 0600) and the local copy's
directory is 0700. Restore refuses transaction-managed hosts, as the role
does; backup only reads Traefik's state and is allowed everywhere.
"""

from __future__ import annotations

import os
import shlex
from io import StringIO
from pathlib import Path, PurePosixPath
from typing import Annotated

from pydantic import Field
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
    create_archive: bool = True
    fetch_local: bool = True
    # None: ``~/backups/traefik`` on the controller.
    local_dir: Path | None = None


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
    os.makedirs(path, mode=0o700, exist_ok=True)
    os.chmod(path, 0o700)


@deploy("Traefik backup")
def deploy_traefik_backup(cfg: TraefikBackupConfig) -> None:
    """Write a backup directory and archive under ``root`` and fetch the archive."""

    if cfg.include_acme and not _exists(cfg.acme_path):
        raise DeployError(f"traefik_backup: ACME state file not found: {cfg.acme_path}")
    # Ansible's ``ansible_date_time.iso8601_basic_short``: the host's local time.
    stamp = output("date +%Y%m%dT%H%M%S").strip()
    if len(stamp) != 15:
        raise DeployError("traefik_backup: cannot read the host's time")
    name = f"{cfg.prefix}-{stamp}"
    backup_dir = f"{cfg.root}/{name}"
    archive = f"{backup_dir}.tar.gz"

    for path in (cfg.root, backup_dir, f"{backup_dir}/acme"):
        directory(path, user="root", group="root", mode="0700")
    if cfg.include_acme:
        dest = f"{backup_dir}/acme/{PurePosixPath(cfg.acme_path).name}"
        server.shell(
            name="Copy the ACME state",
            commands=[f"install -o root -g root -m 0600 {shlex.quote(cfg.acme_path)} {shlex.quote(dest)}"],
        )
    files.put(
        name="Write the backup metadata",
        src=StringIO(f"timestamp: {stamp}\nacme_path: {cfg.acme_path}\n"),
        dest=f"{backup_dir}/metadata.yml",
        user="root",
        group="root",
        mode="0600",
    )
    if not cfg.create_archive:
        return
    server.shell(
        name=f"Create {archive}",
        commands=[f"(umask 077 && tar -czf {shlex.quote(archive)} -C {shlex.quote(cfg.root)} {shlex.quote(name)})"],
    )
    if cfg.fetch_local:
        local_dir = str(cfg.local_dir or Path.home() / "backups" / "traefik")
        python.call(name=f"Ensure {local_dir} (0700)", function=_private_local_dir, path=local_dir)
        files.get(name="Fetch the backup archive", src=archive, dest=f"{local_dir}/{name}.tar.gz")


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
