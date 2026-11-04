"""SnappyMail backup and restore (the ``snappymail_backup`` and ``snappymail_restore`` roles).

A backup is one archive ``<root>/<prefix>-<timestamp>.tar.gz`` (or
``.tar.zst``) of the data directory, with the data directory's name as its
only top-level entry, plus the manifest ``<archive>.yml``, exactly as the role
writes them. Either tool restores the other's archives.

Backup and restore run on the host as one bash script each (``files/``), so
the role's ``block``/``always``/``rescue`` structure keeps its meaning: units
a backup stopped start again whatever the archive did; a restore validates
the archive in a staging directory next to the data directory before it
stops nginx and PHP-FPM, keeps the live data as a pre-restore copy
(ops-library's ``restore_preserve_internal``, vendored as
``_lifecycle/files/preserve.py``) and always removes the staging directory.
A restore that fails before the live data was touched starts the units it
stopped again; after that it leaves them stopped and points to the copy, as
the role does. No path removes a pre-restore copy.

Deliberate differences from the roles:

- ``archive`` is ``latest`` or an archive name directly below the restore
  root, never an absolute path or an extracted directory.
- ``dry_run`` (the playbook's check mode) runs the role's checks: the layout
  check, the extraction into staging, the payload and PHP-FPM pool checks and
  the preservation preflight; it then removes the staging directory and stops.
  Without the data directory's parent it stops before the extraction (it
  would have to create the parent).
- An existing data parent keeps its mode (the role's ``file`` task sets
  ``0755``); a missing one is created ``root:root 0755``.
- A failed stop ends the restore at once and starts the units stopped so far
  again (the role's loop would also try the second unit and leave the failed
  one alone).
- With several ``snappymail.conf`` pools (one per PHP version) the
  lexically first path names the PHP-FPM service; the role's order is
  unspecified.
- A symlinked archive is refused. The backup root must lie outside the data
  directory. ``fetch_local`` defaults to the playbook's ``true`` (the role's
  default is ``false``).
- The role installs ``rsync`` (apt, cache valid 3600 s) only for a real
  restore, after the source is resolved; here it is installed for a real
  restore before the restore script runs, and a dry run does not need it.
- A symlinked restore root finds no ``latest`` archive (``find`` does not
  descend it); name the archive instead.
- The restore's ``host_name`` is not used on the host (the role reads none).
- Without a ``<version>/fpm/`` part in the pool's path the PHP-FPM service is
  ``php-fpm``; the role would use the whole path as the service name.
- ``retain`` counts archives only: the role's ``<prefix>-*.tar.*`` glob also
  counts the ``.tar.gz.yml`` manifests, so it kept about half as many.
- The backup restarts the units it found active and stopped (a failed stop
  included); the role's "changed or failed" rule does the same, except that
  it also tries to start a unit whose stop failed because it does not exist.

``required_mount`` keeps the backup root and the restore's staging directory
(next to the data directory) on the encrypted disk
(:mod:`ops_deploy.services._lifecycle.local_backup`).
"""

from __future__ import annotations

import os
from pathlib import Path, PurePosixPath
from typing import Annotated, Literal, Self

from pydantic import Field, StrictBool, model_validator
from pyinfra.api import DeployError, deploy
from pyinfra.operations import apt, files, python, server

from ops_deploy.base._common import output
from ops_deploy.core.config import UnixUser
from ops_deploy.services._lifecycle import flag, private_local_dir, script
from ops_deploy.services._lifecycle.canonical import CanonicalPath, FileMode, Hostname, Prefix
from ops_deploy.services._lifecycle.local_backup import MountGuard
from ops_deploy.services._lifecycle.preserve import PRESERVE_PY

FILES = Path(__file__).parent / "files"
# ``latest``, or a ``.tar.gz``/``.tar.zst`` name directly below the restore root.
ArchiveName = Annotated[str, Field(pattern=r"^(latest|[A-Za-z0-9._+-]+\.tar\.(gz|zst))$")]


class SnappyMailBackupConfig(MountGuard):
    # The manifest's ``host`` (Ansible's ``inventory_hostname``).
    host_name: Hostname
    data_dir: CanonicalPath = "/mnt/cryptdata/snappymail"
    root: CanonicalPath = "/mnt/cryptdata/backups/snappymail"
    # The playbook passes ``backup_prefix`` (default ``manual``); the role's own default is ``snappymail``.
    prefix: Prefix = "manual"
    archive_format: Literal["tar.gz", "tar.zst"] = "tar.gz"
    owner: UnixUser = "root"
    group: UnixUser = "root"
    mode: FileMode = "0600"
    dir_mode: FileMode = "0700"
    stop_services: StrictBool = False
    # 0 keeps everything; otherwise the newest N ``<prefix>-*.tar.*`` archives stay.
    retain: int = Field(default=0, ge=0)
    manifest: StrictBool = True
    fetch_local: StrictBool = True
    # None: ``~/backups/snappymail`` on the controller.
    fetch_dir: Path | None = None

    def guarded_paths(self) -> dict[str, str]:
        return {"root": self.root}

    @model_validator(mode="after")
    def _data_apart(self) -> Self:
        if PurePosixPath(self.root).is_relative_to(self.data_dir):
            raise ValueError(f"root ({self.root}) must lie outside data_dir ({self.data_dir})")
        return self


class SnappyMailRestoreConfig(MountGuard):
    host_name: Hostname
    archive: ArchiveName = "latest"
    root: CanonicalPath = "/mnt/cryptdata/backups/snappymail"
    data_dir: CanonicalPath = "/mnt/cryptdata/snappymail"
    # Restore into an empty directory after keeping the live data (False: keep it in place too).
    clean: StrictBool = True
    owner: UnixUser = "snappymail"
    group: UnixUser = "snappymail"
    mode: FileMode = "0750"
    restart_services: StrictBool = True
    dry_run: StrictBool = False

    @property
    def staging_parent(self) -> str:
        return str(PurePosixPath(self.data_dir).parent)

    def guarded_paths(self) -> dict[str, str]:
        # The role stages next to the data directory.
        return {"data_dir": self.data_dir}


def _stamp() -> str:
    # Ansible's ``ansible_date_time.iso8601_basic_short``: the host's local time.
    stamp = output("date +%Y%m%dT%H%M%S").strip()
    if len(stamp) != 15:
        raise DeployError("snappymail_backup: cannot read the host's time")
    return stamp


def backup_manifest(cfg: SnappyMailBackupConfig, *, stamp: str, archive: str) -> str:
    """``<archive>.yml`` exactly as the role's template renders it."""

    return (
        f'timestamp: "{stamp}"\n'
        f'host: "{cfg.host_name}"\n'
        f'data_dir: "{cfg.data_dir}"\n'
        f'archive: "{archive}"\n'
        f'format: "{cfg.archive_format}"\n'
        "version: 1\n"
    )


def _restrict_local(path: str) -> None:
    # ``fetch`` writes the copy with the controller's umask; the archive holds the SnappyMail secrets.
    if os.path.exists(path):
        os.chmod(path, 0o600)


@deploy("SnappyMail backup")
def deploy_snappymail_backup(cfg: SnappyMailBackupConfig) -> None:
    """Archive the SnappyMail data directory into the backup root and fetch the archive."""

    stamp = _stamp()
    archive = f"{cfg.root}/{cfg.prefix}-{stamp}.{cfg.archive_format}"
    data = PurePosixPath(cfg.data_dir)
    server.shell(
        name="Back up SnappyMail",
        commands=[
            script(
                FILES / "backup.sh",
                {
                    "REQUIRED_MOUNT": cfg.required_mount or "",
                    "DATA": cfg.data_dir,
                    "PARENT": str(data.parent),
                    "BASENAME": data.name,
                    "ROOT": cfg.root,
                    "ARCHIVE": archive,
                    "ZSTD": flag(cfg.archive_format == "tar.zst"),
                    "OWNER": cfg.owner,
                    "GROUP": cfg.group,
                    "MODE": cfg.mode,
                    "DIR_MODE": cfg.dir_mode,
                    "STOP": flag(cfg.stop_services),
                    "PHP_ETC": "/etc/php",
                    "MANIFEST": backup_manifest(cfg, stamp=stamp, archive=archive) if cfg.manifest else "",
                    "PREFIX": cfg.prefix,
                    "RETAIN": str(cfg.retain),
                },
            )
        ],
        _shell_executable="bash",
    )
    if cfg.fetch_local:
        local_dir = str(cfg.fetch_dir or Path.home() / "backups" / "snappymail")
        local = f"{local_dir}/{PurePosixPath(archive).name}"
        python.call(name=f"Ensure {local_dir} (0700)", function=private_local_dir, path=local_dir)
        files.get(name="Fetch the backup archive", src=archive, dest=local)
        python.call(name="Restrict the local archive copy (0600)", function=_restrict_local, path=local)


@deploy("SnappyMail restore")
def deploy_snappymail_restore(cfg: SnappyMailRestoreConfig) -> None:
    """Restore a SnappyMail archive over the data directory, keeping the live data as a pre-restore copy."""

    if not cfg.dry_run:
        apt.packages(name="Ensure rsync", packages=["rsync"], update=True, cache_time=3600)
    server.shell(
        name="Restore SnappyMail" + (" (dry run)" if cfg.dry_run else ""),
        commands=[
            script(
                FILES / "restore.sh",
                {
                    "REQUIRED_MOUNT": cfg.required_mount or "",
                    "ARCHIVE": cfg.archive,
                    "ROOT": cfg.root,
                    "DATA": cfg.data_dir,
                    "PARENT": cfg.staging_parent,
                    "BASENAME": PurePosixPath(cfg.data_dir).name,
                    "CLEAN": flag(cfg.clean),
                    "OWNER": cfg.owner,
                    "GROUP": cfg.group,
                    "MODE": cfg.mode,
                    "RESTART": flag(cfg.restart_services),
                    "PHP_ETC": "/etc/php",
                    "DRY_RUN": flag(cfg.dry_run),
                    "PRESERVE": ("python3", "-I", "-c", PRESERVE_PY),
                },
            )
        ],
        _shell_executable="bash",
    )


__all__ = [
    "SnappyMailBackupConfig",
    "SnappyMailRestoreConfig",
    "backup_manifest",
    "deploy_snappymail_backup",
    "deploy_snappymail_restore",
]
