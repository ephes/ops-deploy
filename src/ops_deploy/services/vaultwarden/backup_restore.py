"""Vaultwarden backup and restore (the ``vaultwarden_backup`` and ``vaultwarden_restore`` roles).

A backup is ``<root>/<prefix>-<timestamp>.tar.gz`` holding the directory
``<prefix>-<timestamp>/`` with ``data/`` (``db.sqlite3`` as a ``sqlite3
.backup`` copy, ``attachments/``, ``sends/``, the RSA keys), ``config/``,
``systemd/override.conf``, ``traefik/`` and ``manifest.yml``, exactly as the
role writes it; with ``encrypt`` the archive is age-encrypted for
``age_recipient`` (``.tar.gz.age``) and the plain archive removed. The
archive is fetched into ``~/backups/vaultwarden``.

The restore is the role's legacy path from those controller copies (Echoport
is the documented restore runner, docs in ops-control): it refuses unless
``legacy_restore_confirmed`` is set (ops-control's
``VAULTWARDEN_LEGACY_RESTORE_CONFIRM=yes`` gate), picks the archive on the
controller, decrypts an ``.age`` archive with ``age_identity`` in memory (no
plaintext file on the controller) and streams it on stdin into one host
script, which keeps the role's safety contract:

- the staged database must pass ``PRAGMA integrity_check`` before anything is
  stopped or overwritten;
- a failed stop (or a unit not confirmed ``inactive``/``failed``) aborts with
  the live data untouched;
- a timestamped safety copy of the data directory and of the config, systemd
  override and Traefik file is taken after the stop, before the first
  overwrite, and never removed;
- stale ``-wal``/``-shm``/``-journal`` files go before the database copy;
- any failure while overwriting puts the safety copy back (only once the unit
  is confirmed down) and leaves Vaultwarden stopped;
- the staging directory is removed whether the restore succeeds or fails.

Deliberate differences from the roles:

- ``archive`` is ``latest`` or a name directly in the controller directory,
  never an absolute path.
- ``dry_run`` selects the archive on the controller (no decryption), checks
  the mount, resets the (empty) staging directory and refuses symlinked data
  paths; it uploads nothing and changes no live file.
- The backup prunes old archives on the host before the controller fetches
  the new one (the role fetches first).
- ``age_recipient`` must be an X25519 ``age1...`` recipient; the role would
  also take SSH or plugin recipients.
- The staging directory is created fresh (``mkdir``, never an existing one),
  and a unit that is not installed must not be running either.
- The archive reaches the host on the restore script's stdin (base64) instead
  of a controller-side decrypted file and a copy task.
- A changed Traefik route is written only while no Traefik transaction holds
  its lock; a lock held at the start stops the restore before Vaultwarden is
  stopped, a lock taken later rolls the restore back like any other failure.
  The rollback puts the old route back without that check, as the role does.
- Retention (``retain``, the playbook's 7) counts the plain and encrypted
  archives of the prefix by mtime, as the role, whoever wrote them.

``required_mount`` keeps the backup root and the restore's staging directory
on the external disk (:mod:`ops_deploy.services._lifecycle.local_backup`).
"""

from __future__ import annotations

import base64
import os
import shlex
import subprocess
from pathlib import Path, PurePosixPath
from typing import Annotated, Self

from pydantic import Field, StrictBool, model_validator
from pyinfra.api import DeployError, deploy
from pyinfra.operations import apt, files, python, server

from ops_deploy.base._common import output
from ops_deploy.core.config import ServiceName, UnixUser
from ops_deploy.helpers.probes import stdin_arguments
from ops_deploy.helpers.traefik import route_guard_command
from ops_deploy.services._lifecycle import flag, private_local_dir, script
from ops_deploy.services._lifecycle.canonical import CanonicalPath, FileMode, Prefix
from ops_deploy.services._lifecycle.local_backup import MountGuard

FILES = Path(__file__).parent / "files"
# ``latest``, or a plain or age-encrypted archive name in the controller directory.
ArchiveName = Annotated[str, Field(pattern=r"^(latest|[A-Za-z0-9._+-]+\.tar\.gz(\.age)?)$")]
AgeRecipient = Annotated[str, Field(pattern=r"^age1[0-9a-z]{58}$")]


class _Paths(MountGuard):
    """``vaultwarden_shared``'s paths."""

    service_name: ServiceName = "vaultwarden"
    user: UnixUser = "vaultwarden"
    group: UnixUser = "vaultwarden"
    data_dir: CanonicalPath = "/var/lib/vaultwarden/data"
    config_file: CanonicalPath = "/etc/vaultwarden.env"
    service_unit: CanonicalPath = "/lib/systemd/system/vaultwarden.service"
    service_override_dir: CanonicalPath = "/etc/systemd/system/vaultwarden.service.d"
    traefik_config_path: CanonicalPath = "/etc/traefik/dynamic/vaultwarden.yml"


class VaultwardenBackupConfig(_Paths):
    bin_path: CanonicalPath = "/usr/bin/vaultwarden"
    root: CanonicalPath = "/opt/backups/vaultwarden"
    prefix: Prefix = "manual"
    owner: UnixUser = "root"
    group_owner: UnixUser = "root"
    dir_mode: FileMode = "0700"
    file_mode: FileMode = "0600"
    stop_service: StrictBool = True
    include_data: StrictBool = True
    include_config: StrictBool = True
    include_systemd: StrictBool = True
    include_traefik: StrictBool = True
    create_archive: StrictBool = True
    skip_dependencies: StrictBool = False
    # 0 keeps everything; otherwise the newest N archives of the prefix (plain and ``.age``).
    retain: int = Field(default=7, ge=0)
    encrypt: StrictBool = False
    age_recipient: AgeRecipient | None = None
    fetch_local: StrictBool = True
    # None: ``~/backups/vaultwarden`` on the controller.
    local_dir: Path | None = None

    def guarded_paths(self) -> dict[str, str]:
        return {"root": self.root}

    @model_validator(mode="after")
    def _recipient(self) -> Self:
        if self.encrypt and self.create_archive and not self.age_recipient:
            raise ValueError("vaultwarden_backup_age_recipient must be set when vaultwarden_backup_encrypt is true")
        return self


class VaultwardenRestoreConfig(_Paths):
    # ops-control's VAULTWARDEN_LEGACY_RESTORE_CONFIRM=yes: nothing runs without it.
    legacy_restore_confirmed: StrictBool = False
    archive: ArchiveName = "latest"
    # The controller directory the backups were fetched into; None: ``~/backups/vaultwarden``.
    local_dir: Path | None = None
    # The age identity for ``.age`` archives; None: ``~/.config/sops/age/keys.txt``.
    age_identity: Path | None = None
    log_dir: CanonicalPath = "/var/log/vaultwarden"
    staging_dir: CanonicalPath = "/tmp/vaultwarden-restore"
    safety_root: CanonicalPath = "/var/backups/vaultwarden-pre-restore"
    restart: StrictBool = True
    cleanup: StrictBool = True
    dry_run: StrictBool = False

    def guarded_paths(self) -> dict[str, str]:
        return {"staging_dir": self.staging_dir}

    @model_validator(mode="after")
    def _apart(self) -> Self:
        # The script removes the staging directory first; the safety copy must
        # not lie in what it protects or in the staging directory.
        staging, safety = PurePosixPath(self.staging_dir), PurePosixPath(self.safety_root)
        live = [self.data_dir, self.config_file, self.service_override_dir, self.traefik_config_path, self.log_dir]
        for path in [*live, self.safety_root]:
            if PurePosixPath(path).is_relative_to(staging) or staging.is_relative_to(path):
                raise ValueError(f"staging_dir ({staging}) must lie apart from {path}")
        for path in live:
            if safety.is_relative_to(path) or PurePosixPath(path).is_relative_to(safety):
                raise ValueError(f"safety_root ({safety}) must lie apart from {path}")
        return self


def _stamp() -> str:
    # Ansible's ``ansible_date_time.iso8601_basic_short``: the host's local time.
    stamp = output("date +%Y%m%dT%H%M%S").strip()
    if len(stamp) != 15:
        raise DeployError("vaultwarden: cannot read the host's time")
    return stamp


def backup_manifest(cfg: VaultwardenBackupConfig, *, version: str, stamp: str) -> str:
    """``manifest.yml`` exactly as the role's template renders it."""

    return (
        f'version: "{version}"\n'
        f'timestamp: "{stamp}"\n'
        f'archive: "{cfg.prefix}-{stamp}.tar.gz"\n'
        f'data_dir: "{cfg.data_dir}"\n'
        f'config: "{cfg.config_file}"\n'
        f'service_unit: "{cfg.service_unit}"\n'
        f'traefik_config: "{cfg.traefik_config_path}"\n'
    )


def _restrict_local(path: str) -> None:
    # ``fetch`` writes the copy with the controller's umask; the archive holds the vault.
    if os.path.exists(path):
        os.chmod(path, 0o600)


@deploy("Vaultwarden backup")
def deploy_vaultwarden_backup(cfg: VaultwardenBackupConfig) -> None:
    """Copy the vault with Vaultwarden stopped, pack (and encrypt) the archive, prune and fetch it."""

    if not cfg.skip_dependencies:
        apt.packages(name="Ensure sqlite3 and rsync", packages=["sqlite3", "rsync"], update=True, cache_time=3600)
    if cfg.encrypt and cfg.create_archive:
        apt.packages(name="Ensure age", packages=["age"], update=True, cache_time=3600)
    # The role's ``stdout | default('unknown')``: an empty stdout stays empty.
    version = output(f"{cfg.bin_path} --version 2>/dev/null || true").strip()
    stamp = _stamp()
    name = f"{cfg.prefix}-{stamp}"
    final = f"{cfg.root}/{name}.tar.gz" + (".age" if cfg.encrypt and cfg.create_archive else "")
    server.shell(
        name="Back up Vaultwarden",
        commands=[
            script(
                FILES / "backup.sh",
                {
                    "REQUIRED_MOUNT": cfg.required_mount or "",
                    "ROOT": cfg.root,
                    "DIR": f"{cfg.root}/{name}",
                    "OWNER": cfg.owner,
                    "GROUP": cfg.group_owner,
                    "DIR_MODE": cfg.dir_mode,
                    "FILE_MODE": cfg.file_mode,
                    "DATA": cfg.data_dir,
                    "CONFIG": cfg.config_file,
                    "OVERRIDE": f"{cfg.service_override_dir}/override.conf",
                    "TRAEFIK": cfg.traefik_config_path,
                    "SERVICE": cfg.service_name,
                    "STOP": flag(cfg.stop_service),
                    "INCLUDE_DATA_DIR": flag(cfg.include_data),
                    "INCLUDE_CONFIG": flag(cfg.include_config),
                    "INCLUDE_SYSTEMD": flag(cfg.include_systemd),
                    "INCLUDE_TRAEFIK": flag(cfg.include_traefik),
                    "MANIFEST": backup_manifest(cfg, version=version, stamp=stamp),
                    "ARCHIVE": flag(cfg.create_archive),
                    "ENCRYPT": flag(cfg.encrypt and cfg.create_archive),
                    "RECIPIENT": cfg.age_recipient or "",
                    "PREFIX": cfg.prefix,
                    "RETAIN": str(cfg.retain),
                },
            )
        ],
        _shell_executable="bash",
    )
    if cfg.fetch_local and cfg.create_archive:
        local_dir = str(cfg.local_dir or Path.home() / "backups" / "vaultwarden")
        local = f"{local_dir}/{PurePosixPath(final).name}"
        python.call(name=f"Ensure {local_dir} (0700)", function=private_local_dir, path=local_dir)
        files.get(name="Fetch the backup archive", src=final, dest=local)
        python.call(name="Restrict the local archive copy (0600)", function=_restrict_local, path=local)


def select_archive(local_dir: Path, archive: str) -> Path:
    """The role's controller-side choice: ``latest`` (newest by mtime) or a name in ``local_dir``."""

    if archive == "latest":
        candidates = [
            path
            for path in (local_dir.iterdir() if local_dir.is_dir() else ())
            if not path.name.startswith(".")
            and path.is_file()
            and not path.is_symlink()
            and (path.name.endswith(".tar.gz") or path.name.endswith(".tar.gz.age"))
        ]
        if not candidates:
            raise DeployError(f"No Vaultwarden backup archives found in {local_dir}")
        return max(candidates, key=lambda path: path.stat().st_mtime)
    selected = local_dir / archive
    if not selected.is_file() or selected.is_symlink():
        raise DeployError(f"Vaultwarden restore archive not found: {selected}")
    return selected


def archive_bytes(selected: Path, identity: Path) -> bytes:
    """The plain archive: read, or decrypted with ``age`` in memory (no plaintext file)."""

    if not selected.name.endswith(".age"):
        return selected.read_bytes()
    try:
        done = subprocess.run(
            ["age", "--decrypt", "--identity", str(identity), str(selected)], capture_output=True, check=False
        )
    except OSError as exc:
        raise DeployError(f"vaultwarden_restore: cannot run age on the controller ({exc.strerror})") from None
    if done.returncode != 0:
        # age's stderr names files and errors, never key material or plaintext.
        reason = done.stderr.decode(errors="replace").strip()[:300]
        raise DeployError(f"vaultwarden_restore: age could not decrypt {selected.name}: {reason}")
    return done.stdout


@deploy("Vaultwarden restore")
def deploy_vaultwarden_restore(cfg: VaultwardenRestoreConfig) -> None:
    """The legacy restore from a controller archive, with the role's safety copy and rollback."""

    if not cfg.legacy_restore_confirmed:
        raise DeployError(
            "Refusing the legacy Vaultwarden restore: it overwrites the live vault. Use the Echoport "
            "restore instead (pre-restore safety snapshot, health check, rollback), or confirm the "
            "legacy path explicitly (VAULTWARDEN_LEGACY_RESTORE_CONFIRM=yes)."
        )
    local_dir = cfg.local_dir or Path.home() / "backups" / "vaultwarden"
    selected = select_archive(local_dir, cfg.archive)
    identity = cfg.age_identity or Path.home() / ".config" / "sops" / "age" / "keys.txt"
    encrypted = selected.name.endswith(".age")
    payload = "" if cfg.dry_run else base64.encodebytes(archive_bytes(selected, identity)).decode()
    if not cfg.dry_run:
        apt.packages(name="Ensure rsync and sqlite3", packages=["rsync", "sqlite3"], update=True, cache_time=3600)
    # The safety copy's name: the role's ``now(utc=true)``, from the host's clock.
    safety_stamp = output("date -u +%Y%m%dT%H%M%SZ").strip()
    if len(safety_stamp) != 16:
        raise DeployError("vaultwarden_restore: cannot read the host's time")
    commands = [
        script(
            FILES / "restore.sh",
            {
                "REQUIRED_MOUNT": cfg.required_mount or "",
                "ARCHIVE_NAME": selected.name,
                "ENCRYPTED": flag(encrypted),
                "DRY_RUN": flag(cfg.dry_run),
                "STAGING": cfg.staging_dir,
                "CLEANUP": flag(cfg.cleanup),
                "SAFETY_ROOT": cfg.safety_root,
                "SAFETY_DIR": f"{cfg.safety_root}/{safety_stamp}",
                "DATA": cfg.data_dir,
                "CONFIG": cfg.config_file,
                "CONFIG_NAME": PurePosixPath(cfg.config_file).name,
                "OVERRIDE_DIR": cfg.service_override_dir,
                "TRAEFIK": cfg.traefik_config_path,
                "LOG_DIR": cfg.log_dir,
                "SERVICE": cfg.service_name,
                "USER_NAME": cfg.user,
                "GROUP_NAME": cfg.group,
                "RESTART": flag(cfg.restart),
                "ROUTE_GUARD": shlex.split(route_guard_command()),
            },
        )
    ]
    server.shell(
        name="Restore Vaultwarden" + (" (dry run)" if cfg.dry_run else ""),
        commands=commands,
        _shell_executable="bash",
        # No pty: it would echo the archive back (stdin_arguments).
        **stdin_arguments(payload or None),
    )


__all__ = [
    "VaultwardenBackupConfig",
    "VaultwardenRestoreConfig",
    "archive_bytes",
    "backup_manifest",
    "deploy_vaultwarden_backup",
    "deploy_vaultwarden_restore",
    "select_archive",
]
