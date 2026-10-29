"""Traefik dynamic-config backup and optional ACME backup/restore.

A backup holds ``metadata.yml``, the whole ``dynamic/`` tree (default on)
and optional ``acme/`` state, under one ``<prefix>-<timestamp>/`` archive
entry. Dynamic files may contain authentication hashes or other credentials;
the containing directory and archive stay private even without ACME.

Only regular files/directories are supported for dynamic snapshots: symlinks
and special entries refuse rather than follow data outside the selected tree.
Restore remains ACME-only and refuses transaction-managed hosts. Its explicit
dry_run path validates without staging or publication. It never publishes archived dynamic routes.

``required_mount`` keeps the backup root (and the restore's staging
directory) on an external disk and ``retain_count``/``retain_days`` limit the
snapshots a backup keeps (:mod:`ops_deploy.services._lifecycle.local_backup`).
The restore's staging directory is removed whether the restore succeeds or
fails.
"""

from __future__ import annotations

import json
import os
import shlex
import stat
from io import StringIO
from pathlib import Path, PurePosixPath
from typing import Annotated, Self

from pydantic import BeforeValidator, Field, field_validator, model_validator
from pyinfra.api import DeployError, deploy
from pyinfra.operations import files, python, server

from ops_deploy.base._common import AbsolutePath, output
from ops_deploy.helpers.probes import probe, stdin_arguments, verify_probe
from ops_deploy.infra._common import directory
from ops_deploy.infra.traefik_lifecycle_state import refuse_managed
from ops_deploy.services._lifecycle.local_backup import (
    MountGuard,
    SnapshotRetention,
    backup_preflight,
    mount_check,
    retention,
)

Prefix = Annotated[str, Field(pattern=r"^[A-Za-z0-9._-]+$")]
# An archive name below the backup root, or an absolute path.
ArchiveName = Annotated[str, Field(pattern=r"^(latest|/?[A-Za-z0-9._/ +\-]+)$")]


def _mode_input(value: object) -> object:
    return format(value, "04o") if type(value) is int else value


Mode = Annotated[str, BeforeValidator(_mode_input), Field(pattern=r"^0?[0-7]{3}$")]


def _identity_input(value: object) -> object:
    return str(value) if type(value) is int else value


Identity = Annotated[str, BeforeValidator(_identity_input), Field(pattern=r"^(?:[a-z_][a-z0-9_-]*|[0-9]+)$")]
RESTORE_SCRIPT = (Path(__file__).parent / "files/traefik_restore_host.py").read_text()


class TraefikBackupConfig(SnapshotRetention):
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

    def guarded_paths(self) -> dict[str, str]:
        return {"root": self.root}


SpacedAbsolutePath = Annotated[str, Field(pattern=r"^/[A-Za-z0-9._/ +\-]*$")]


class TraefikRestoreConfig(MountGuard):
    # ``latest``: the newest ``*.tar.gz`` in ``root`` by modification time.
    archive: ArchiveName = "latest"
    required_mount: SpacedAbsolutePath | None = None
    root: SpacedAbsolutePath = "/opt/backups/traefik"
    staging_dir: SpacedAbsolutePath = "/tmp/traefik-restore"
    staging_mode: Mode = "0700"
    archive_extension: Annotated[str, Field(pattern=r"^[A-Za-z0-9.]+$")] = "tar.gz"
    dry_run: bool = False
    acme_path: SpacedAbsolutePath = "/etc/traefik/acme/acme.json"
    acme_dir: SpacedAbsolutePath | None = None
    acme_owner: Identity = "root"
    acme_group: Identity = "root"
    acme_dir_mode: Mode = "0700"
    acme_mode: Mode = "0600"
    include_acme: bool = False
    # Transaction-managed hosts are refused, as by the role.
    transaction_required: bool = False

    @field_validator("archive")
    @classmethod
    def bounded_archive(cls, value: str) -> str:
        if not value.startswith("/") and ".." in PurePosixPath(value).parts:
            raise ValueError("Relative archive names must stay below the backup root")
        return value

    @field_validator("root", "staging_dir", "acme_path", "acme_dir")
    @classmethod
    def canonical_path(cls, value: str | None) -> str | None:
        if value is not None and ".." in PurePosixPath(value).parts:
            raise ValueError("Traefik restore paths cannot contain parent traversal")
        return str(PurePosixPath(value)) if value is not None else None

    @model_validator(mode="after")
    def bounded_staging(self) -> Self:
        if self.staging_dir in {"/", "/tmp", "/etc", "/var", "/var/lib"}:
            raise ValueError("staging_dir must identify the declared restore work directory")
        return self

    def guarded_paths(self) -> dict[str, str]:
        return {"staging_dir": self.staging_dir}


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


def _canonical(path: str) -> str:
    # ``PurePosixPath`` drops trailing separators and ``.`` components, so
    # ``link/`` and ``link/.`` name the link itself for ``test -L``.
    return str(PurePosixPath(path))


def _unsafe_root_check(root: str) -> str:
    quoted = shlex.quote(_canonical(root))
    return f"if [ -L {quoted} ] || {{ [ -e {quoted} ] && [ ! -d {quoted} ]; }}; then echo unsafe; fi"


def _resolved_paths(root: str, source: str) -> str:
    # GNU ``realpath -m`` resolves the existing ancestors of an absent root,
    # so an aliased root cannot land inside the live source tree.
    return f"realpath -m -- {shlex.quote(_canonical(root))} && realpath -e -- {shlex.quote(_canonical(source))}"


def _resolved_overlap(cfg: TraefikBackupConfig) -> bool:
    lines = output(_resolved_paths(cfg.root, cfg.dynamic_dir)).splitlines()
    if len(lines) != 2 or not all(line.startswith("/") for line in lines):
        return True
    root, source = PurePosixPath(lines[0]), PurePosixPath(lines[1])
    return root.is_relative_to(source) or source.is_relative_to(root)


def _dynamic_tree_check(path: str) -> str:
    source = shlex.quote(_canonical(path))
    return (
        f"test -d {source} && test ! -L {source} "
        f'&& unsafe=$(find {source} ! -type d ! -type f -print -quit) && test -z "$unsafe"'
    )


def _dynamic_copy(source: str, destination: str) -> str:
    # cp -a preserves modes and copies dot/nested files without following links.
    # Copying ``source/.`` also gives ``destination`` the source directory's
    # owner and mode, so restore the root:root 0700 container afterwards; the
    # descendants keep their source modes. GNU ``chmod 0700`` keeps a
    # directory's setuid/setgid bits, so the extra leading zero clears them
    # (BSD treats ``00700`` as plain ``0700``). Check again after copying: a
    # newly introduced link must not produce an apparently complete archive.
    target = shlex.quote(destination)
    return (
        f"{_dynamic_tree_check(source)} && "
        f"cp -a {shlex.quote(_canonical(source) + '/.')} {shlex.quote(destination + '/')} && "
        f"chown root:root {target} && chmod 00700 {target} && "
        f"{_dynamic_tree_check(destination)}"
    )


@deploy("Traefik backup")
def deploy_traefik_backup(cfg: TraefikBackupConfig) -> None:
    """Write a backup directory and archive under ``root`` and fetch the archive."""

    if cfg.include_acme and not _exists(cfg.acme_path):
        raise DeployError(f"traefik_backup: ACME state file not found: {cfg.acme_path}")
    if cfg.include_dynamic and output(_dynamic_tree_check(cfg.dynamic_dir) + " && echo yes").strip() != "yes":
        raise DeployError("traefik_backup: dynamic source must be a directory of regular files (no links)")
    if cfg.include_dynamic and _resolved_overlap(cfg):
        raise DeployError("traefik_backup: resolved dynamic source and backup root must not overlap")
    # Ansible's ``ansible_date_time.iso8601_basic_short``: the host's local time.
    stamp = output("date +%Y%m%dT%H%M%S").strip()
    if len(stamp) != 15:
        raise DeployError("traefik_backup: cannot read the host's time")
    name = f"{cfg.prefix}-{stamp}"
    root_dir = _canonical(cfg.root)
    backup_dir = f"{root_dir}/{name}"
    archive = f"{backup_dir}.tar.gz"

    if output(_unsafe_root_check(cfg.root)).strip():
        raise DeployError("traefik_backup: backup root must be a real directory, not a link or special file")
    for target in (backup_dir, archive):
        quoted = shlex.quote(target)
        if output(f"if [ -e {quoted} ] || [ -L {quoted} ]; then echo exists; fi").strip():
            raise DeployError("traefik_backup: backup attempt already exists; choose another prefix or timestamp")

    preflight = backup_preflight(cfg, root_dir, name)
    if preflight:
        server.shell(name="Check the backup root and name", commands=[preflight], _shell_executable="bash")
    for path in (root_dir, backup_dir, f"{backup_dir}/acme", f"{backup_dir}/dynamic"):
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
    if cfg.create_archive:
        server.shell(
            name=f"Create {archive}",
            commands=[
                f"(umask 077 && tar -czf {shlex.quote(archive)} -C {shlex.quote(root_dir)} -- {shlex.quote(name)} "
                f"&& chmod 0600 {shlex.quote(archive)})"
            ],
        )
    if cfg.retention:
        server.shell(
            name="Prune local snapshots",
            commands=[retention(cfg, root_dir, name, stamp)],
            _shell_executable="bash",
        )
    if cfg.create_archive and cfg.fetch_local:
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


@deploy("Traefik restore")
def deploy_traefik_restore(cfg: TraefikRestoreConfig) -> None:
    """Validate without writes, or stage/restore only the source ACME payload.

    Normal staging/extraction/cleanup is transient managed work even with
    include_acme=false. Only the explicit dry_run path is nonmutating.
    """
    refuse_managed(cfg.transaction_required, "traefik_restore")
    if (
        cfg.required_mount
        and probe(
            shlex.join(["bash", "-c", mount_check(cfg.required_mount, cfg.staging_dir)]),
            name="Traefik restore required mount",
        )
        is None
    ):
        raise DeployError("traefik_restore: required restore mount is unavailable")

    payload = cfg.model_dump(mode="json")
    command = shlex.join(["python3", "-I", "-c", RESTORE_SCRIPT])
    raw = probe(
        command + " validate", name="Traefik archive/path validation before mutation", stdin=json.dumps(payload)
    )
    try:
        result = json.loads(raw) if raw is not None else None
    except ValueError:
        result = None
    if (
        not isinstance(result, dict)
        or set(result) != {"valid", "archive"}
        or result["valid"] is not True
        or not isinstance(result["archive"], str)
    ):
        raise DeployError("traefik_restore: archive/path validation failed before mutation")
    payload["archive"] = result["archive"]
    if cfg.dry_run:
        verify_probe(
            command + " validate",
            name="Traefik archive validation only; no staging/publication",
            stdin=json.dumps(payload),
        )
    else:
        server.shell(
            name="Original ACME-only restore with private staging and cleanup",
            commands=[command + " apply"],
            **stdin_arguments(json.dumps(payload)),
        )
