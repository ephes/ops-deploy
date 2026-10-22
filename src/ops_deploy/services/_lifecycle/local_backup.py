"""Where local backups and restore work directories may live, and how long snapshots stay.

The local archives of the backup ports are rollback snapshots. Echoport (or
another off-host copy) is the backup of record, so a host keeps them on an
external disk with a retention rule, never on the root filesystem by accident:

- ``required_mount``: the mount point the backup root (or a restore's work
  directory) must lie below. Before anything is written there the host checks
  that it is mounted (an automount alone does not count) and that the path
  resolves below it; otherwise the run stops before its first write. ``None``
  (the default) checks nothing, as before.
- ``retain_count`` / ``retain_days``: snapshots written with either set are
  recorded in ``<root>/.ops-deploy-snapshots/``. After each such backup the
  recorded snapshots beyond the newest ``retain_count`` of their prefix or
  older than ``retain_days`` (by the timestamp in their name) are removed,
  directory and archive. A backup under retention refuses a name that is
  already taken (directory, archive or record). The snapshot just written
  always stays. Snapshots without a record (written by Ansible, by hand or
  before retention was set) are never removed. ``0`` turns a limit off; both ``0`` (the default) keeps
  everything and records nothing, as before.
"""

from __future__ import annotations

import shlex
from datetime import datetime, timedelta
from pathlib import PurePosixPath
from typing import Self

from pydantic import Field, model_validator

from ops_deploy.base._common import AbsolutePath, RoleConfig
from ops_deploy.services._lifecycle import COMMON

STAMP_FORMAT = "%Y%m%dT%H%M%S"


def _below(mount: str, path: str) -> bool:
    candidate = PurePosixPath(path)
    return ".." not in candidate.parts and candidate != PurePosixPath(mount) and candidate.is_relative_to(mount)


class MountGuard(RoleConfig):
    """``required_mount`` and the check that every guarded path lies below it."""

    required_mount: AbsolutePath | None = None

    def guarded_paths(self) -> dict[str, str]:
        """The config fields (name: path) that must lie below ``required_mount``."""

        return {}

    @model_validator(mode="after")
    def _paths_below_the_mount(self) -> Self:
        mount = self.required_mount
        if mount is None:
            return self
        parts = PurePosixPath(mount).parts
        if mount != str(PurePosixPath(mount)) or ".." in parts or len(parts) < 2:
            raise ValueError("required_mount must be a canonical absolute path other than /")
        for field, path in self.guarded_paths().items():
            if not _below(mount, path):
                raise ValueError(f"{field} ({path}) must lie below required_mount ({mount})")
        return self


class SnapshotRetention(MountGuard):
    """:class:`MountGuard` plus the retention of the snapshots a backup writes."""

    retain_count: int = Field(default=0, ge=0)
    retain_days: int = Field(default=0, ge=0)

    @property
    def retention(self) -> bool:
        return self.retain_count > 0 or self.retain_days > 0

    def cutoff(self, stamp: str) -> str:
        """The oldest timestamp ``retain_days`` keeps, from the host's ``stamp``; empty without an age limit."""

        if not self.retain_days:
            return ""
        return (datetime.strptime(stamp, STAMP_FORMAT) - timedelta(days=self.retain_days)).strftime(STAMP_FORMAT)


def _bash(*calls: str) -> str:
    return "\n".join(["set -euo pipefail", COMMON.read_text(), *calls]) + "\n"


def mount_check(mount: str, *paths: str) -> str:
    """bash: stop unless ``mount`` is mounted and every path resolves below it."""

    return _bash(shlex.join(["require_mount", mount, *paths]))


def backup_preflight(cfg: SnapshotRetention, root: str, name: str) -> str | None:
    """bash, before a backup's first write: the mount check and, under retention, a name not yet taken."""

    calls = []
    if cfg.required_mount:
        calls.append(shlex.join(["require_mount", cfg.required_mount, root]))
    if cfg.retention:
        calls.append(shlex.join(["require_new_snapshot", root, name]))
    return _bash(*calls) if calls else None


def retention(cfg: SnapshotRetention, root: str, name: str, stamp: str) -> str:
    """bash: record snapshot ``name`` below ``root`` and prune the recorded ones by ``cfg``'s limits."""

    return _bash(
        shlex.join(["record_snapshot", root, name]),
        shlex.join(["prune_snapshots", root, str(cfg.retain_count), cfg.cutoff(stamp), name]),
    )


__all__ = ["STAMP_FORMAT", "MountGuard", "SnapshotRetention", "backup_preflight", "mount_check", "retention"]
