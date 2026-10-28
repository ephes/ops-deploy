"""Explicit original identity backup, LAN/manual restore and removal inputs."""

from __future__ import annotations

from pathlib import Path, PurePosixPath

from pydantic import Field, model_validator

from ops_deploy.base._common import AbsolutePath, RoleConfig
from ops_deploy.infra.netplan.config import Hostname, UnitName
from ops_deploy.infra.postgres_install import PackageName, RepoWord


class TailscalePaths(RoleConfig):
    state_dir: AbsolutePath = "/var/lib/tailscale"
    sysconfig_path: AbsolutePath = "/etc/default/tailscaled"
    systemd_dropin_dir: AbsolutePath = "/etc/systemd/system/tailscaled.service.d"
    service_name: UnitName = "tailscaled"

    @model_validator(mode="after")
    def _paths(self) -> TailscalePaths:
        paths = [self.state_dir, self.sysconfig_path, self.systemd_dropin_dir]
        if any(path == "/" or ".." in path.split("/") for path in paths):
            raise ValueError("identity lifecycle paths must be explicit nonroot paths without traversal")
        if any(PurePosixPath(a).is_relative_to(b) for a in paths for b in paths if a != b) or len(set(paths)) != len(
            paths
        ):
            raise ValueError("identity lifecycle paths must be disjoint")
        return self


class TailscaleBackupConfig(TailscalePaths):
    root: AbsolutePath = "/opt/backups/tailscale"
    prefix: str = Field(default="manual", pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    include_sysconfig: bool = True
    include_dropins: bool = True
    create_archive: bool = True
    fetch_local: bool = True
    local_dir: Path = Field(default_factory=lambda: Path.home() / "backups/tailscale")
    owner: str = Field(default="root", pattern=r"^[a-z_][a-z0-9_-]*$")
    group: str = Field(default="root", pattern=r"^[a-z_][a-z0-9_-]*$")

    @model_validator(mode="after")
    def _backup(self) -> TailscaleBackupConfig:
        if (
            self.root == "/"
            or ".." in self.root.split("/")
            or not self.local_dir.is_absolute()
            or ".." in self.local_dir.parts
        ):
            raise ValueError("backup destinations must be explicit absolute paths without traversal")
        if PurePosixPath(self.root).is_relative_to(self.state_dir) or PurePosixPath(self.state_dir).is_relative_to(
            self.root
        ):
            raise ValueError("backup root must not overlap live state")
        if self.fetch_local and not self.create_archive:
            raise ValueError("fetch requires an actual archive")
        return self


class TailscaleManualRestoreConfig(TailscalePaths):
    inventory_name: Hostname
    root: AbsolutePath = "/opt/backups/tailscale"
    archive: str = "latest"
    staging_dir: AbsolutePath = "/tmp/tailscale-restore"
    include_dropins: bool = True
    cleanup: bool = True
    restart_service: bool = True
    force_reup: bool = True
    dry_run: bool = False

    @model_validator(mode="after")
    def _restore(self) -> TailscaleManualRestoreConfig:
        if not self.archive or any(ord(c) < 32 for c in self.archive) or ".." in self.archive.split("/"):
            raise ValueError("restore archive must be latest or an explicit safe archive path")
        for path in (self.root, self.staging_dir):
            if path == "/" or ".." in path.split("/"):
                raise ValueError("restore roots must be explicit nonroot paths")
            if PurePosixPath(path).is_relative_to(self.state_dir) or PurePosixPath(self.state_dir).is_relative_to(path):
                raise ValueError("restore staging/archive roots must not overlap live state")
        return self


class TailscaleRemoveConfig(TailscalePaths):
    confirm: bool = False
    skip_logout: bool = False
    purge_state: bool = False
    binary: AbsolutePath = "/usr/bin/tailscale"
    package_name: PackageName = "tailscale"
    repo_name: RepoWord = "tailscale"
    repo_keyring: AbsolutePath = "/usr/share/keyrings/tailscale-archive-keyring.gpg"

    @model_validator(mode="after")
    def _remove_paths(self) -> TailscaleRemoveConfig:
        if any(path == "/" or ".." in path.split("/") for path in (self.binary, self.repo_keyring)):
            raise ValueError("removal paths must be explicit nonroot files without traversal")
        return self
