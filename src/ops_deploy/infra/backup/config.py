"""Original scheduled backup policies; deploy only configures, never runs a job."""

from __future__ import annotations

import re
from typing import Annotated, Any, Literal

from pydantic import Field, StrictBool, model_validator

from ops_deploy.base._common import AbsolutePath, RoleConfig
from ops_deploy.infra.zfs_storage.config import DatasetName, Identity, PoolName, UnitName, canonical

DevicePath = Annotated[str, Field(pattern=r"^/dev/[A-Za-z0-9._/:+-]+$")]
Mode = Annotated[str, Field(pattern=r"^0?[0-7]{3}$")]
SafeName = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")]
Hostname = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")]


def literal_values(value: Any) -> None:
    """These original templates place literals inside shell/systemd syntax."""
    if isinstance(value, str) and any(ord(c) < 32 or ord(c) == 127 or c in '$`"\\;|&<>' for c in value):
        raise ValueError("backup template inputs must be literal, single-line operational values")
    if isinstance(value, dict):
        for item in value.values():
            literal_values(item)
    elif isinstance(value, (tuple, list)):
        for item in value:
            literal_values(item)


class BackupConfig(RoleConfig):
    enabled: bool = True
    packages: tuple[str, ...] = ("sanoid",)
    service_name: UnitName
    timer_name: UnitName
    on_calendar: str
    randomized_delay_sec: str
    timeout_sec: str
    alert_enabled: bool = True
    alert_email: str = "root"
    alert_subject_prefix: str
    alert_script_path: AbsolutePath
    spindown_enabled: bool
    spindown_pool: PoolName | Literal[""] = ""
    spindown_devices: tuple[DevicePath, ...] = ()
    spindown_script_path: AbsolutePath | Literal[""]

    @model_validator(mode="after")
    def _literal(self) -> BackupConfig:
        literal_values(self.model_dump())
        for name, item in self.model_dump().items():
            if isinstance(item, str) and item.startswith("/"):
                canonical(item)
            if name in {"on_calendar", "randomized_delay_sec", "timeout_sec"} and not item:
                raise ValueError("original timer policy fields must be nonempty")
        if self.enabled and self.alert_enabled and (not self.alert_email or self.alert_email == "CHANGE_ME"):
            raise ValueError("enabled original alert policy requires a recipient")
        if any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9+.:~-]*", p) for p in self.packages):
            raise ValueError("invalid package prerequisite")
        return self


class SyncoidJob(RoleConfig):
    source: DatasetName
    target: DatasetName
    recursive: StrictBool = False
    readonly: StrictBool = False
    force_delete: StrictBool = False
    no_rollback: StrictBool | None = None
    prune_conflicting_snapshots: StrictBool = False
    prune_target_only_snapshots: StrictBool = False
    abort_partial_receive: StrictBool = False
    extra_args: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _arguments(self) -> SyncoidJob:
        if self.source == self.target:
            raise ValueError("replication source and target must differ")
        for item in self.extra_args:
            if not re.fullmatch(r"--[A-Za-z0-9][A-Za-z0-9_./:=,+-]*", item):
                raise ValueError("syncoid extra_args must be literal option tokens")
        return self


class SyncoidConfig(BackupConfig):
    service_name: UnitName = "zfs-syncoid-replication"
    timer_name: UnitName = "zfs-syncoid-replication"
    on_calendar: str = "02:00"
    randomized_delay_sec: str = "10m"
    timeout_sec: str = "6h"
    syncoid_path: AbsolutePath = "/usr/sbin/syncoid"
    default_args: tuple[str, ...] = ("--no-rollback",)
    jobs: tuple[SyncoidJob, ...] = ()
    alert_subject_prefix: str = "[zfs-syncoid]"
    alert_script_path: AbsolutePath = "/usr/local/bin/zfs-syncoid-alert.sh"
    spindown_enabled: bool = True
    spindown_script_path: AbsolutePath = "/usr/local/bin/zfs-syncoid-spindown.sh"
    spindown_retries: int = Field(default=10, ge=1)
    spindown_sleep_sec: int = Field(default=60, ge=0)
    prune_script_path: AbsolutePath = "/usr/local/bin/zfs-syncoid-prune-conflicts.sh"
    abort_partial_receive_script_path: AbsolutePath = "/usr/local/bin/zfs-syncoid-abort-partial-receive.sh"

    @model_validator(mode="after")
    def _jobs(self) -> SyncoidConfig:
        if self.enabled and not self.jobs:
            raise ValueError("enabled original syncoid policy requires jobs")
        SyncoidJob(source="validation/source", target="validation/target", extra_args=self.default_args)
        return self


class UsbDrive(RoleConfig):
    name: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9_-]*$")]
    device: Annotated[str, Field(pattern=r"^/dev/disk/by-id/[^/\s]+$")]
    pool_guid: Annotated[str, Field(pattern=r"^[0-9]+$")] | None = None


class SnapshotRetention(RoleConfig):
    source: DatasetName
    target: DatasetName
    keep_days: int = Field(ge=1)
    prefixes: tuple[SafeName, ...] = Field(min_length=1)


class UsbReplicationConfig(BackupConfig):
    service_name: UnitName = "zfs-usb-replication"
    timer_name: UnitName = "zfs-usb-replication"
    on_calendar: str = "Sun 04:00"
    randomized_delay_sec: str = "30m"
    timeout_sec: str = "8h"
    syncoid_path: AbsolutePath = "/usr/sbin/syncoid"
    state_dir: AbsolutePath = "/var/lib/zfs-usb-replication"
    state_path: AbsolutePath | None = None
    state_writer_path: AbsolutePath = "/usr/local/bin/zfs_usb_replication_state.py"
    attestation_dir: AbsolutePath | None = None
    attestation_helper_path: AbsolutePath = "/usr/local/sbin/zfs-snapshot-file-attestation"
    snapshot_retention: tuple[SnapshotRetention, ...] = ()
    retention_script_path: AbsolutePath = "/usr/local/bin/zfs_usb_snapshot_retention.py"
    wait_for_async_destroy: bool = True
    device: AbsolutePath | Literal[""] = ""
    pool: PoolName | Literal[""] = ""
    devices: tuple[UsbDrive, ...] = ()
    anchor_mode: Literal["sync_snapshot", "bookmark"] = "sync_snapshot"
    anchor_helper_path: AbsolutePath = "/usr/local/bin/zfs_usb_bookmark_anchors.py"
    anchor_state_path: AbsolutePath | None = None
    bookmark_prune: bool = True
    bookmark_prune_prefixes: tuple[SafeName, ...] = ("autosnap_", "syncoid_")
    identifier: Annotated[str, Field(pattern=r"^[a-zA-Z0-9_-]*$")] = ""
    force_export: bool = False
    exportfs_lock_dir: AbsolutePath = "/etc/exports.d"
    set_canmount_off_for_readonly_recursive_targets: bool = True
    key_manage: bool = True
    key_path: AbsolutePath = "/root/.zfs-key-vault"
    default_args: tuple[str, ...] = ("--no-rollback",)
    abort_partial_receive_script_path: AbsolutePath = "/usr/local/bin/zfs-syncoid-abort-partial-receive.sh"
    jobs: tuple[SyncoidJob, ...] = ()
    alert_subject_prefix: str = "[zfs-usb]"
    alert_script_path: AbsolutePath = "/usr/local/bin/zfs-usb-alert.sh"
    spindown_enabled: bool = False
    spindown_script_path: AbsolutePath = "/usr/local/bin/zfs-usb-spindown.sh"

    @model_validator(mode="after")
    def _rotation(self) -> UsbReplicationConfig:
        if not self.enabled:
            return self
        if not self.jobs or not self.pool or self.pool == "CHANGE_ME":
            raise ValueError("original USB policy requires pool and jobs")
        if not self.devices and (not self.device or self.anchor_mode == "bookmark"):
            raise ValueError("single USB device required; bookmark mode requires named drives")
        if len({d.name for d in self.devices}) != len(self.devices) or len({d.device for d in self.devices}) != len(
            self.devices
        ):
            raise ValueError("USB rotation names/devices must be unique")
        if len(self.devices) > 1 and self.anchor_mode != "bookmark":
            raise ValueError("multiple USB drives require original bookmark anchors")
        if self.bookmark_prune and not self.bookmark_prune_prefixes:
            raise ValueError("bookmark pruning requires original managed prefixes")
        if self.spindown_enabled and (not self.spindown_devices or not self.spindown_pool):
            raise ValueError("enabled USB spindown requires declared pool/devices")
        SyncoidJob(source="validation/source", target="validation/target", extra_args=self.default_args)
        return self


class OffsiteConfig(BackupConfig):
    packages: tuple[str, ...] = ("rsync", "openssh-client")
    source_host: Hostname | Literal[""] = ""
    source_user: Identity = "root"
    ssh_key_manage: bool = True
    ssh_key_path: AbsolutePath
    ssh_known_hosts_path: AbsolutePath = "/root/.ssh/known_hosts"
    ssh_connect_timeout: int = Field(default=30, ge=1)
    manage_known_hosts: bool = True
    ssh_keyscan_type: Literal["ed25519", "rsa", "ecdsa"] = "ed25519"
    destination_path: AbsolutePath
    destination_owner: Identity = "root"
    destination_group: Identity = "root"
    destination_mode: Mode = "0750"
    status_dir: AbsolutePath
    status_file: AbsolutePath | None = None
    status_owner: Identity = "root"
    status_group: Identity = "root"
    status_mode: Mode = "0750"
    latest_marker_file: AbsolutePath | None = None
    script_path: AbsolutePath
    spindown_enabled: bool = False
    spindown_script_path: AbsolutePath | Literal[""] = ""

    @model_validator(mode="after")
    def _offsite(self) -> OffsiteConfig:
        if self.enabled and (
            not self.source_host
            or self.source_host == "CHANGE_ME"
            or (self.spindown_enabled and not self.spindown_script_path)
        ):
            raise ValueError("original offsite source and optional spindown path must be configured")
        return self


class MinioArchiveConfig(OffsiteConfig):
    service_name: UnitName = "minio-offsite-replication"
    timer_name: UnitName = "minio-offsite-replication"
    on_calendar: str = "05:00"
    randomized_delay_sec: str = "15m"
    timeout_sec: str = "4h"
    source_path: AbsolutePath = "/opt/backups/minio"
    ssh_key_path: AbsolutePath = "/root/.ssh/minio-offsite-replication-ed25519"
    destination_path: AbsolutePath = "/tank/backups/minio"
    status_dir: AbsolutePath = "/var/lib/minio-offsite-replication"
    archive_patterns: tuple[str, ...] = ("*.tar.gz", "*.tar.zst")
    rsync_extra_args: tuple[str, ...] = ("--archive", "--hard-links", "--numeric-ids", "--partial-dir=.rsync-partial")
    rsync_delete: bool = False
    require_archives: bool = False
    alert_subject_prefix: str = "[minio-offsite]"
    alert_script_path: AbsolutePath = "/usr/local/bin/minio-offsite-alert.sh"
    script_path: AbsolutePath = "/usr/local/bin/minio-offsite-replication.sh"

    @model_validator(mode="after")
    def _patterns(self) -> MinioArchiveConfig:
        if self.enabled and (not self.archive_patterns or any(not p.strip() for p in self.archive_patterns)):
            raise ValueError("original archive selection requires nonempty literal patterns")
        return self


class MailReplicationConfig(OffsiteConfig):
    service_name: UnitName = "mail-offsite-replication"
    timer_name: UnitName = "mail-offsite-replication"
    on_calendar: str = "04:00"
    randomized_delay_sec: str = "15m"
    timeout_sec: str = "4h"
    source_vmail_path: AbsolutePath = "/mnt/cryptdata/vmail"
    source_stage_path: AbsolutePath = "/mnt/cryptdata/mail-backup-stage"
    source_stage_command: AbsolutePath = "/usr/local/sbin/mail-backup-stage.sh"
    ssh_key_path: AbsolutePath = "/root/.ssh/mail-offsite-replication-ed25519"
    destination_path: AbsolutePath = "/tank/backups/mail"
    destination_vmail_subdir: SafeName = "vmail"
    destination_stage_subdir: SafeName = "stage"
    status_dir: AbsolutePath = "/var/lib/mail-offsite-replication"
    vmail_rsync_extra_args: tuple[str, ...] = (
        "--archive",
        "--hard-links",
        "--numeric-ids",
        "--partial-dir=.rsync-partial",
        "--delete",
    )
    stage_rsync_extra_args: tuple[str, ...] = ("--archive", "--numeric-ids")
    snapshot_enabled: bool = True
    snapshot_dataset: DatasetName = "tank/backups/mail"
    snapshot_prefix: SafeName = "mail-sync"
    snapshot_keep: int = Field(default=30, ge=1)
    alert_subject_prefix: str = "[mail-offsite]"
    alert_script_path: AbsolutePath = "/usr/local/bin/mail-offsite-alert.sh"
    script_path: AbsolutePath = "/usr/local/bin/mail-offsite-replication.sh"
