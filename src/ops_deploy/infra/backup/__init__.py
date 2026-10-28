"""Typed original configuration for scheduled replication; no deploy starts a backup."""

from .archive import deploy_minio_archive
from .config import (
    MailReplicationConfig,
    MinioArchiveConfig,
    SnapshotRetention,
    SyncoidConfig,
    SyncoidJob,
    UsbDrive,
    UsbReplicationConfig,
)
from .mail import deploy_mail_replication
from .source import (
    BackupRestoreAccessConfig,
    BackupSourceConfig,
    deploy_backup_restore_access,
    deploy_backup_restore_client,
    deploy_backup_source,
)
from .syncoid import deploy_syncoid
from .usb import deploy_usb_replication

__all__ = [
    "BackupRestoreAccessConfig",
    "BackupSourceConfig",
    "MailReplicationConfig",
    "MinioArchiveConfig",
    "SnapshotRetention",
    "SyncoidConfig",
    "SyncoidJob",
    "UsbDrive",
    "UsbReplicationConfig",
    "deploy_backup_restore_access",
    "deploy_backup_restore_client",
    "deploy_backup_source",
    "deploy_mail_replication",
    "deploy_minio_archive",
    "deploy_syncoid",
    "deploy_usb_replication",
]
