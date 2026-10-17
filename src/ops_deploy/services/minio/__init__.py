"""minio: the MinIO object store (``minio_deploy``) and its scoped backup accounts."""

from ops_deploy.services.minio.deploy import (
    BackupAccount,
    Bucket,
    MinioConfig,
    RunnerAlias,
    backup_account,
    deploy_backup_account,
    deploy_minio,
)

__all__ = [
    "BackupAccount",
    "Bucket",
    "MinioConfig",
    "RunnerAlias",
    "backup_account",
    "deploy_backup_account",
    "deploy_minio",
]
