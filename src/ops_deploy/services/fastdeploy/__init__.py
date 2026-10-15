"""FastDeploy: deploy platform on PostgreSQL (port of the fastdeploy_deploy, _backup, _restore and _remove roles)."""

from ops_deploy.services.fastdeploy.deploy import FastdeployConfig, deploy_fastdeploy
from ops_deploy.services.fastdeploy.lifecycle import (
    FastdeployBackupConfig,
    FastdeployRemoveConfig,
    FastdeployRestoreConfig,
    deploy_fastdeploy_backup,
    deploy_fastdeploy_remove,
    deploy_fastdeploy_restore,
)

__all__ = [
    "FastdeployBackupConfig",
    "FastdeployConfig",
    "FastdeployRemoveConfig",
    "FastdeployRestoreConfig",
    "deploy_fastdeploy",
    "deploy_fastdeploy_backup",
    "deploy_fastdeploy_remove",
    "deploy_fastdeploy_restore",
]
