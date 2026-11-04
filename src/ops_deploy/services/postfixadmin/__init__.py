"""PostfixAdmin ordinary deployment API, backup and restore (postfixadmin_deploy, _backup, _restore)."""

from pyinfra.api import deploy

from ops_deploy.core.secrets import SecretValues
from ops_deploy.services.postfixadmin.backup_restore import (
    PostfixAdminBackupConfig,
    PostfixAdminRestoreConfig,
    deploy_postfixadmin_backup,
    deploy_postfixadmin_restore,
)
from ops_deploy.services.postfixadmin.config import PostfixAdminConfig


@deploy("PostfixAdmin")
def deploy_postfixadmin(cfg: PostfixAdminConfig, secrets: SecretValues) -> None:
    from ops_deploy.services._mail_web.deploy import deploy as run

    run(cfg, secrets)


__all__ = [
    "PostfixAdminBackupConfig",
    "PostfixAdminConfig",
    "PostfixAdminRestoreConfig",
    "deploy_postfixadmin",
    "deploy_postfixadmin_backup",
    "deploy_postfixadmin_restore",
]
