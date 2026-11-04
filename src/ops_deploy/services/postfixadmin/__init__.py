"""PostfixAdmin deployment, backup, restore and removal (postfixadmin_deploy, _backup, _restore, _remove)."""

from pyinfra.api import deploy

from ops_deploy.core.secrets import SecretValues
from ops_deploy.services.postfixadmin.backup_restore import (
    PostfixAdminBackupConfig,
    PostfixAdminRestoreConfig,
    deploy_postfixadmin_backup,
    deploy_postfixadmin_restore,
)
from ops_deploy.services.postfixadmin.config import PostfixAdminConfig
from ops_deploy.services.postfixadmin.remove import PostfixAdminRemoveConfig, remove_postfixadmin


@deploy("PostfixAdmin")
def deploy_postfixadmin(cfg: PostfixAdminConfig, secrets: SecretValues) -> None:
    from ops_deploy.services._mail_web.deploy import deploy as run

    run(cfg, secrets)


__all__ = [
    "PostfixAdminBackupConfig",
    "PostfixAdminConfig",
    "PostfixAdminRemoveConfig",
    "PostfixAdminRestoreConfig",
    "deploy_postfixadmin",
    "deploy_postfixadmin_backup",
    "deploy_postfixadmin_restore",
    "remove_postfixadmin",
]
