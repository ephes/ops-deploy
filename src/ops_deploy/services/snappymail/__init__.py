"""SnappyMail deployment, backup, restore and removal (snappymail_deploy, _backup, _restore, _remove)."""

from pyinfra.api import deploy

from ops_deploy.core.secrets import SecretValues
from ops_deploy.services.snappymail.backup_restore import (
    SnappyMailBackupConfig,
    SnappyMailRestoreConfig,
    deploy_snappymail_backup,
    deploy_snappymail_restore,
)
from ops_deploy.services.snappymail.config import SnappyMailConfig
from ops_deploy.services.snappymail.remove import SnappyMailRemoveConfig, remove_snappymail


@deploy("SnappyMail")
def deploy_snappymail(cfg: SnappyMailConfig, secrets: SecretValues) -> None:
    from ops_deploy.services._mail_web.deploy import deploy as run

    run(cfg, secrets)


__all__ = [
    "SnappyMailBackupConfig",
    "SnappyMailConfig",
    "SnappyMailRemoveConfig",
    "SnappyMailRestoreConfig",
    "deploy_snappymail",
    "deploy_snappymail_backup",
    "deploy_snappymail_restore",
    "remove_snappymail",
]
