"""homelab: the home dashboard (ports of homelab_deploy, homelab_backup, homelab_restore and homelab_remove)."""

from ops_deploy.services.homelab.backup_restore import (
    HomelabBackupConfig,
    HomelabRestoreConfig,
    deploy_homelab_backup,
    deploy_homelab_restore,
)
from ops_deploy.services.homelab.deploy import HomelabConfig, deploy_homelab
from ops_deploy.services.homelab.remove import HomelabRemoveConfig, remove_homelab

__all__ = [
    "HomelabBackupConfig",
    "HomelabConfig",
    "HomelabRemoveConfig",
    "HomelabRestoreConfig",
    "deploy_homelab",
    "deploy_homelab_backup",
    "deploy_homelab_restore",
    "remove_homelab",
]
