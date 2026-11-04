"""jellyfin: the Jellyfin media server (jellyfin_deploy port; backup, restore and confirmed removal)."""

from ops_deploy.services._lifecycle.media_lifecycle import (
    JellyfinBackupConfig,
    JellyfinRestoreConfig,
    deploy_jellyfin_backup,
    deploy_jellyfin_restore,
)
from ops_deploy.services.jellyfin.deploy import JellyfinConfig, deploy_jellyfin

from .remove import JellyfinRemoveConfig, deploy_jellyfin_remove

__all__ = [
    "JellyfinBackupConfig",
    "JellyfinConfig",
    "JellyfinRemoveConfig",
    "JellyfinRestoreConfig",
    "deploy_jellyfin",
    "deploy_jellyfin_backup",
    "deploy_jellyfin_remove",
    "deploy_jellyfin_restore",
]
