"""Navidrome confirmed removal, backup and guarded recovery restore."""

from ops_deploy.services._lifecycle.media_lifecycle import (
    NavidromeBackupConfig,
    NavidromeRestoreConfig,
    deploy_navidrome_backup,
    deploy_navidrome_restore,
)

from .remove import NavidromeRemoveConfig, deploy_navidrome_remove

__all__ = [
    "NavidromeBackupConfig",
    "NavidromeRemoveConfig",
    "NavidromeRestoreConfig",
    "deploy_navidrome_backup",
    "deploy_navidrome_remove",
    "deploy_navidrome_restore",
]
