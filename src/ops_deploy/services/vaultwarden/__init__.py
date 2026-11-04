"""vaultwarden from its vendor's .deb packages (ports of vaultwarden_deploy, _backup, _restore, _remove)."""

from ops_deploy.services.vaultwarden.backup_restore import (
    VaultwardenBackupConfig,
    VaultwardenRestoreConfig,
    deploy_vaultwarden_backup,
    deploy_vaultwarden_restore,
)
from ops_deploy.services.vaultwarden.deploy import (
    VaultwardenConfig,
    deploy_vaultwarden,
    render_dropin,
    render_env,
    render_route,
)
from ops_deploy.services.vaultwarden.remove import VaultwardenRemoveConfig, remove_vaultwarden

__all__ = [
    "VaultwardenBackupConfig",
    "VaultwardenConfig",
    "VaultwardenRemoveConfig",
    "VaultwardenRestoreConfig",
    "deploy_vaultwarden",
    "deploy_vaultwarden_backup",
    "deploy_vaultwarden_restore",
    "remove_vaultwarden",
    "render_dropin",
    "render_env",
    "render_route",
]
