"""vaultwarden: the password manager from its vendor's .deb packages (port of vaultwarden_deploy)."""

from ops_deploy.services.vaultwarden.deploy import (
    VaultwardenConfig,
    deploy_vaultwarden,
    render_dropin,
    render_env,
    render_route,
)

__all__ = [
    "VaultwardenConfig",
    "deploy_vaultwarden",
    "render_dropin",
    "render_env",
    "render_route",
]
