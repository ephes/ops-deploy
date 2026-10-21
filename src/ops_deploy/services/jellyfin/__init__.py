"""jellyfin: the Jellyfin media server (port of the jellyfin_deploy role, deploy only)."""

from ops_deploy.services.jellyfin.deploy import JellyfinConfig, deploy_jellyfin

__all__ = ["JellyfinConfig", "deploy_jellyfin"]
