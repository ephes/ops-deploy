"""jellyfin: the Jellyfin media server (port of the jellyfin_deploy role, deploy and confirmed removal)."""

from ops_deploy.services.jellyfin.deploy import JellyfinConfig, deploy_jellyfin

__all__ = ["JellyfinConfig", "deploy_jellyfin"]

from .remove import JellyfinRemoveConfig, deploy_jellyfin_remove

__all__ += ["JellyfinRemoveConfig", "deploy_jellyfin_remove"]
