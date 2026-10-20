"""homelab: the home dashboard (port of the homelab_deploy role, deploy only)."""

from ops_deploy.services.homelab.deploy import HomelabConfig, deploy_homelab

__all__ = ["HomelabConfig", "deploy_homelab"]
