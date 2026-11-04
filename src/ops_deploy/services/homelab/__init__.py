"""homelab: the home dashboard (ports of the homelab_deploy and homelab_remove roles)."""

from ops_deploy.services.homelab.deploy import HomelabConfig, deploy_homelab
from ops_deploy.services.homelab.remove import HomelabRemoveConfig, remove_homelab

__all__ = ["HomelabConfig", "HomelabRemoveConfig", "deploy_homelab", "remove_homelab"]
