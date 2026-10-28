"""ZFS event daemon and timer policy, with no deployment-time scrub."""

from .config import ZedConfig
from .deploy import deploy_zed

__all__ = ["ZedConfig", "deploy_zed"]
