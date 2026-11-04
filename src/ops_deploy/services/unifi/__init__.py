"""Deploy an initialized UniFi controller (fresh database bootstrap is separate) and the role's removal."""

from .config import UnifiConfig, UnifiRoutine
from .deploy import deploy_unifi
from .remove import UnifiRemoveConfig, remove_unifi

__all__ = ["UnifiConfig", "UnifiRemoveConfig", "UnifiRoutine", "deploy_unifi", "remove_unifi"]
