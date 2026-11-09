"""os_apt_maintenance: host-local apt maintenance timers, the state endpoint and their Nyxmon checks."""

from ops_deploy.services.os_apt_maintenance.deploy import (
    NyxmonTarget,
    OsAptMaintenanceConfig,
    OsAptNyxmonConfig,
    deploy_os_apt_maintenance,
    deploy_os_apt_maintenance_nyxmon,
)

__all__ = [
    "NyxmonTarget",
    "OsAptMaintenanceConfig",
    "OsAptNyxmonConfig",
    "deploy_os_apt_maintenance",
    "deploy_os_apt_maintenance_nyxmon",
]
