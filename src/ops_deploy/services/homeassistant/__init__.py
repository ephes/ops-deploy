"""Home Assistant deployment, backup, restore and removal (ports of the homeassistant_* roles)."""

from .deploy import deploy_homeassistant as deploy_homeassistant
from .deploy_config import HomeAssistantDeployConfig as HomeAssistantDeployConfig
from .lifecycle import HomeAssistantBackupConfig as HomeAssistantBackupConfig
from .lifecycle import HomeAssistantRestoreConfig as HomeAssistantRestoreConfig
from .lifecycle import deploy_homeassistant_backup as deploy_homeassistant_backup
from .lifecycle import deploy_homeassistant_restore as deploy_homeassistant_restore
from .remove import HomeAssistantRemoveConfig as HomeAssistantRemoveConfig
from .remove import remove_homeassistant as remove_homeassistant

__all__ = [
    "HomeAssistantBackupConfig",
    "HomeAssistantDeployConfig",
    "HomeAssistantRemoveConfig",
    "HomeAssistantRestoreConfig",
    "deploy_homeassistant",
    "deploy_homeassistant_backup",
    "deploy_homeassistant_restore",
    "remove_homeassistant",
]
