"""Typed Tailscale core deployment and selected native preferences."""

from .config import TailscaleConfig
from .deploy import deploy_tailscale
from .lifecycle import deploy_tailscale_backup, deploy_tailscale_manual_restore, deploy_tailscale_remove
from .lifecycle_config import TailscaleBackupConfig, TailscaleManualRestoreConfig, TailscaleRemoveConfig
from .metrics import deploy_tailscale_metrics
from .metrics_config import TailscaleMetricsConfig
from .nyxmon import TailscaleNyxmonConfig, TailscaleNyxmonTarget, deploy_tailscale_nyxmon

__all__ = [
    "TailscaleBackupConfig",
    "TailscaleConfig",
    "TailscaleManualRestoreConfig",
    "TailscaleMetricsConfig",
    "TailscaleNyxmonConfig",
    "TailscaleNyxmonTarget",
    "TailscaleRemoveConfig",
    "deploy_tailscale",
    "deploy_tailscale_backup",
    "deploy_tailscale_manual_restore",
    "deploy_tailscale_metrics",
    "deploy_tailscale_nyxmon",
    "deploy_tailscale_remove",
]
