"""Thermal monitoring: exporter, cached authenticated endpoint, Nyxmon freshness check (port of two roles),
and optional drive-aware case-fan control."""

from ops_deploy.services._nyxmon_json_metrics import JsonMetricsCheck
from ops_deploy.services.thermal_monitoring.deploy import (
    PASSWORD_KEY,
    IpmiSensor,
    LmSensor,
    SysfsSensor,
    ThermalCheckConfig,
    ThermalExporter,
    ThermalMonitoringConfig,
    deploy_thermal_check,
    deploy_thermal_monitoring,
)
from ops_deploy.services.thermal_monitoring.fan_control import (
    METRICS as FAN_CONTROL_METRICS,
)
from ops_deploy.services.thermal_monitoring.fan_control import (
    METRICS_DIR as FAN_CONTROL_METRICS_DIR,
)
from ops_deploy.services.thermal_monitoring.fan_control import (
    Board,
    Calibration,
    Curves,
    FanControl,
    FanPosition,
    HddDrive,
    HwmonSensor,
    NvmeDrive,
    ScanPool,
)

__all__ = [
    "FAN_CONTROL_METRICS",
    "FAN_CONTROL_METRICS_DIR",
    "PASSWORD_KEY",
    "Board",
    "Calibration",
    "Curves",
    "FanControl",
    "FanPosition",
    "HddDrive",
    "HwmonSensor",
    "IpmiSensor",
    "JsonMetricsCheck",
    "LmSensor",
    "NvmeDrive",
    "ScanPool",
    "SysfsSensor",
    "ThermalCheckConfig",
    "ThermalExporter",
    "ThermalMonitoringConfig",
    "deploy_thermal_check",
    "deploy_thermal_monitoring",
]
