"""SMART daemon configuration without deployment-time hardware queries."""

from .config import SmartdConfig, SmartdDevice
from .deploy import deploy_smartd

__all__ = ["SmartdConfig", "SmartdDevice", "deploy_smartd"]
