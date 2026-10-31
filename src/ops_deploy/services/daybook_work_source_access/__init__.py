"""The original dedicated read-only Obsidian work-source identity."""

from .config import DaybookWorkSourceAccessConfig, DaybookWorkSourceCredentials
from .deploy import install_daybook_work_source_access

__all__ = [
    "DaybookWorkSourceAccessConfig",
    "DaybookWorkSourceCredentials",
    "install_daybook_work_source_access",
]
