"""Explicit fresh-apply-bound Weeknotes schedule activation."""

from .config import WeeknotesActivationConfig
from .deploy import activate_weeknotes_schedule

__all__ = ["WeeknotesActivationConfig", "activate_weeknotes_schedule"]
