"""Explicit original Weeknotes identity rail; no implicit install or activation."""

from .config import IdentityMove, WeeknotesIdentityConfig
from .deploy import run_weeknotes_identity

__all__ = ["IdentityMove", "WeeknotesIdentityConfig", "run_weeknotes_identity"]
