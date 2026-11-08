"""Explicit retirement of unmanaged legacy accounts and services: archive first, then remove."""

from .retire import LegacyRetirementConfig, RetiredDatabase, retire_legacy

__all__ = ["LegacyRetirementConfig", "RetiredDatabase", "retire_legacy"]
