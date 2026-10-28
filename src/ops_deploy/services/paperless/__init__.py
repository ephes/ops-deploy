"""Prepared Paperless API; native qualification and inventory adoption pending."""

from .config import PaperlessConfig, PaperlessCredentials, PaperlessUvConfig
from .deploy import deploy_paperless

__all__ = ["PaperlessConfig", "PaperlessCredentials", "PaperlessUvConfig", "deploy_paperless"]
