"""Prepared Paperless API; native qualification and inventory adoption pending."""

from .config import PaperlessConfig, PaperlessCredentials
from .deploy import deploy_paperless

__all__ = ["PaperlessConfig", "PaperlessCredentials", "deploy_paperless"]
