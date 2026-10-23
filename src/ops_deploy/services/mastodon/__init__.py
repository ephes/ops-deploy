"""Bounded existing-install Mastodon configuration convergence (deploy only)."""

from ops_deploy.services.mastodon.config import MastodonConfig
from ops_deploy.services.mastodon.deploy import deploy_mastodon

__all__ = ["MastodonConfig", "deploy_mastodon"]
