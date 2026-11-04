"""Bounded existing-install Mastodon configuration convergence and the role's removal."""

from ops_deploy.services.mastodon.candidate import describe_candidate
from ops_deploy.services.mastodon.config import MastodonConfig
from ops_deploy.services.mastodon.deploy import deploy_mastodon
from ops_deploy.services.mastodon.release_config import MastodonReleaseConfig
from ops_deploy.services.mastodon.remove import MastodonRemoveConfig, remove_mastodon

__all__ = [
    "MastodonConfig",
    "MastodonReleaseConfig",
    "MastodonRemoveConfig",
    "deploy_mastodon",
    "describe_candidate",
    "remove_mastodon",
]
