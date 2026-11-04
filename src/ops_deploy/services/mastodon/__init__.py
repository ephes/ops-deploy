"""Bounded existing-install Mastodon configuration convergence and the roles' removal, backup and restore."""

from ops_deploy.services.mastodon.backup_restore import (
    MastodonBackupConfig,
    MastodonRestoreConfig,
    deploy_mastodon_backup,
    deploy_mastodon_restore,
)
from ops_deploy.services.mastodon.candidate import describe_candidate
from ops_deploy.services.mastodon.config import MastodonConfig
from ops_deploy.services.mastodon.deploy import deploy_mastodon
from ops_deploy.services.mastodon.release_config import MastodonReleaseConfig
from ops_deploy.services.mastodon.remove import MastodonRemoveConfig, remove_mastodon

__all__ = [
    "MastodonBackupConfig",
    "MastodonConfig",
    "MastodonReleaseConfig",
    "MastodonRemoveConfig",
    "MastodonRestoreConfig",
    "deploy_mastodon",
    "deploy_mastodon_backup",
    "deploy_mastodon_restore",
    "describe_candidate",
    "remove_mastodon",
]
