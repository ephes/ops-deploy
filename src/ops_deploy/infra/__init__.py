"""Shared host services ported from ops-library: PostgreSQL, Redis and Traefik.

Like :mod:`ops_deploy.base`, each module holds a typed config and a
``@deploy`` function; they are deploys, not shared helpers, so they sit
outside the size-capped helpers/ops/core layer. Secrets (database and Redis
passwords) are deploy arguments, never config fields.
"""

from ops_deploy.infra.postgres_install import (
    DatabaseSpec,
    ExtensionSpec,
    PgHbaRule,
    PostgresInstallConfig,
    deploy_postgres_install,
)
from ops_deploy.infra.redis_install import RedisInstallConfig, deploy_redis_install
from ops_deploy.infra.traefik_backup import (
    TraefikBackupConfig,
    TraefikRestoreConfig,
    deploy_traefik_backup,
    deploy_traefik_restore,
)
from ops_deploy.infra.traefik_deploy import FileCertificate, TraefikDeployConfig, deploy_traefik
from ops_deploy.infra.traefik_remove import TraefikRemoveConfig, deploy_traefik_remove

__all__ = [
    "DatabaseSpec",
    "ExtensionSpec",
    "FileCertificate",
    "PgHbaRule",
    "PostgresInstallConfig",
    "RedisInstallConfig",
    "TraefikBackupConfig",
    "TraefikDeployConfig",
    "TraefikRemoveConfig",
    "TraefikRestoreConfig",
    "deploy_postgres_install",
    "deploy_redis_install",
    "deploy_traefik",
    "deploy_traefik_backup",
    "deploy_traefik_remove",
    "deploy_traefik_restore",
]
