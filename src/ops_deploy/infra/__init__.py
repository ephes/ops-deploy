"""Shared host services ported from ops-library: PostgreSQL and Redis.

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

__all__ = [
    "DatabaseSpec",
    "ExtensionSpec",
    "PgHbaRule",
    "PostgresInstallConfig",
    "RedisInstallConfig",
    "deploy_postgres_install",
    "deploy_redis_install",
]
