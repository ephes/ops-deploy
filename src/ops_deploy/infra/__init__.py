"""Shared host services ported from ops-library: PostgreSQL, Redis, Traefik, Docker, Vector and certbot.

Like :mod:`ops_deploy.base`, each module holds a typed config and a
``@deploy`` function; they are deploys, not shared helpers, so they sit
outside the size-capped helpers/ops/core layer. Secrets (database and Redis
passwords) are deploy arguments, never config fields.
"""

from ops_deploy.infra.certbot_dns import CertbotDnsConfig, deploy_certbot_dns
from ops_deploy.infra.docker_install import DockerInstallConfig, deploy_docker_install, docker_steps
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
from ops_deploy.infra.vector_apt_install import VectorAptInstallConfig, deploy_vector_apt_install, vector_apt_steps

__all__ = [
    "CertbotDnsConfig",
    "DatabaseSpec",
    "DockerInstallConfig",
    "ExtensionSpec",
    "FileCertificate",
    "PgHbaRule",
    "PostgresInstallConfig",
    "RedisInstallConfig",
    "TraefikBackupConfig",
    "TraefikDeployConfig",
    "TraefikRemoveConfig",
    "TraefikRestoreConfig",
    "VectorAptInstallConfig",
    "deploy_certbot_dns",
    "deploy_docker_install",
    "deploy_postgres_install",
    "deploy_redis_install",
    "deploy_traefik",
    "deploy_traefik_backup",
    "deploy_traefik_remove",
    "deploy_traefik_restore",
    "deploy_vector_apt_install",
    "docker_steps",
    "vector_apt_steps",
]
