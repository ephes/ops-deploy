"""django_site: one deploy for the Django/Wagtail sites (gunicorn, SQLite, Traefik, an optional Next.js frontend).

Each site is a :class:`DjangoSiteConfig`; :func:`deploy_django_site` runs the
shared step sequence and writes the canonical file set
(``docs/services/django_site.md``).
"""

from ops_deploy.services.django_site.config import (
    AppSpec,
    BootstrapSuperuser,
    Checks,
    DjangoSiteConfig,
    EnsureSuperuser,
    EnvEntry,
    EnvLiteral,
    EnvSpec,
    Joined,
    LegacyGuard,
    LocalMedia,
    ManageStep,
    NextStandalone,
    PathSecrets,
    PostgresDb,
    Route,
    Secret,
    SourceSpec,
    SqliteDb,
    StepGroup,
    Steps,
    UrlCheck,
)
from ops_deploy.services.django_site.deploy import deploy_django_site

__all__ = [
    "AppSpec",
    "BootstrapSuperuser",
    "Checks",
    "DjangoSiteConfig",
    "EnsureSuperuser",
    "EnvEntry",
    "EnvLiteral",
    "EnvSpec",
    "Joined",
    "LegacyGuard",
    "LocalMedia",
    "ManageStep",
    "NextStandalone",
    "PathSecrets",
    "PostgresDb",
    "Route",
    "Secret",
    "SourceSpec",
    "SqliteDb",
    "StepGroup",
    "Steps",
    "UrlCheck",
    "deploy_django_site",
]
