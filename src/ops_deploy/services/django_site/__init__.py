"""django_site: one deploy for the Django/Wagtail sites (gunicorn, SQLite, Traefik).

Each site is a :class:`DjangoSiteConfig`; :func:`deploy_django_site` runs the
shared step sequence and writes the canonical file set
(``docs/services/django_site.md``).
"""

from ops_deploy.services.django_site.config import (
    AppSpec,
    Checks,
    DjangoSiteConfig,
    EnsureSuperuser,
    EnvEntry,
    EnvSpec,
    LocalMedia,
    ManageStep,
    Route,
    Secret,
    SourceSpec,
    SqliteDb,
    StepGroup,
    Steps,
)
from ops_deploy.services.django_site.deploy import deploy_django_site

__all__ = [
    "AppSpec",
    "Checks",
    "DjangoSiteConfig",
    "EnsureSuperuser",
    "EnvEntry",
    "EnvSpec",
    "LocalMedia",
    "ManageStep",
    "Route",
    "Secret",
    "SourceSpec",
    "SqliteDb",
    "StepGroup",
    "Steps",
    "deploy_django_site",
]
