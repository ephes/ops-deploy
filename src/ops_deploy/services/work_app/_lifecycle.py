"""Paths and names shared by the work_app backup, restore and remove deploys.

They take no secrets, so they build on :class:`~ops_deploy.base._common.RoleConfig`
and default to the ``work_app_shared`` role defaults. Pass the same paths the
deploy used.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import Field

from ops_deploy.base._common import AbsolutePath, RoleConfig
from ops_deploy.core.config import SERVICE_NAME_PATTERN, UNIX_USER_PATTERN

SLUG = "work_app"
Name = Annotated[str, Field(pattern=SERVICE_NAME_PATTERN)]
User = Annotated[str, Field(pattern=UNIX_USER_PATTERN)]


class WorkAppPaths(RoleConfig):
    user: User = "work"
    group: User = "work"
    home: AbsolutePath = "/home/work"
    site_path: AbsolutePath = "/home/work/site"
    database_path: AbsolutePath = "/home/work/site/db.sqlite3"
    service_name: Name = "work-app"
    traefik_config_path: AbsolutePath = "/etc/traefik/dynamic/work-app.yml"
    django_settings_module: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.]+$")] = "config.settings.production"

    @property
    def static_root(self) -> str:
        return f"{self.site_path}/staticfiles"

    @property
    def env_file(self) -> str:
        return f"{self.site_path}/.env"

    @property
    def venv_python(self) -> str:
        return f"{self.site_path}/.venv/bin/python"

    @property
    def unit(self) -> str:
        return f"{self.service_name}.service"

    @property
    def unit_path(self) -> str:
        return f"/etc/systemd/system/{self.unit}"
