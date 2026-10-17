"""compose_app: one deploy for the Docker Compose apps (rendered compose file, oneshot unit, route, checks).

Each app is a :class:`ComposeAppConfig`; :func:`deploy_compose_app` runs the
shared step sequence and writes the canonical file set
(``docs/services/compose_app.md``); :func:`remove_compose_app` takes it down
again and keeps the data.
"""

from ops_deploy.services.compose_app.config import (
    ApiAuth,
    AppUser,
    Bind,
    Checks,
    ComposeAppConfig,
    ComposeService,
    ConfigFile,
    DependsOn,
    Directory,
    EnvEntry,
    EnvFile,
    EnvRef,
    Healthcheck,
    HostId,
    HostSecret,
    HttpCheck,
    HttpJsonItems,
    HttpJsonSettings,
    JsonKeyCopy,
    PublishedPort,
    QbittorrentPreferences,
    RequiredPath,
    Route,
    SchemaRef,
    Secret,
    Sysctl,
)
from ops_deploy.services.compose_app.deploy import ComposeAppRemoveConfig, deploy_compose_app, remove_compose_app

__all__ = [
    "ApiAuth",
    "AppUser",
    "Bind",
    "Checks",
    "ComposeAppConfig",
    "ComposeAppRemoveConfig",
    "ComposeService",
    "ConfigFile",
    "DependsOn",
    "Directory",
    "EnvEntry",
    "EnvFile",
    "EnvRef",
    "Healthcheck",
    "HostId",
    "HostSecret",
    "HttpCheck",
    "HttpJsonItems",
    "HttpJsonSettings",
    "JsonKeyCopy",
    "PublishedPort",
    "QbittorrentPreferences",
    "RequiredPath",
    "Route",
    "SchemaRef",
    "Secret",
    "Sysctl",
    "deploy_compose_app",
    "remove_compose_app",
]
