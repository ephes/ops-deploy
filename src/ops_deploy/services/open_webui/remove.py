"""The ``open_webui_venv_remove`` role: explicit confirmation and opt-in removal flags.

As in the role, the unit is always stopped, disabled and removed; everything
else is kept unless its ``remove_*`` flag is set (all default ``False``).
``remove_user`` is ``userdel --remove``, which also takes the account's home
(uv runs as the user with that home). The paths are the role's defaults:
``data_dir`` is ``/var/lib/open-webui`` here, not the deploy's data directory,
unless the caller passes it.

The shared removal helper (``_lifecycle.media_remove``) plans from the listed
paths, unit and account only, refuses system roots, and deletes the route
behind the Traefik transaction guard. Differences from the role: systemd is
reloaded only when a unit file was removed, and the role's Traefik reload
(which fails on a unit without ``ExecReload`` and is ignored) is not run;
Traefik's file watch drops the route.
"""

from __future__ import annotations

from pyinfra.api import deploy

from ops_deploy.base._common import RoleConfig
from ops_deploy.services._lifecycle.media_remove import Identity, ResourcePath, ServiceName, remove_media


class OpenWebUIRemoveConfig(RoleConfig):
    confirm: bool = False
    remove_env_file: bool = False
    remove_venv: bool = False
    remove_site_dir: bool = False
    remove_data: bool = False
    remove_log_dir: bool = False
    remove_traefik_config: bool = False
    remove_user: bool = False
    remove_group: bool = False
    service_name: ServiceName = "open-webui"
    user: Identity = "openwebui"
    group: Identity = "openwebui"
    site_dir: ResourcePath = "/opt/open-webui"
    # The role's defaults below site_dir.
    env_path: ResourcePath | None = None
    venv_path: ResourcePath | None = None
    data_dir: ResourcePath = "/var/lib/open-webui"
    log_dir: ResourcePath = "/var/log/open-webui"
    traefik_config_path: ResourcePath = "/etc/traefik/dynamic/open-webui.yml"


@deploy("Remove Open WebUI")
def deploy_open_webui_remove(cfg: OpenWebUIRemoveConfig) -> None:
    paths = []
    for enabled, path in [
        (cfg.remove_traefik_config, cfg.traefik_config_path),
        (cfg.remove_env_file, cfg.env_path or f"{cfg.site_dir}/open-webui.env"),
        (cfg.remove_venv, cfg.venv_path or f"{cfg.site_dir}/.venv"),
        (cfg.remove_site_dir, cfg.site_dir),
        (cfg.remove_data, cfg.data_dir),
        (cfg.remove_log_dir, cfg.log_dir),
    ]:
        if enabled:
            paths.append(path)
    remove_media(
        confirm=cfg.confirm,
        label="open_webui_venv_remove",
        service_name=cfg.service_name,
        unit_paths=[f"/etc/systemd/system/{cfg.service_name}.service"],
        paths=paths,
        user=cfg.user if cfg.remove_user else None,
        group=cfg.group if cfg.remove_group else None,
        defer_unit_reload=True,
        traefik_path=cfg.traefik_config_path if cfg.remove_traefik_config else None,
    )
