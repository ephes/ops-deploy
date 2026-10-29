"""Original jellyfin_remove role; explicit confirmation and independent keep flags."""

from pyinfra.api import deploy

from ops_deploy.services._lifecycle.media_remove import (
    Identity,
    MediaRemoveConfig,
    ResourcePath,
    ServiceName,
    remove_media,
)


class JellyfinRemoveConfig(MediaRemoveConfig):
    remove_packages: bool = True
    remove_data: bool = True
    remove_logs: bool = True
    remove_config: bool = True
    user: Identity = "jellyfin"
    group: Identity = "jellyfin"
    service_name: ServiceName = "jellyfin"
    service_unit: ResourcePath = "/lib/systemd/system/jellyfin.service"
    config_dir: ResourcePath = "/etc/jellyfin"
    data_dir: ResourcePath = "/var/lib/jellyfin"
    log_dir: ResourcePath = "/var/log/jellyfin"
    traefik_config_path: ResourcePath = "/etc/traefik/dynamic/jellyfin.yml"


@deploy("Remove Jellyfin")
def deploy_jellyfin_remove(cfg: JellyfinRemoveConfig) -> None:
    paths = []
    for enabled, path in [
        (cfg.remove_config, cfg.config_dir),
        (cfg.remove_data, cfg.data_dir),
        (cfg.remove_logs, cfg.log_dir),
        (cfg.remove_traefik_config, cfg.traefik_config_path),
    ]:
        if enabled:
            paths.append(path)
    remove_media(
        confirm=cfg.confirm,
        label="jellyfin_remove",
        service_name=cfg.service_name,
        unit_paths=[cfg.service_unit],
        paths=paths,
        user=cfg.user if cfg.remove_user else None,
        group=cfg.group if cfg.remove_user else None,
        packages=cfg.remove_packages,
        traefik_path=cfg.traefik_config_path if cfg.remove_traefik_config else None,
    )
