"""Original metube_remove role; explicit confirmation and independent keep flags."""

from pyinfra.api import deploy

from ops_deploy.services._lifecycle.media_remove import (
    Identity,
    MediaRemoveConfig,
    ResourcePath,
    ServiceName,
    remove_media,
)


class MetubeRemoveConfig(MediaRemoveConfig):
    remove_service: bool = True
    remove_install_dir: bool = True
    remove_state: bool = True
    remove_env: bool = True
    remove_downloads: bool = False
    user: Identity = "metube"
    group: Identity = "metube"
    service_name: ServiceName = "metube"
    service_unit: ResourcePath = "/etc/systemd/system/metube.service"
    env_dir: ResourcePath = "/etc/metube"
    state_dir: ResourcePath = "/var/lib/metube"
    download_dir: ResourcePath = "/mnt/cryptdata/media/video/youtube"
    install_dir: ResourcePath = "/opt/metube"
    ui_build_root: ResourcePath = "/var/cache/metube"
    traefik_config_path: ResourcePath = "/etc/traefik/dynamic/metube.yml"


@deploy("Remove Metube")
def deploy_metube_remove(cfg: MetubeRemoveConfig) -> None:
    paths = []
    for enabled, selected in [
        (cfg.remove_env, [cfg.env_dir]),
        (cfg.remove_state, [cfg.state_dir]),
        (cfg.remove_downloads, [cfg.download_dir]),
        (cfg.remove_install_dir, [cfg.install_dir, cfg.ui_build_root]),
        (cfg.remove_traefik_config, [cfg.traefik_config_path]),
    ]:
        if enabled:
            paths.extend(selected)
    remove_media(
        confirm=cfg.confirm,
        label="metube_remove",
        service_name=cfg.service_name,
        unit_paths=[cfg.service_unit] if cfg.remove_service else [],
        paths=paths,
        user=cfg.user if cfg.remove_user else None,
        group=cfg.group if cfg.remove_user else None,
        control_service=cfg.remove_service,
        defer_unit_reload=True,
        reload_traefik=True,
        traefik_path=cfg.traefik_config_path if cfg.remove_traefik_config else None,
    )
