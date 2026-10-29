"""Original navidrome_remove role; explicit confirmation and independent keep flags."""

from pyinfra.api import deploy

from ops_deploy.services._lifecycle.media_remove import (
    Identity,
    MediaRemoveConfig,
    ResourcePath,
    ServiceName,
    remove_media,
)


class NavidromeRemoveConfig(MediaRemoveConfig):
    remove_data: bool = True
    remove_logs: bool = True
    remove_binary: bool = True
    user: Identity = "navidrome"
    group: Identity = "navidrome"
    service_name: ServiceName = "navidrome"
    service_unit: ResourcePath = "/etc/systemd/system/navidrome.service"
    rescan_service_unit: ResourcePath = "/etc/systemd/system/navidrome-rescan.service"
    rescan_timer_unit: ResourcePath = "/etc/systemd/system/navidrome-rescan.timer"
    config_path: ResourcePath = "/etc/navidrome.toml"
    data_dir: ResourcePath = "/var/lib/navidrome"
    cache_dir: ResourcePath | None = None
    log_dir: ResourcePath = "/var/log/navidrome"
    install_dir: ResourcePath = "/opt/navidrome"
    bin_path: ResourcePath | None = None
    bin_link_path: ResourcePath = "/usr/local/bin/navidrome"
    traefik_config_path: ResourcePath = "/etc/traefik/dynamic/navidrome.yml"


@deploy("Remove Navidrome")
def deploy_navidrome_remove(cfg: NavidromeRemoveConfig) -> None:
    paths = [cfg.config_path]
    if cfg.remove_data:
        paths += [cfg.data_dir, cfg.cache_dir or f"{cfg.data_dir}/cache"]
    if cfg.remove_logs:
        paths.append(cfg.log_dir)
    if cfg.remove_binary:
        paths += [cfg.bin_path or f"{cfg.install_dir}/navidrome", cfg.bin_link_path, cfg.install_dir]
    if cfg.remove_traefik_config:
        paths.append(cfg.traefik_config_path)
    remove_media(
        confirm=cfg.confirm,
        label="navidrome_remove",
        service_name=cfg.service_name,
        unit_paths=[cfg.service_unit, cfg.rescan_service_unit, cfg.rescan_timer_unit],
        paths=paths,
        user=cfg.user if cfg.remove_user else None,
        group=cfg.group if cfg.remove_user else None,
        traefik_path=cfg.traefik_config_path if cfg.remove_traefik_config else None,
    )
