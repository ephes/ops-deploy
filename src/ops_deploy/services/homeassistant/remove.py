"""Prepared original removal flags/order; never dispatched without confirmation."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any, Self

from pydantic import StrictBool, model_validator
from pyinfra.api import DeployError, deploy
from pyinfra.operations import server, systemd

from ops_deploy.base._common import AbsolutePath, RoleConfig, require_linux
from ops_deploy.services._lifecycle.ansible_remove import SERVICE_PROBE as SERVICE_PROBE
from ops_deploy.services._lifecycle.ansible_remove import absent, service_absent, user_absent


class HomeAssistantRemoveConfig(RoleConfig):
    confirm_removal: StrictBool = False
    user: str = "homeassistant"
    group: str = "homeassistant"
    service_name: str = "homeassistant"
    home: AbsolutePath = "/home/homeassistant"
    site_path: AbsolutePath = "/home/homeassistant/site"
    config_path: AbsolutePath = "/home/homeassistant/site/config"
    data_path: AbsolutePath = "/home/homeassistant/site/data"
    logs_path: AbsolutePath = "/home/homeassistant/site/logs"
    bin_path: AbsolutePath = "/home/homeassistant/site/bin"
    virtualenv_path: AbsolutePath = "/home/homeassistant/site/.venv"
    virtualenv_link: AbsolutePath = "/home/homeassistant/site/venv"
    systemd_unit_path: AbsolutePath = "/etc/systemd/system/homeassistant.service"
    traefik_config_path: AbsolutePath = "/etc/traefik/dynamic/homeassistant.yml"
    udev_rule_path: AbsolutePath = "/etc/udev/rules.d/99-homeassistant-zbt1.rules"
    remove_service: StrictBool = True
    remove_traefik: StrictBool = True
    remove_udev_rule: StrictBool = True
    remove_virtualenv: StrictBool = True
    remove_site_dir: StrictBool = True
    remove_config_dir: StrictBool = True
    remove_data_dir: StrictBool = True
    remove_logs_dir: StrictBool = True
    remove_bin_dir: StrictBool = True
    remove_user: StrictBool = True
    remove_group: StrictBool = True

    @model_validator(mode="before")
    @classmethod
    def original_dependent_paths(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        data = dict(value)
        data.setdefault("home", "/home/" + str(data.get("user", "homeassistant")))
        data.setdefault("site_path", str(data["home"]) + "/site")
        for field, suffix in (
            ("config_path", "config"),
            ("data_path", "data"),
            ("logs_path", "logs"),
            ("bin_path", "bin"),
            ("virtualenv_path", ".venv"),
            ("virtualenv_link", "venv"),
        ):
            data.setdefault(field, str(data["site_path"]) + "/" + suffix)
        data.setdefault(
            "systemd_unit_path", "/etc/systemd/system/" + str(data.get("service_name", "homeassistant")) + ".service"
        )
        return data

    @model_validator(mode="after")
    def bounded_paths(self) -> Self:
        for value in self.model_dump().values():
            if isinstance(value, str) and value.startswith("/"):
                path = PurePosixPath(value)
                if path == PurePosixPath("/") or ".." in path.parts:
                    raise ValueError("removal paths must not be root or contain traversal")
        return self


def _absent(path: str) -> None:
    absent("Remove Home Assistant path " + path, path)


@deploy("Remove Home Assistant")
def remove_homeassistant(cfg: HomeAssistantRemoveConfig) -> None:
    if not cfg.confirm_removal:
        raise DeployError("Home Assistant removal requires confirm_removal=true")
    require_linux("Home Assistant removal")
    if cfg.remove_service:
        service_absent(
            name="Disable and stop Home Assistant for removal",
            service=cfg.service_name,
            label="Home Assistant removal",
            _ignore_errors=True,
        )
        _absent(cfg.systemd_unit_path)
        systemd.daemon_reload(name="Reload systemd after Home Assistant removal")
    if cfg.remove_traefik:
        _absent(cfg.traefik_config_path)
    if cfg.remove_udev_rule:
        _absent(cfg.udev_rule_path)
    if cfg.remove_virtualenv:
        _absent(cfg.virtualenv_path)
        _absent(cfg.virtualenv_link)
    for path, enabled in (
        (cfg.config_path, cfg.remove_config_dir),
        (cfg.data_path, cfg.remove_data_dir),
        (cfg.logs_path, cfg.remove_logs_dir),
        (cfg.bin_path, cfg.remove_bin_dir),
        (cfg.site_path, cfg.remove_site_dir),
    ):
        if enabled:
            _absent(path)
    if cfg.remove_user:
        user_absent(name="Remove Home Assistant account", user=cfg.user, remove_home=cfg.remove_site_dir)
    if cfg.remove_group:
        server.group(name="Remove Home Assistant group", group=cfg.group, present=False)
