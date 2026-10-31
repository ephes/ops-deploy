"""Prepared original removal flags/order; never dispatched without confirmation."""

from __future__ import annotations

import json
import shlex
from collections.abc import Generator
from pathlib import PurePosixPath
from typing import Any, Self

from pydantic import StrictBool, model_validator
from pyinfra import host
from pyinfra.api import DeployError, FunctionCommand, OperationError, QuoteString, StringCommand, deploy, operation
from pyinfra.facts.server import Command, Users
from pyinfra.operations import files, server, systemd

from ops_deploy.base._common import AbsolutePath, RoleConfig, require_linux


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


SERVICE_PROBE = """import json, subprocess, sys
try:
    unit = sys.argv[1]
    show = subprocess.run(['systemctl', 'show', unit],
                          capture_output=True, text=True, timeout=60)
    enabled = subprocess.run(['systemctl', 'is-enabled', unit, '-l'],
                             capture_output=True, text=True, timeout=60)
    fields = dict(line.split('=', 1) for line in show.stdout.splitlines() if '=' in line)
    result = dict(success=show.returncode == 0 and
                          (fields.get('LoadState') == 'masked' or 'LoadError' not in fields),
                  load=fields.get('LoadState', ''),
                  active=fields.get('ActiveState', ''),
                  enabled=enabled.returncode == 0 and enabled.stdout.rstrip()
                          not in ('enabled-runtime', 'indirect', 'alias'))
except Exception:
    result = dict(success=False)
print(json.dumps(result))
"""


def _unavailable_service() -> None:
    raise OperationError("Home Assistant removal service inspection failed or unit was absent")


@operation()
def _stop_disable_service(service: str) -> Generator[StringCommand | FunctionCommand, None, None]:
    # Ansible systemd_service disables BEFORE stopping. A failed disable must
    # skip stop, then the role's ignored-task failure permits later removal.
    raw = host.get_fact(Command, command=shlex.join(["/usr/bin/python3", "-I", "-B", "-c", SERVICE_PROBE, service]))
    try:
        observed = json.loads(raw or "")
        if (
            set(observed) != {"success", "load", "active", "enabled"}
            or observed["success"] is not True
            or type(observed["enabled"]) is not bool
            or not all(type(observed[key]) is str for key in ("load", "active"))
            or observed["load"] in ("", "not-found")
            or not observed["active"]
        ):
            raise ValueError
    except (ValueError, TypeError, KeyError):
        yield FunctionCommand(_unavailable_service, (), {})
        return
    if observed["enabled"]:
        yield StringCommand("systemctl", "disable", QuoteString(service))
    if observed["active"] in ("active", "activating", "deactivating"):
        yield StringCommand("systemctl", "stop", QuoteString(service))


@operation()
def _remove_user(user: str, remove_home: bool) -> Generator[StringCommand, None, None]:
    # server.user(present=False) does not expose the original user module's
    # remove=true behavior. Keep userdel failure fatal, including partial failure.
    if user in host.get_fact(Users):
        yield StringCommand("userdel", *(["-r"] if remove_home else []), QuoteString(user))


def _absent(path: str) -> None:
    # Original file(state=absent) handles directory, file and leaf symlink; do not
    # follow the leaf or preserve a renamed backup of an explicitly removed path.
    files.directory(name="Remove Home Assistant path " + path, path=path, present=False, force=True, force_backup=False)


@deploy("Remove Home Assistant")
def remove_homeassistant(cfg: HomeAssistantRemoveConfig) -> None:
    if not cfg.confirm_removal:
        raise DeployError("Home Assistant removal requires confirm_removal=true")
    require_linux("Home Assistant removal")
    if cfg.remove_service:
        _stop_disable_service(
            name="Disable and stop Home Assistant for removal",
            service=cfg.service_name,
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
        _remove_user(name="Remove Home Assistant account", user=cfg.user, remove_home=cfg.remove_site_dir)
    if cfg.remove_group:
        server.group(name="Remove Home Assistant group", group=cfg.group, present=False)
