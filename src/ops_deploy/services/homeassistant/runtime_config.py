"""Physical runtime inputs, preserving the original role's independent paths."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Annotated, Any, Literal, Self

from pydantic import Field, StrictBool, StrictInt, model_validator

from ops_deploy.base._common import AbsolutePath, RoleConfig, Version
from ops_deploy.core.config import ServiceName, UnixUser

Port = Annotated[StrictInt, Field(ge=1, le=65535)]
Positive = Annotated[StrictInt, Field(ge=1)]
Plain = Annotated[str, Field(min_length=1, pattern=r"^[^\x00-\x1f\x7f]+$")]
ServiceState = Literal["started", "stopped", "restarted", "reloaded"]


class HomeAssistantRuntimeConfig(RoleConfig):
    user: UnixUser = "homeassistant"
    group: UnixUser = "homeassistant"
    shell: AbsolutePath = "/bin/bash"
    enable_udev_rule: StrictBool = True
    udev_rule_path: AbsolutePath = "/etc/udev/rules.d/99-homeassistant-zbt1.rules"
    home: AbsolutePath = "/home/homeassistant"
    site_path: AbsolutePath = "/home/homeassistant/site"
    config_path: AbsolutePath = "/home/homeassistant/site/config"
    data_path: AbsolutePath = "/home/homeassistant/site/data"
    logs_path: AbsolutePath = "/home/homeassistant/site/logs"
    bin_path: AbsolutePath = "/home/homeassistant/site/bin"
    virtualenv_path: AbsolutePath = "/home/homeassistant/site/.venv"
    virtualenv_link: AbsolutePath = "/home/homeassistant/site/venv"
    virtualenv_version_file: AbsolutePath = "/home/homeassistant/site/.venv/.ansible-python-version"
    python_version: Version = "3.14.8"
    package_spec: Plain = "homeassistant"
    extra_package_specs: tuple[Plain, ...] = ()
    force_reinstall: StrictBool = False
    restart_on_change: StrictBool = True
    service_name: ServiceName = "homeassistant"
    service_enabled: StrictBool = True
    service_state: ServiceState = "started"
    systemd_unit_path: AbsolutePath = "/etc/systemd/system/homeassistant.service"
    python_security_floor_enabled: StrictBool = True
    python_security_constraints_path: AbsolutePath = "/home/homeassistant/site/.python-security-constraints.txt"
    uv_system_certs: StrictBool = True
    uv_system_certs_dropin_path: AbsolutePath = "/etc/systemd/system/homeassistant.service.d/50-uv-system-certs.conf"
    uv_system_certs_allowed_dropins: tuple[AbsolutePath, ...] = ()
    manage_matter_server: StrictBool = False
    matter_server_package_spec: Plain = "python-matter-server[server]"
    matter_server_virtualenv_path: AbsolutePath = "/home/homeassistant/site/.venv-matter-server"
    matter_server_virtualenv_version_file: AbsolutePath = (
        "/home/homeassistant/site/.venv-matter-server/.ansible-python-version"
    )
    matter_server_service_name: ServiceName = "matter-server"
    matter_server_service_enabled: StrictBool = True
    matter_server_service_state: ServiceState = "started"
    matter_server_systemd_unit_path: AbsolutePath = "/etc/systemd/system/matter-server.service"
    matter_server_storage_path: AbsolutePath = "/home/homeassistant/site/data/matter-server"
    matter_server_port: Port = 5580
    matter_server_vendor_id: Annotated[StrictInt, Field(ge=0)] = 0xFFF1
    matter_server_fabric_id: Positive = 1
    matter_server_log_level: Annotated[str, Field(pattern=r"^[a-zA-Z]+$")] = "info"
    matter_server_log_file: AbsolutePath | Literal[""] = "/home/homeassistant/site/logs/matter-server.log"
    matter_server_restart_on_change: StrictBool = True
    matter_server_chip_factory_dir: AbsolutePath = "/data"

    @model_validator(mode="before")
    @classmethod
    def derived_defaults(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        result = dict(value)
        result.setdefault("group", result.get("user", "homeassistant"))
        result.setdefault("home", "/home/" + str(result.get("user", "homeassistant")))
        result.setdefault("site_path", str(result["home"]) + "/site")
        for field, suffix in (
            ("config_path", "config"),
            ("data_path", "data"),
            ("logs_path", "logs"),
            ("bin_path", "bin"),
            ("virtualenv_path", ".venv"),
            ("virtualenv_link", "venv"),
            ("matter_server_virtualenv_path", ".venv-matter-server"),
            ("python_security_constraints_path", ".python-security-constraints.txt"),
        ):
            result.setdefault(field, str(result["site_path"]) + "/" + suffix)
        for prefix in ("", "matter_server_"):
            result.setdefault(
                prefix + "virtualenv_version_file", str(result[prefix + "virtualenv_path"]) + "/.ansible-python-version"
            )
            service = result.get(prefix + "service_name", "matter-server" if prefix else "homeassistant")
            result.setdefault(prefix + "systemd_unit_path", f"/etc/systemd/system/{service}.service")
        result.setdefault("matter_server_storage_path", str(result["data_path"]) + "/matter-server")
        result.setdefault("matter_server_log_file", str(result["logs_path"]) + "/matter-server.log")
        result.setdefault(
            "uv_system_certs_dropin_path",
            f"/etc/systemd/system/{result.get('service_name', 'homeassistant')}.service.d/50-uv-system-certs.conf",
        )
        return result

    @model_validator(mode="after")
    def validate_runtime(self) -> Self:
        values = [*self.model_dump().values(), *self.uv_system_certs_allowed_dropins]
        for value in values:
            if isinstance(value, str) and value.startswith("/"):
                path = PurePosixPath(value)
                if path == PurePosixPath("/") or ".." in path.parts:
                    raise ValueError("runtime paths must not be root or contain traversal")
        if self.manage_matter_server:
            if (
                "python-matter-server" not in self.matter_server_package_spec
                or "[server]" not in self.matter_server_package_spec
            ):
                raise ValueError("Matter package must include python-matter-server and server extras")
            if tuple(int(part) for part in self.python_version.split(".")) < (3, 12):
                raise ValueError("Matter requires Python 3.12 or newer")
        return self
