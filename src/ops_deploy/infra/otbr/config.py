"""Original otbr_deploy desired state, without the otbr_ variable prefix."""

from __future__ import annotations

from typing import Annotated, Literal, Self

from pydantic import Field, field_validator, model_validator

from ops_deploy.base._common import AbsolutePath, RoleConfig

Word = Annotated[str, Field(pattern=r"^[A-Za-z0-9_.:@+-]+$", min_length=1)]
Mode = Annotated[str, Field(pattern=r"^0?[0-7]{3,4}$")]
Line = Annotated[str, Field(pattern=r"^[^\r\n\x00]*$")]
NonEmptyLine = Annotated[str, Field(pattern=r"^[^\r\n\x00]+$", min_length=1)]


class OtbrConfig(RoleConfig):
    repo_url: NonEmptyLine = "https://github.com/openthread/ot-br-posix.git"
    repo_version: NonEmptyLine = "main"
    install_dir: AbsolutePath = "/opt/ot-br-posix"
    manage_packages: bool = True
    prereq_packages: tuple[NonEmptyLine, ...] = ("ca-certificates", "curl", "git", "lsb-release", "sudo")
    remove_bind: bool = True
    bind_packages: tuple[NonEmptyLine, ...] = ("bind9",)
    bind_services: tuple[Word, ...] = ("named.service", "named-resolvconf.service")
    force_bootstrap: bool = False
    force_rebuild: bool = False
    bootstrap_marker: AbsolutePath | None = None
    build_config_path: AbsolutePath | None = None
    agent_bin: AbsolutePath = "/usr/sbin/otbr-agent"
    agent_defaults_path: AbsolutePath = "/etc/default/otbr-agent"
    rcp_device: AbsolutePath
    rcp_baudrate: Annotated[int, Field(gt=0)] = 460800
    wpan_interface: Word = "wpan0"
    # Empty string preserves the role's default-IPv4-interface fallback.
    infra_interface: Word | Literal[""] = ""
    backbone_interface: Word | Literal[""] | None = None
    rest_api_enabled: bool = True
    rest_listen_address: Line = "127.0.0.1"
    rest_listen_port: Annotated[int, Field(gt=0)] = 8081
    agent_extra_opts: Line = ""
    no_auto_attach: bool = False
    web_enabled: bool = False
    mdns: Line = "openthread"
    dhcp6_pd_client: Line = "none"
    backbone_router: bool = True
    border_routing: bool = True
    nat64: bool = True
    discovery_proxy: bool = True
    firewall: bool = True
    build_options: Line = ""
    # An explicit mapping replaces the default mapping; never silently merge.
    build_env: dict[str, str] | None = None
    service_name: Word = "otbr-agent"
    web_service_name: Word = "otbr-web"
    service_enabled: bool = True
    service_state: Literal["started", "stopped", "restarted", "reloaded"] = "started"
    restart_on_change: bool = True
    manage_udev: bool = True
    udev_rule_path: AbsolutePath = "/etc/udev/rules.d/99-otbr-zbt2.rules"
    udev_group: Word = "dialout"
    udev_mode: Mode = "0660"
    udev_vid: Annotated[str, Field(pattern=r"^[0-9A-Fa-f]{4}$")] = "303a"
    udev_pids: tuple[Annotated[str, Field(pattern=r"^[0-9A-Fa-f]{4}$")], ...] = ("4001", "831a")

    @model_validator(mode="after")
    def original_validation(self) -> Self:
        if self.rest_api_enabled and not self.rest_listen_address:
            raise ValueError("REST listen address is required when REST is enabled")
        if self.install_dir == "/":
            raise ValueError("install_dir must identify the OTBR source directory")
        return self

    @field_validator("repo_url", "repo_version")
    @classmethod
    def no_git_options(cls, value: str) -> str:
        if value.startswith("-"):
            raise ValueError("repository and revision must not be Git options")
        return value

    @field_validator("build_env")
    @classmethod
    def environment_keys(cls, value: dict[str, str] | None) -> dict[str, str] | None:
        import re

        if value is not None and any(
            re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) is None or "\x00" in item for key, item in value.items()
        ):
            raise ValueError("build environment names must be shell environment names")
        return value
