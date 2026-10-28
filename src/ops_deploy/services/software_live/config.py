"""Inputs of the software_live role, including its rollback and shadow contract."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, ClassVar, Literal, Self

from pydantic import Field, StrictBool, StrictInt, model_validator

from ops_deploy.core.config import BaseServiceConfig, ServiceName, UnixUser
from ops_deploy.services.metrics_endpoint.common import EndpointConfig, Package, PlainPath

Positive = Annotated[StrictInt, Field(ge=1)]
Nonnegative = Annotated[StrictInt, Field(ge=0)]
Port = Annotated[StrictInt, Field(gt=1024, lt=65536)]
Calendar = Annotated[str, Field(min_length=1, pattern=r"^[^\x00-\x1f\x7f]+$")]
Dedicated = Annotated[PlainPath, Field()]
DEDICATED = re.compile(r"^/(etc|var/lib|usr/local/lib)/[a-zA-Z0-9_-]*software-live[a-zA-Z0-9_-]*$")


class SoftwareLiveConfig(BaseServiceConfig):
    required_secret_keys: ClassVar[tuple[str, ...]] = ("endpoint_password",)
    service_name: ServiceName = "software-live-endpoint"
    user: UnixUser = "metrics"
    group: UnixUser = "metrics"
    site_path: PlainPath = PurePosixPath("/usr/local/lib/software-live")
    policy: dict[str, Any]
    bind: ipaddress.IPv4Address | Literal["tailscale"] = "tailscale"
    port: Port = 9110
    auth_user: Annotated[str, Field(pattern=r"^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$")]
    config_dir: Dedicated = PurePosixPath("/etc/software-live")
    data_dir: Dedicated = PurePosixPath("/var/lib/software-live")
    install_dir: Dedicated = PurePosixPath("/usr/local/lib/software-live")
    packages: tuple[Package, ...] = ("python3", "python3-apt", "apache2-utils")
    on_calendar: Calendar = "*:0/15"
    inventory_export: StrictBool = False
    inventory_group: UnixUser = "software-estate-publisher"
    impl: Literal["python", "rust"] = "python"
    rust_version: str = ""
    rust_sha256: dict[str, str] = Field(default_factory=dict)
    rust_release_url: str = ""
    rust_local_archive: Path | None = None
    rust_keep_versions: Annotated[StrictInt, Field(ge=2)] = 3
    rust_shadow: StrictBool = False
    shadow_port: Port = 9119
    shadow_on_calendar: Calendar = "*:7/15"
    verify_retries: Positive = 15
    verify_delay: Nonnegative = 2
    collector_wait_retries: Positive = 60
    systemd_dir: PlainPath = PurePosixPath("/etc/systemd/system")
    proc_root: PlainPath = PurePosixPath("/proc")
    cgroup_root: PlainPath = PurePosixPath("/sys/fs/cgroup")
    os_release_path: PlainPath = PurePosixPath("/etc/os-release")
    rust_version_check_user: UnixUser | Literal[""] | None = None

    @model_validator(mode="after")
    def role_inputs(self) -> Self:
        if any(key not in self.policy for key in ("host", "os", "postgresql", "traefik")):
            raise ValueError("policy requires host, os, postgresql and traefik")
        if self.auth_user == "CHANGE_ME":
            raise ValueError("auth_user is still the role placeholder")
        if any(not DEDICATED.fullmatch(str(path)) for path in (self.config_dir, self.data_dir, self.install_dir)):
            raise ValueError("use dedicated software-live directories under etc, var/lib or usr/local/lib")
        if self.port == self.shadow_port:
            raise ValueError("shadow_port must differ from the production port")
        if not isinstance(self.bind, str) and not (
            self.bind.is_loopback or self.bind in ipaddress.ip_network("100.64.0.0/10")
        ):
            raise ValueError("bind must be a loopback or Tailscale IPv4 address")
        return self

    @property
    def host_id(self) -> str:
        return str(self.policy["host"])

    @property
    def release_root(self) -> PurePosixPath:
        return self.install_dir / "releases"

    @property
    def binary(self) -> PurePosixPath:
        return self.release_root / self.rust_version / "software-live"

    @property
    def state_path(self) -> PurePosixPath:
        return self.data_dir / "state.json"

    def endpoint(self) -> EndpointConfig:
        return EndpointConfig(
            service_name=self.service_name,
            user=self.user,
            group=self.group,
            secrets=self.secrets,
            bind=self.bind,
            port=self.port,
            path="/.well-known/software-live",
            auth_user=self.auth_user,
            server_path=self.install_dir / "software_live.py",
            htpasswd_dir=self.config_dir,
            packages=self.packages,
        )


class SoftwareLiveRemoveConfig(BaseServiceConfig):
    user: UnixUser = "metrics"
    site_path: PlainPath = PurePosixPath("/usr/local/lib/software-live")
    service_name: ServiceName = "software-live-endpoint"
    config_dir: Dedicated = PurePosixPath("/etc/software-live")
    data_dir: Dedicated = PurePosixPath("/var/lib/software-live")
    install_dir: Dedicated = PurePosixPath("/usr/local/lib/software-live")
    remove_data: StrictBool = False

    @model_validator(mode="after")
    def dedicated_paths(self) -> Self:
        if any(not DEDICATED.fullmatch(str(path)) for path in (self.config_dir, self.data_dir, self.install_dir)):
            raise ValueError("removal requires dedicated software-live directories")
        return self
