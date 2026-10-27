"""Deliberately narrow configuration convergence contract for an installed controller."""

from __future__ import annotations

import ipaddress
import re
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from ops_deploy.base._common import RoleConfig
from ops_deploy.helpers.traefik import Hostname

Word = Annotated[str, Field(pattern=r"^[A-Za-z][A-Za-z0-9_-]{0,63}$")]


class UnifiRoutine(RoleConfig):
    """Explicit artifact selection for normal deployment of an initialized controller.

    MongoDB authentication must already work; provisioning a new database is a
    separate bootstrap concern. Package presence preserves installed Java/Mongo
    patches, as the Ansible role does.
    """

    package_version: Annotated[str, Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-[0-9]+$")]
    package_url: Annotated[
        str, Field(pattern=r"^https://dl\.ui\.com/unifi/[0-9]+\.[0-9]+\.[0-9]+/unifi_sysvinit_all\.deb$")
    ]
    package_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class UnifiConfig(RoleConfig):
    """Fixed role layout; unknown/unsupported role settings fail rather than being ignored.

    Without routine selection, retain the original exact-build config contract.
    Routine selection adds package/runtime and authenticated Mongo/HA changes
    for an initialized Ubuntu 24.04 controller; no fresh database bootstrap.
    """

    routine: UnifiRoutine | None = None
    installed_package_version: Literal["9.5.21-31260-1"]
    controller_bind_address: str
    external_hostname: Hostname
    traefik_enabled: bool = True
    traefik_entrypoints: tuple[Word, ...] = ("web-secure",)
    traefik_certresolver: Word | None = "letsencrypt"
    traefik_ip_allowlist: tuple[str, ...] = ()
    manage_firewall: bool = True
    create_homeassistant_user: bool = False
    homeassistant_username: Word = "homeassistant"
    jvm_min_heap_mb: int = Field(default=1024, ge=128, le=131072)
    jvm_max_heap_mb: int = Field(default=2048, ge=128, le=131072)
    mongodb_logrotate_enabled: bool = True
    mongodb_monitor_script_enabled: bool = True
    mongodb_log_max_size_mb: int = Field(default=500, ge=1, le=1048576)
    healthcheck_timeout: int = Field(default=120, ge=1, le=600)

    @field_validator("controller_bind_address")
    @classmethod
    def _address(cls, value: str) -> str:
        # The role writes this unbracketed in its HTTPS backend URL.
        ipaddress.IPv4Address(value)
        return value

    @field_validator("traefik_entrypoints")
    @classmethod
    def _entrypoints(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value or len(set(value)) != len(value):
            raise ValueError("traefik_entrypoints must contain distinct names")
        return value

    @field_validator("traefik_ip_allowlist")
    @classmethod
    def _networks(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for network in value:
            if not re.fullmatch(r"[0-9A-Fa-f:.]+(/[0-9]{1,3})?", network):
                raise ValueError("traefik_ip_allowlist must contain unscoped IP networks")
            ipaddress.ip_network(network, strict=False)
        return value

    @model_validator(mode="after")
    def _heaps(self) -> UnifiConfig:
        if self.routine and self.routine.package_version.split("-", 1)[0] != self.routine.package_url.split("/")[-2]:
            raise ValueError("selected package URL must match its full version")
        if self.jvm_min_heap_mb > self.jvm_max_heap_mb:
            raise ValueError("jvm_min_heap_mb must not exceed jvm_max_heap_mb")
        return self
