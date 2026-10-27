"""Common current-host inputs; no PHP or nginx architecture conversion."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, StrictBool, field_validator

from ops_deploy.core.config import BaseServiceConfig

PathText = Annotated[str, Field(pattern=r"^/[A-Za-z0-9_./-]+$")]
Name = Annotated[str, Field(pattern=r"^[A-Za-z0-9_.-]+$")]
Domain = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9.-]*$")]


class MailWebConfig(BaseServiceConfig):
    php_version: Annotated[str, Field(pattern=r"^[0-9]+\.[0-9]+$")] = "8.3"
    listen_address: Literal["127.0.0.1"] = "127.0.0.1"
    listen_port: Annotated[int, Field(ge=1, le=65535)]
    traefik_host: Domain
    traefik_enabled: StrictBool = True
    traefik_entrypoints: tuple[Name, ...] = ("web-secure",)
    traefik_cert_resolver: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]*$")] = ""
    traefik_middlewares: tuple[Annotated[str, Field(pattern=r"^[A-Za-z0-9_.@-]+$")], ...] = ()
    traefik_sts_preload: StrictBool = False
    healthcheck_enabled: StrictBool = True
    healthcheck_timeout: Annotated[int, Field(ge=1, le=60)] = 10
    healthcheck_retries: Annotated[int, Field(ge=1, le=10)] = 3
    php_pm: Literal["ondemand", "dynamic", "static"] = "ondemand"
    php_pm_max_children: Annotated[int, Field(ge=1, le=128)] = 5
    php_pm_max_requests: Annotated[int, Field(ge=1)] = 500
    php_pm_process_idle_timeout: Annotated[str, Field(pattern=r"^[0-9]+s$")] = "10s"
    php_memory_limit: Annotated[str, Field(pattern=r"^[0-9]+M$")] = "128M"
    php_max_execution_time: Annotated[int, Field(ge=1)] = 30
    nginx_client_max_body_size: Annotated[str, Field(pattern=r"^[0-9]+m$")] = "10m"
    web_user: Name = "www-data"
    web_group: Name = "www-data"

    @field_validator("*", mode="after")
    @classmethod
    def no_control_or_parent(cls, value: object) -> object:
        if isinstance(value, str) and (any(ord(c) < 32 for c in value) or "/../" in value or value.endswith("/..")):
            raise ValueError("mail web input contains unsafe path or control characters")
        return value
