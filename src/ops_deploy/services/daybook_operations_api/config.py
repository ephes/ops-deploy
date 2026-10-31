"""Original Operations API inputs; fresh installs remain explicitly disabled."""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath
from typing import Annotated, Literal
from urllib.parse import quote

from pydantic import Field, SecretStr, field_validator, model_validator

from ops_deploy.base._common import AbsolutePath, RoleConfig
from ops_deploy.core.config import UnixUser
from ops_deploy.infra.postgres_install import Identifier, PostgresInstallConfig

Slug = Annotated[str, Field(pattern=r"^[a-z0-9_-]{1,50}$")]


class OperationsProfile(RoleConfig):
    """Schema4 identity and credentials only; source settings are never accepted."""

    schema_version: Literal[4] = Field(default=4, alias="schema")
    name: Slug
    host: Slug
    profile: Slug
    enabled: bool = Field(strict=True)
    tokens: tuple[SecretStr, ...] = Field(min_length=1)
    monitor_tokens: tuple[SecretStr, ...] = ()

    @field_validator("schema_version", mode="before")
    @classmethod
    def _schema(cls, value: object) -> object:
        if type(value) is not int or value != 4:
            raise ValueError("Profiles require integer schema4")
        return value

    @field_validator("tokens", "monitor_tokens")
    @classmethod
    def _tokens(cls, values: tuple[SecretStr, ...]) -> tuple[SecretStr, ...]:
        for token in values:
            value = token.get_secret_value()
            if not 32 <= len(value) <= 256 or not value.isascii() or any(c.isspace() for c in value):
                raise ValueError("Profile tokens must be bounded ASCII without whitespace")
        return values

    @model_validator(mode="after")
    def _purposes(self) -> OperationsProfile:
        if {v.get_secret_value() for v in self.tokens} & {v.get_secret_value() for v in self.monitor_tokens}:
            raise ValueError("Executor and monitor credentials must have distinct purposes")
        return self

    def revealed(self) -> dict[str, object]:
        return {
            "schema": self.schema_version,
            "name": self.name,
            "host": self.host,
            "profile": self.profile,
            "enabled": self.enabled,
            "tokens": [v.get_secret_value() for v in self.tokens],
            "monitor_tokens": [v.get_secret_value() for v in self.monitor_tokens],
        }


class OperationsApiPins(RoleConfig):
    secret_key: SecretStr
    database_password: SecretStr
    signing_keys: dict[str, SecretStr]
    signing_key_id: str
    profiles: tuple[OperationsProfile, ...] = Field(default=(), max_length=100)
    # Original standalone role permits overriding the complete connection URL.
    database_url: SecretStr | None = None

    @field_validator("secret_key", "database_password")
    @classmethod
    def _secret(cls, value: SecretStr) -> SecretStr:
        if not re.fullmatch(r"[A-Za-z0-9._~-]{32,256}", value.get_secret_value()):
            raise ValueError("Operations secrets must be32-256 original URL-safe characters")
        return value

    @field_validator("signing_keys")
    @classmethod
    def _keys(cls, value: dict[str, SecretStr]) -> dict[str, SecretStr]:
        if any(
            not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", key)
            or not re.fullmatch(r"[A-Za-z0-9._~-]{32,256}", secret.get_secret_value())
            for key, secret in value.items()
        ):
            raise ValueError("Operations derivation keys must match original bounds")
        return value

    @field_validator("database_url")
    @classmethod
    def _url_line(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None and any(c in value.get_secret_value() for c in "\r\n\x00"):
            raise ValueError("Database URL must be a single environment value")
        return value

    @model_validator(mode="after")
    def _identity(self) -> OperationsApiPins:
        if self.signing_key_id not in self.signing_keys:
            raise ValueError("Selected signing key must exist")
        if len({row.name for row in self.profiles}) != len(self.profiles):
            raise ValueError("Profile names must be unique")
        return self


class OperationsApiConfig(RoleConfig):
    enabled: bool = False
    user: UnixUser = "daybook-operations"
    home: AbsolutePath = "/home/daybook-operations"
    site: AbsolutePath | None = None
    venv: AbsolutePath | None = None
    config_dir: AbsolutePath = "/etc/daybook-operations"
    source_path: Path | None = None
    deploy_method: Literal["rsync", "git"] = "rsync"
    git_repo: str = "https://github.com/ephes/daybook.git"
    git_revision: str = ""
    uv: AbsolutePath = "/usr/local/bin/uv"
    port: int = Field(default=10063, gt=1024, lt=65536)
    domain: str = Field(default="operations.home.example.com", pattern=r"^[a-z0-9.-]+$")
    database: Identifier = "daybook_operations"
    database_user: Identifier = "daybook_operations"
    postgres: PostgresInstallConfig = Field(default_factory=PostgresInstallConfig)
    record_limit: int = Field(default=100000, ge=100)
    storage_path: AbsolutePath | None = None
    storage_sample_interval: int = Field(default=300, ge=1)
    storage_sample_max_age: int = Field(default=900, ge=1)
    nominal_records_per_day: int = Field(default=1152, ge=1)
    capacity_warn_utilization: float = Field(default=0.70, gt=0, le=1)
    capacity_critical_utilization: float = Field(default=0.80, gt=0, le=1)
    capacity_warn_days: float = Field(default=30, gt=0)
    capacity_critical_days: float = Field(default=14, gt=0)
    allowed_networks: tuple[str, ...] = Field(default=("100.64.0.0/10", "fd7a:115c:a1e0::/48"), min_length=1)
    traefik_path: AbsolutePath = "/etc/traefik/dynamic/daybook-operations.yml"
    backup_root: AbsolutePath = "/opt/backups/daybook_operations"

    @model_validator(mode="after")
    def _original_contract(self) -> OperationsApiConfig:
        if self.deploy_method == "rsync" and self.source_path is None:
            raise ValueError("Rsync requires an explicit prepared source")
        if self.deploy_method == "git" and not re.fullmatch(r"[0-9a-f]{40}", self.git_revision):
            raise ValueError("Git requires an exact reviewed revision")
        if self.storage_sample_max_age < self.storage_sample_interval:
            raise ValueError("Storage maximum age must cover the sampling interval")
        if self.capacity_warn_utilization > self.capacity_critical_utilization:
            raise ValueError("Capacity utilization thresholds must rise")
        if self.capacity_critical_days > self.capacity_warn_days:
            raise ValueError("Capacity horizon thresholds must fall")
        return self

    @property
    def site_path(self) -> PurePosixPath:
        return PurePosixPath(self.site or self.home + "/site")

    @property
    def venv_path(self) -> PurePosixPath:
        return PurePosixPath(self.venv or self.home + "/venv")

    def connection_url(self, pins: OperationsApiPins) -> str:
        if pins.database_url is not None:
            return pins.database_url.get_secret_value()
        password = quote(pins.database_password.get_secret_value(), safe="")
        return f"postgresql://{self.database_user}:{password}@127.0.0.1:5432/{self.database}"
