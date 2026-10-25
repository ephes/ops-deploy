"""Bounded, existing-install Mastodon configuration convergence; no upgrades."""

from __future__ import annotations

import re
import string
from pathlib import PurePosixPath
from typing import Annotated, Self

from pydantic import Field, field_validator, model_validator

from ops_deploy.base._common import RoleConfig
from ops_deploy.core.git_source import CommitSha

Path_ = Annotated[str, Field(pattern=r"^/[A-Za-z0-9._/-]+$")]
Domain = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9.-]*[a-z0-9]$")]
Version = Annotated[str, Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")]


def unquoted_env_literal(value: str) -> str:
    """Validate literal Bash assignment values used by the unchanged role env."""
    if any(c in value for c in string.whitespace + "\x00\"\\$`';|&<>()") or re.search(r"(?:^|:)~", value):
        raise ValueError("mastodon: unsupported unquoted literal environment value")
    return value


class MastodonConfig(RoleConfig):
    """Existing single-domain or delegated-domain local-storage layouts are supported.

    The controller resolves the inventory ref through ``fetch_source`` and
    supplies the commit and runtime versions. The host must already carry
    exactly that clean commit, dependencies, assets and environment.
    """

    site_path: Path_
    home_path: Path_
    local_domain: Domain
    web_domain: Domain
    source_commit: CommitSha
    ruby_version: Version
    node_version: Annotated[str, Field(pattern=r"^[0-9]+\.[0-9]+(?:\.[0-9]+)?$")]
    source_files: dict[str, Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]]
    web_port: int = Field(default=10040, gt=1024, lt=65536)
    streaming_port: int = Field(default=10041, gt=1024, lt=65536)
    web_concurrency: Annotated[int, Field(strict=True, gt=0)] = 2
    max_threads: Annotated[int, Field(strict=True, gt=0)] = 5
    sidekiq_concurrency: Annotated[int, Field(strict=True, gt=0)] = 25
    db_pool: Annotated[int, Field(strict=True, gt=0)] = 25
    nginx_federation_cache_enabled: bool = False
    nginx_access_log_timing: bool = False
    traefik_local_domain_wellknown: bool = False
    traefik_local_domain_cert_resolver: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]*$")] = ""
    smtp_server: Domain
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_login: str
    smtp_from_address: str
    smtp_domain: Domain
    traefik_cert_resolver: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]*$")] = ""

    @field_validator("site_path", "home_path")
    @classmethod
    def _normal_path(cls, value: str) -> str:
        if ".." in PurePosixPath(value).parts or "//" in value or value.endswith("/") or value == "/":
            raise ValueError("paths must be normalised non-root absolute paths")
        return value

    @field_validator("smtp_from_address")
    @classmethod
    def _literal_env(cls, value: str) -> str:
        if not value or any(c in value for c in '\r\n\x00"\\$`'):
            raise ValueError("SMTP fields must be literal single-line environment values")
        return value

    @field_validator("smtp_login")
    @classmethod
    def _smtp_login_literal(cls, value: str) -> str:
        if not value:
            raise ValueError("SMTP login must not be empty")
        return unquoted_env_literal(value)

    @model_validator(mode="after")
    def _layout(self) -> Self:
        if set(self.source_files) != {"Gemfile.lock", "yarn.lock", "package.json", ".ruby-version", ".nvmrc"}:
            raise ValueError("the source contract requires both lockfiles and runtime declarations")
        if self.db_pool < max(self.max_threads, self.sidekiq_concurrency):
            raise ValueError("db_pool must cover both max_threads and sidekiq_concurrency")
        if self.site_path != self.home_path + "/live":
            raise ValueError("only the existing <home>/live layout is supported")
        if len({self.web_port, self.streaming_port, 10044}) != 3:
            raise ValueError("web, streaming and nginx ports must differ")
        return self
