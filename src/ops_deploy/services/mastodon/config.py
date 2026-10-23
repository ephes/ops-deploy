"""Bounded, existing-install Mastodon configuration convergence; no upgrades."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Annotated, Self

from pydantic import Field, field_validator, model_validator

from ops_deploy.base._common import RoleConfig
from ops_deploy.core.git_source import CommitSha

Path_ = Annotated[str, Field(pattern=r"^/[A-Za-z0-9._/-]+$")]
Domain = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9.-]*[a-z0-9]$")]
Version = Annotated[str, Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")]


class MastodonConfig(RoleConfig):
    """Only the default single-domain, local-storage layout is supported.

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

    @field_validator("smtp_login", "smtp_from_address")
    @classmethod
    def _literal_env(cls, value: str) -> str:
        if not value or any(c in value for c in '\r\n\x00"\\$`'):
            raise ValueError("SMTP fields must be literal single-line environment values")
        return value

    @model_validator(mode="after")
    def _layout(self) -> Self:
        if set(self.source_files) != {"Gemfile.lock", "yarn.lock", "package.json", ".ruby-version", ".nvmrc"}:
            raise ValueError("the source contract requires both lockfiles and runtime declarations")
        if self.local_domain != self.web_domain:
            raise ValueError("split-domain changes are outside the existing-install contract")
        if self.site_path != self.home_path + "/live":
            raise ValueError("only the existing <home>/live layout is supported")
        if len({self.web_port, self.streaming_port, 10044}) != 3:
            raise ValueError("web, streaming and nginx ports must differ")
        return self
