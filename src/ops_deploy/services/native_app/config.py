"""The release/TOML/custom-unit subset of native_app; no package manager hooks."""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Annotated, Literal, Self
from urllib.parse import urlsplit

from pydantic import Field, model_validator

from ops_deploy.base._common import Sha256
from ops_deploy.core.config import BaseServiceConfig, UnixUser
from ops_deploy.services.compose_app.config import (
    Directory,
    Label,
    Part,
    PlainPath,
    Route,
    Secret,
    UnitName,
    Word,
)


class Release(Part):
    """One pinned tar.gz member, installed atomically; adopt a matching existing version."""

    kind: Literal["release"] = "release"
    version: Annotated[str, Field(pattern=r"^[0-9]+(?:\.[0-9]+)+$")]
    url: str
    checksums: dict[Literal["x86_64", "aarch64"], Sha256] = Field(min_length=1)
    member: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.-]+$")]
    dest: PlainPath
    version_args: tuple[Word, ...] = ("--version",)
    insecure_reason: Label | None = None

    @model_validator(mode="after")
    def _url(self) -> Self:
        parsed = urlsplit(self.url.replace("{arch}", "amd64"))
        if parsed.scheme not in ("https", "http") or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("release URL must be HTTP(S) without credentials")
        if parsed.scheme == "http" and not self.insecure_reason:
            raise ValueError("HTTP release requires insecure_reason")
        if any(char in self.url for char in "\r\n\x00") or self.member in (".", ".."):
            raise ValueError("invalid release URL or archive member")
        return self


class Account(Part):
    name: UnixUser
    group: UnixUser
    home: PlainPath
    shell: PlainPath = PurePosixPath("/usr/sbin/nologin")


TomlScalar = str | int | float | bool
TomlData = dict[str, TomlScalar | dict[str, TomlScalar]]


class TomlFile(Part):
    path: PlainPath
    data: TomlData
    mode: Annotated[str, Field(pattern=r"^0?[0-7]{3,4}$")] = "0644"


class Unit(Part):
    name: UnitName
    description: Label
    user: UnixUser
    group: UnixUser
    working_directory: PlainPath
    exec_start: tuple[Word, ...] = Field(min_length=1)
    after: tuple[Annotated[str, Field(pattern=r"^[A-Za-z0-9@_.-]+$")], ...] = ("network-online.target",)
    environment: dict[Annotated[str, Field(pattern=r"^[A-Z_][A-Z0-9_]*$")], Word] = Field(default_factory=dict)
    nofile: int = Field(default=16384, ge=64)

    @model_validator(mode="after")
    def _executable(self) -> Self:
        if not self.exec_start[0].startswith("/"):
            raise ValueError("ExecStart requires an absolute executable")
        return self


class NativeRoute(Route):
    """The existing access model, extended with a remote backend for route-only apps."""

    backend_host: Annotated[str, Field(pattern=r"^[A-Za-z0-9.-]+$")] = "127.0.0.1"
    remote_reason: Label | None = None

    @model_validator(mode="after")
    def _remote(self) -> Self:
        user = self.basic_auth_user
        if isinstance(user, str) and not re.fullmatch(r"[A-Za-z0-9._@-]{1,64}", user):
            raise ValueError("basic auth username must be nonempty and valid")
        if self.backend_host != "127.0.0.1" and self.remote_reason is None:
            raise ValueError("remote backend requires remote_reason")
        return self


class NativeAppConfig(BaseServiceConfig):
    title: Label
    account: Account | None = None
    mounts_required: tuple[PlainPath, ...] = ()
    paths_required: tuple[PlainPath, ...] = ()
    directories: tuple[Directory, ...] = ()
    source: Release | None = None
    configs: tuple[TomlFile, ...] = ()
    unit: Unit | None = None
    binary_link: PlainPath | None = None
    route: NativeRoute | None = None
    listen_port: int | None = Field(default=None, ge=1, le=65535)
    health_url: str | None = None
    health_statuses: tuple[int, ...] = (200,)
    # Runtime prerequisites are checked, never installed by this subset.
    executables_required: tuple[PlainPath, ...] = ()

    @model_validator(mode="after")
    def _shape(self) -> Self:
        if self.unit is None:
            if (
                self.source
                or self.configs
                or self.account
                or self.directories
                or self.binary_link
                or self.health_url
                or self.listen_port
            ):
                raise ValueError("route-only config must not contain runtime parts")
            if self.route is None:
                raise ValueError("route-only config requires a route")
        elif self.account is None or self.unit.user != self.account.name or self.unit.group != self.account.group:
            raise ValueError("unit must use the declared account")
        if self.source is not None and (self.unit is None or self.unit.exec_start[0] != str(self.source.dest)):
            raise ValueError("release binary must be the unit executable")
        if (
            self.unit is not None
            and self.route is not None
            and (self.route.backend_host != "127.0.0.1" or self.route.port != self.listen_port)
        ):
            raise ValueError("runtime route must target its declared loopback listener")
        if self.binary_link is not None and self.source is None:
            raise ValueError("binary_link requires a release")
        paths = [str(c.path) for c in self.configs]
        if len(set(paths)) != len(paths):
            raise ValueError("config paths must be unique")
        if any(not re.match(r"^[A-Za-z0-9_.-]+$", key) for c in self.configs for key in c.data):
            raise ValueError("TOML keys must be plain names")
        if self.health_url is not None:
            if not re.fullmatch(r"http://[^\s\'\"$`\\]+", self.health_url):
                raise ValueError("invalid health URL")
            parsed = urlsplit(self.health_url)
            if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.username or parsed.password:
                raise ValueError("health_url must be loopback HTTP without credentials")
        if not self.health_statuses or any(not 100 <= code <= 599 for code in self.health_statuses):
            raise ValueError("health_statuses must contain HTTP statuses")
        return self

    @property
    def state_dir(self) -> PurePosixPath:
        return PurePosixPath("/var/lib/ops-deploy") / self.service_name

    @property
    def required_secret_keys(self) -> tuple[str, ...]:  # type: ignore[override]
        if self.route is None:
            return ()
        return tuple(
            dict.fromkeys(
                value.secret
                for value in (self.route.basic_auth_user, self.route.basic_auth_password)
                if isinstance(value, Secret)
            )
        )
