"""Strict MinIO role inputs; secret material is separate from public configuration."""

from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, SecretStr, StrictBool, StrictInt, field_validator, model_validator

from ops_deploy.base._common import AbsolutePath, RoleConfig
from ops_deploy.core.config import UnixUser
from ops_deploy.helpers.traefik import Hostname

Name = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")]
Port = Annotated[StrictInt, Field(ge=1, le=65535)]
MINIO_VERSION = "RELEASE.2025-10-15T17-29-55Z.hotfix.c392ab039"
MINIO_SHA256 = "2d88210a1e5750a5291d5af9c386a7f3d42c426f77c9446c0bad821b4f5391c4"
MC_VERSION = "RELEASE.2025-08-13T08-35-41Z"
MC_SHA256 = "01f866e9c5f9b87c2b09116fa5d7c06695b106242d829a8bb32990c00312e891"
MC_DOWNLOAD_URL = f"https://github.com/minio/mc/releases/download/{MC_VERSION}/mc.linux-amd64.{MC_VERSION}"


class MinioBucket(RoleConfig):
    name: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")]
    versioning: StrictBool = False
    policy: Literal["private", "readonly", "writeonly", "public"] = "private"


class MinioPolicy(RoleConfig):
    name: Name
    document: dict[str, Any]
    immutable: StrictBool = False
    # Optional role-exact JSON spelling for the managed on-disk policy file.
    content: str | None = None

    @model_validator(mode="after")
    def valid_document(self) -> Self:
        if self.document.get("Version") != "2012-10-17" or not isinstance(self.document.get("Statement"), list):
            raise ValueError("policy requires a 2012-10-17 document and Statement list")
        if self.content is not None and json.loads(self.content) != self.document:
            raise ValueError("policy file content must encode exactly the declared document")
        return self

    @property
    def file_content(self) -> str:
        return self.content if self.content is not None else json.dumps(self.document, indent=2) + "\n"


class MinioIdentity(RoleConfig):
    name: Name
    policies: tuple[Name, ...]
    exact: StrictBool = False
    # Read-only bucket stat, or a deliberately non-existent key under an owned
    # prefix for identities that cannot inspect their whole bucket.
    proof: Annotated[str, Field(min_length=3, pattern=r"^[^\x00-\x1f\x7f]+$")]

    @model_validator(mode="after")
    def safe_proof(self) -> Self:
        if not self.policies or len(set(self.policies)) != len(self.policies):
            raise ValueError("identity policies must be nonempty and unique")
        if self.proof.startswith(("/", "-")) or any(part in ("", ".", "..") for part in self.proof.split("/")):
            raise ValueError("proof must be a bucket or a key below its declared bucket")
        return self


class MinioSupersededPolicy(RoleConfig):
    name: Name
    identity: Name


class MinioConfig(RoleConfig):
    """Active role settings plus explicit private-play IAM declarations.

    Out of scope: role backup_account, config export, service-account bootstrap,
    custom bucket policies/lifecycle and removal. Those workflows remain with
    their original owners; they are not implicitly invoked by deployment.
    """

    user: UnixUser = "minio"
    group: UnixUser = "minio"
    home: AbsolutePath = "/home/minio"
    bin_path: AbsolutePath = "/usr/local/bin/minio"
    config_dir: AbsolutePath = "/etc/minio"
    env_file: AbsolutePath = "/etc/default/minio"
    service_unit: AbsolutePath = "/etc/systemd/system/minio.service"
    certs_dir: AbsolutePath = "/etc/minio/certs"
    data_dirs: tuple[AbsolutePath, ...] = ("/var/lib/minio/data",)
    bind_host: Literal["127.0.0.1"] = "127.0.0.1"
    api_port: Port = 9001
    console_port: Port = 9002
    expose_via_traefik: StrictBool = False
    traefik_host: Hostname = "minio.home.example.com"
    traefik_api_host: Hostname = "s3.minio.home.example.com"
    traefik_cert_resolver: Name | Literal[""] = ""
    traefik_config_path: Literal["/etc/traefik/dynamic/minio.yml"] = "/etc/traefik/dynamic/minio.yml"
    console_basic_auth_enabled: StrictBool = True
    console_basic_auth_user: Name = "admin"
    internal_ip_ranges: tuple[str, ...] = (
        "192.168.0.0/16",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "100.64.0.0/10",
        "fd7a:115c:a1e0::/48",
    )
    tls_enable: StrictBool = False
    sse_enabled: StrictBool = False
    bootstrap_with_mc: StrictBool = False
    mc_bin_path: AbsolutePath = "/usr/local/bin/mc"
    host_alias: Name = "local"
    mc_config_dir: AbsolutePath = "/root/.mc"
    policy_dir: AbsolutePath = "/etc/minio/policies"
    buckets: tuple[MinioBucket, ...] = ()
    policies: tuple[MinioPolicy, ...] = ()
    identities: tuple[MinioIdentity, ...] = ()
    superseded: tuple[MinioSupersededPolicy, ...] = ()
    systemd_restart: Literal["always", "on-failure", "on-success", "no"] = "always"
    systemd_memory_max: Annotated[str, Field(pattern=r"^([0-9]+[KMGT]?|infinity)?$")] = ""
    systemd_limit_nofile: Annotated[StrictInt, Field(ge=1)] = 65536
    systemd_tasks_max: Annotated[str, Field(pattern=r"^([0-9]+|infinity)$")] = "infinity"
    healthcheck_timeout: Annotated[StrictInt, Field(ge=1)] = 30
    # Explicit controller artifacts for owned fixtures/fresh install when the
    # declared upstream URLs no longer work. Exact pinned checksums still apply.
    local_minio_binary: Path | None = None
    local_mc_binary: Path | None = None

    @field_validator("internal_ip_ranges")
    @classmethod
    def valid_networks(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        import ipaddress

        for value in values:
            ipaddress.ip_network(value)
        return values

    @model_validator(mode="after")
    def contract(self) -> Self:
        paths = [value for value in self.model_dump().values() if isinstance(value, str) and value.startswith("/")]
        paths += list(self.data_dirs)
        if any(str(PurePosixPath(path)) != path or ".." in PurePosixPath(path).parts or path == "/" for path in paths):
            raise ValueError("paths must be canonical and below the filesystem root")
        if not self.data_dirs or len(set(self.data_dirs)) != len(self.data_dirs):
            raise ValueError("data roots must be nonempty and unique")
        if self.api_port == self.console_port:
            raise ValueError("API and console ports must differ")
        if not self.bootstrap_with_mc and (self.buckets or self.policies or self.identities or self.superseded):
            raise ValueError("IAM/bucket declarations require bootstrap_with_mc")
        for items in (self.buckets, self.policies, self.identities, self.superseded):
            names = [item.name for item in items]
            if len(names) != len(set(names)):
                raise ValueError("owned declarations must have unique names")
        policies = {item.name for item in self.policies}
        identities = {item.name for item in self.identities}
        if any(not set(item.policies) <= policies for item in self.identities):
            raise ValueError("identities may attach only declared policies")
        if any(item.identity not in identities or item.name in policies for item in self.superseded):
            raise ValueError("superseded policies must name a declared identity and differ from current policies")
        exact = {identity.name for identity in self.identities if identity.exact}
        if any(item.identity in exact for item in self.superseded):
            raise ValueError("superseded policy retirement requires an additive identity")
        return self


class MinioUserCredentials(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)
    access: SecretStr
    secret: SecretStr

    @field_validator("access", "secret")
    @classmethod
    def credential_lines(cls, value: SecretStr) -> SecretStr:
        raw = value.get_secret_value()
        if len(raw) < 3 or raw == "CHANGEME" or any(ord(char) < 32 or ord(char) == 127 for char in raw):
            raise ValueError("credential must be non-placeholder printable text")
        return value


class MinioCredentials(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)
    root_user: SecretStr
    root_password: SecretStr
    console_basic_auth_password: SecretStr | None = None
    tls_cert_content: SecretStr | None = None
    tls_key_content: SecretStr | None = None
    sse_master_key: SecretStr | None = None
    identities: dict[str, MinioUserCredentials] = Field(default_factory=dict)

    @field_validator("root_user", "root_password", "sse_master_key")
    @classmethod
    def environment_value(cls, value: SecretStr | None) -> SecretStr | None:
        if value is None:
            return None
        raw = value.get_secret_value()
        if not raw or raw == "CHANGEME" or any(char in raw for char in '\\"\n\r\x00'):
            raise ValueError(
                "environment credentials must be non-placeholder single-line values without quotes/backslashes"
            )
        return value
