"""Explicit named-policy maintenance; never part of normal MinIO deployment."""

from __future__ import annotations

import base64
import json
import shlex
from collections.abc import Generator
from importlib.resources import files as resources
from pathlib import PurePosixPath
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, SecretStr, field_validator, model_validator
from pyinfra.api import DeployError, StringCommand, deploy, operation
from pyinfra.operations import files

from ops_deploy.base._common import AbsolutePath, RoleConfig, require_linux
from ops_deploy.helpers import mark_read_only
from ops_deploy.helpers.probes import StdinLines, probe

from .config import Name

RESOURCE = resources("ops_deploy.services.minio")


class MinioPolicyRollbackConfig(RoleConfig):
    mc_bin_path: AbsolutePath = "/usr/local/bin/mc"
    alias: Name = "local"
    endpoint: str = "http://127.0.0.1:9001"
    policy: Name
    policy_dir: AbsolutePath = "/etc/minio/policies"

    @model_validator(mode="after")
    def bounded_paths(self) -> Self:
        from urllib.parse import urlsplit

        endpoint = urlsplit(self.endpoint)
        if (
            endpoint.scheme not in {"http", "https"}
            or not endpoint.hostname
            or endpoint.username is not None
            or endpoint.password is not None
            or endpoint.path not in {"", "/"}
            or endpoint.query
            or endpoint.fragment
            or any(ord(char) < 32 or ord(char) == 127 for char in self.endpoint)
        ):
            raise ValueError("policy rollback requires a credential-free server endpoint")
        for path in (self.mc_bin_path, self.policy_dir):
            if str(PurePosixPath(path)) != path or path == "/" or ".." in PurePosixPath(path).parts:
                raise ValueError("policy rollback paths must be canonical and below root")
        return self

    @property
    def policy_file(self) -> str:
        return f"{self.policy_dir}/{self.policy}.json"


class MinioPolicyRollbackCredentials(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)
    root_user: SecretStr
    root_password: SecretStr
    access: SecretStr

    @field_validator("root_user", "root_password", "access")
    @classmethod
    def nonempty(cls, value: SecretStr) -> SecretStr:
        raw = value.get_secret_value()
        if not raw or raw == "CHANGEME" or any(ord(char) < 32 or ord(char) == 127 for char in raw):
            raise ValueError("rollback credentials must be non-placeholder printable values")
        return value


def host_command(action: Literal["check", "apply", "verify"]) -> str:
    # Reuse the qualified parser/client without executing its normal IAM main.
    common = base64.b64encode(RESOURCE.joinpath("files/iam_host.py").read_bytes()).decode()
    rollback = base64.b64encode(RESOURCE.joinpath("files/policy_rollback.py").read_bytes()).decode()
    source = (
        "import base64;scope={'__name__':'minio_policy_rollback'};"
        f"exec(compile(base64.b64decode('{common}'),'<minio-client>','exec'),scope);"
        f"exec(compile(base64.b64decode('{rollback}'),'<minio-policy-rollback>','exec'),scope);"
        "scope['rollback_main']()"
    )
    return shlex.join(["python3", "-I", "-B", "-c", source, action])


def payload(cfg: MinioPolicyRollbackConfig, credentials: MinioPolicyRollbackCredentials) -> SecretStr:
    return SecretStr(
        json.dumps(
            {
                "mc": cfg.mc_bin_path,
                "alias": cfg.alias,
                "endpoint": cfg.endpoint,
                "policy": cfg.policy,
                "root_user": credentials.root_user.get_secret_value(),
                "root_password": credentials.root_password.get_secret_value(),
                "access": credentials.access.get_secret_value(),
            }
        )
    )


def pending(secret: SecretStr) -> bool:
    result = probe(host_command("check"), stdin=secret.get_secret_value(), name="MinIO named policy inspection")
    try:
        value = json.loads(result or "")
        if set(value) != {"pending"} or type(value["pending"]) is not bool:
            raise ValueError
        return bool(value["pending"])
    except (ValueError, TypeError, KeyError):
        raise DeployError("Cannot prove named MinIO policy state; refusing rollback") from None


@operation()
def retire_policy(secret: SecretStr) -> Generator[StringCommand, None, None]:
    if pending(secret):
        yield StringCommand(host_command("apply"), _stdin=StdinLines(secret.get_secret_value()), _get_pty=False)


@operation()
def verify_absent(secret: SecretStr) -> Generator[StringCommand, None, None]:
    yield StringCommand(host_command("verify"), _stdin=StdinLines(secret.get_secret_value()), _get_pty=False)


@deploy("Roll back named MinIO policy")
def rollback_minio_policy(cfg: MinioPolicyRollbackConfig, credentials: MinioPolicyRollbackCredentials) -> None:
    require_linux("MinIO named policy rollback")
    secret = payload(cfg, credentials)
    retire_policy(name="Detach declared identity and remove named MinIO policy", secret=secret)
    # Retain the original independent final absence proof, including when the
    # first inspection was already absent. A stale planning-time absence does
    # not bypass this execution-time proof before removing the local file.
    mark_read_only(verify_absent(name="Verify named MinIO policy absent", secret=secret))
    files.directory(
        name="Remove named MinIO policy document", path=cfg.policy_file, present=False, force=True, force_backup=False
    )
