"""Explicit retirement of listed MinIO users; never part of normal MinIO deployment."""

from __future__ import annotations

import base64
import json
import re
import shlex
from collections.abc import Generator
from importlib.resources import files as resources
from pathlib import PurePosixPath
from typing import Annotated, Literal, Self
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator
from pyinfra.api import DeployError, StringCommand, deploy, operation

from ops_deploy.base._common import AbsolutePath, RoleConfig, require_linux
from ops_deploy.helpers import mark_read_only
from ops_deploy.helpers.probes import StdinLines, probe

from .config import Name

RESOURCE = resources("ops_deploy.services.minio")

# A MinIO access key has at least 3 characters; the first one keeps it from reading as an mc flag.
UserName = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,62}$")]
REASON = re.compile(r"[A-Za-z0-9 ,;.'-]{1,200}")


class MinioUserRetirementConfig(RoleConfig):
    mc_bin_path: AbsolutePath = "/usr/local/bin/mc"
    alias: Name = "local"
    endpoint: str = "http://127.0.0.1:9001"
    users: tuple[UserName, ...] = Field(min_length=1)
    protected: tuple[UserName, ...] = ()

    @model_validator(mode="after")
    def bounded(self) -> Self:
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
            raise ValueError("user retirement requires a credential-free server endpoint")
        path = self.mc_bin_path
        if str(PurePosixPath(path)) != path or path == "/" or ".." in PurePosixPath(path).parts:
            raise ValueError("user retirement client path must be canonical and below root")
        if len(set(self.users)) != len(self.users):
            raise ValueError("user retirement list has duplicates")
        if set(self.users) & set(self.protected):
            raise ValueError("user retirement refuses a protected user")
        return self


class MinioUserRetirementCredentials(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)
    root_user: SecretStr
    root_password: SecretStr
    # Access keys the caller keeps secret and must never retire; compared, not named.
    protected_access: tuple[SecretStr, ...] = ()

    @field_validator("root_user", "root_password", "protected_access")
    @classmethod
    def nonempty(cls, value: SecretStr | tuple[SecretStr, ...]) -> SecretStr | tuple[SecretStr, ...]:
        for item in (value,) if isinstance(value, SecretStr) else value:
            raw = item.get_secret_value()
            if not raw or raw == "CHANGEME" or any(ord(char) < 32 or ord(char) == 127 for char in raw):
                raise ValueError("retirement credentials must be non-placeholder printable values")
        return value


def host_command(action: Literal["check", "apply", "verify"]) -> str:
    # Reuse the qualified parser/client without executing its normal IAM main.
    common = base64.b64encode(RESOURCE.joinpath("files/iam_host.py").read_bytes()).decode()
    retirement = base64.b64encode(RESOURCE.joinpath("files/user_retirement.py").read_bytes()).decode()
    source = (
        "import base64;scope={'__name__':'minio_user_retirement'};"
        f"exec(compile(base64.b64decode('{common}'),'<minio-client>','exec'),scope);"
        f"exec(compile(base64.b64decode('{retirement}'),'<minio-user-retirement>','exec'),scope);"
        "scope['retirement_main']()"
    )
    return shlex.join(["python3", "-I", "-B", "-c", source, action])


def refuse_protected(cfg: MinioUserRetirementConfig, credentials: MinioUserRetirementCredentials) -> None:
    secret = {credentials.root_user.get_secret_value()}
    secret.update(item.get_secret_value() for item in credentials.protected_access)
    if secret & set(cfg.users):
        raise DeployError("MinIO user retirement refused: a listed user is protected")


def payload(cfg: MinioUserRetirementConfig, credentials: MinioUserRetirementCredentials) -> SecretStr:
    return SecretStr(
        json.dumps(
            {
                "mc": cfg.mc_bin_path,
                "alias": cfg.alias,
                "endpoint": cfg.endpoint,
                "users": list(cfg.users),
                "protected": [*cfg.protected, *(item.get_secret_value() for item in credentials.protected_access)],
                "root_user": credentials.root_user.get_secret_value(),
                "root_password": credentials.root_password.get_secret_value(),
            }
        )
    )


def pending(secret: SecretStr) -> bool:
    result = probe(host_command("check"), stdin=secret.get_secret_value(), name="MinIO listed user inspection")
    try:
        value = json.loads(result or "")
        if set(value) == {"pending"} and type(value["pending"]) is bool:
            return bool(value["pending"])
        refused = value["refused"] if set(value) == {"refused"} else None
    except (ValueError, TypeError, KeyError):
        refused = None
    if isinstance(refused, str) and REASON.fullmatch(refused):
        raise DeployError(f"MinIO user retirement refused: {refused}")
    raise DeployError("Cannot prove listed MinIO user state; refusing retirement")


@operation()
def remove_listed_users(secret: SecretStr) -> Generator[StringCommand, None, None]:
    if pending(secret):
        yield StringCommand(host_command("apply"), _stdin=StdinLines(secret.get_secret_value()), _get_pty=False)


@operation()
def verify_absent(secret: SecretStr) -> Generator[StringCommand, None, None]:
    yield StringCommand(host_command("verify"), _stdin=StdinLines(secret.get_secret_value()), _get_pty=False)


@deploy("Retire listed MinIO users")
def retire_minio_users(cfg: MinioUserRetirementConfig, credentials: MinioUserRetirementCredentials) -> None:
    require_linux("MinIO user retirement")
    refuse_protected(cfg, credentials)
    secret = payload(cfg, credentials)
    remove_listed_users(name="Remove listed MinIO users", secret=secret)
    # An already absent list still gets this execution-time proof, like a first removal.
    mark_read_only(verify_absent(name="Verify listed MinIO users absent", secret=secret))
