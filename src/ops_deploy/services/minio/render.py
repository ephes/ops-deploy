"""The unchanged role templates, with Ansible-compatible whitespace."""

from __future__ import annotations

from functools import cache
from typing import Any

import jinja2

from ops_deploy.services.minio.config import MinioConfig, MinioCredentials


@cache
def environment() -> jinja2.Environment:
    return jinja2.Environment(
        loader=jinja2.PackageLoader("ops_deploy.services.minio", "templates"),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
        autoescape=False,
    )


def render(template: str, cfg: MinioConfig, credentials: MinioCredentials, auth_hash: str = "") -> str:
    values: dict[str, Any] = {"minio_" + key: value for key, value in cfg.model_dump(mode="json").items()}
    root = credentials.root_password.get_secret_value()
    values.update(
        minio_root_user=credentials.root_user.get_secret_value(),
        minio_root_password=root,
        minio_sse_master_key=credentials.sse_master_key.get_secret_value() if credentials.sse_master_key else "",
        minio_console_basic_auth_password_hash=auth_hash,
    )
    return environment().get_template(template).render(**values)
