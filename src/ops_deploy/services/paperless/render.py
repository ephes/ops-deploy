"""Original Paperless templates with Ansible-compatible whitespace/values."""

from __future__ import annotations

from functools import cache
from typing import Any

import jinja2

from .config import PaperlessConfig, PaperlessCredentials, validate_credentials


@cache
def environment() -> jinja2.Environment:
    return jinja2.Environment(
        loader=jinja2.PackageLoader("ops_deploy.services.paperless", "templates"),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
        autoescape=False,
    )


def role_values(cfg: PaperlessConfig, credentials: PaperlessCredentials) -> dict[str, Any]:
    """Return only the original template namespace; never log this secret map."""
    validate_credentials(cfg, credentials)
    values: dict[str, Any] = {"paperless_" + key: value for key, value in cfg.model_dump(mode="python").items()}
    values.update({"paperless_" + key: value.get_secret_value() for key, value in credentials})
    site = cfg.site_root
    current = f"{site}/paperless-ngx"
    virtualenv = f"{site}/.venv"
    host = f"paperless.{cfg.traefik_domain}"
    values.update(
        paperless_virtualenv=virtualenv,
        paperless_python_bin=f"{virtualenv}/bin/python",
        paperless_python_major_minor=cfg.python_version,
        paperless_manage_dir=f"{current}/src",
        paperless_current_symlink=current,
        paperless_env_file=f"{site}/.env",
        paperless_traefik_host=host,
        paperless_url=f"https://{host}",
        paperless_allowed_hosts=f"{host},localhost,127.0.0.1",
        paperless_cors_allowed_hosts=f"https://{host}",
        paperless_force_script_name="",
        paperless_static_url="/static/",
        paperless_db_options=f"sslmode={cfg.postgres_sslmode}",
        paperless_trusted_proxies="127.0.0.1",
        paperless_logrotate_max_size="10485760",
        paperless_logrotate_max_backups=5,
    )
    for name in ("media", "data", "consume", "export", "backup", "tmp"):
        values["paperless_" + name + "_path"] = f"{cfg.external_storage_root}/{name}"
    return values


def render(template: str, cfg: PaperlessConfig, credentials: PaperlessCredentials) -> str:
    return environment().get_template(template).render(**role_values(cfg, credentials))
