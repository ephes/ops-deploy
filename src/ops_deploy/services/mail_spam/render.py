"""Render the spam role's unmodified configuration resources."""

from __future__ import annotations

import json
import re
from functools import cache
from pathlib import Path
from typing import Any

import jinja2

from ops_deploy.core.secrets import SecretValues
from ops_deploy.services.mail_spam.config import MailSpamConfig


@cache
def environment() -> jinja2.Environment:
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(Path(__file__).parent / "templates"),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
        autoescape=False,
    )
    env.filters["regex_escape"] = re.escape
    env.filters["to_json"] = json.dumps
    return env


def role_vars(cfg: MailSpamConfig, secrets: SecretValues, *, web_password_hash: str = "") -> dict[str, Any]:
    values = cfg.model_dump(mode="json", exclude={"service_name", "user", "site_path", "secrets"})
    values.update(
        monitoring_probe=cfg.monitoring_probe.model_dump() if cfg.monitoring_probe else {},
        milter_socket=cfg.milter_socket or f"{cfg.milter_socket_dir}/{cfg.milter_socket_name}",
        milter_socket_postfix=cfg.milter_socket_postfix or f"rspamd/{cfg.milter_socket_name}",
        redis_password=secrets.get("redis_password", ""),
        web_password_hash=web_password_hash,
    )
    return {"mail_spam_" + key: value for key, value in values.items()}


def render_role(template: str, cfg: MailSpamConfig, secrets: SecretValues, *, web_password_hash: str = "") -> str:
    return environment().get_template(template).render(**role_vars(cfg, secrets, web_password_hash=web_password_hash))
