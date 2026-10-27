"""Render the relay role's unmodified configuration resources."""

from __future__ import annotations

import re
from functools import cache
from pathlib import Path
from typing import Any

import jinja2

from ops_deploy.core.secrets import SecretValues
from ops_deploy.services.mail_relay.config import MailRelayConfig


@cache
def environment() -> jinja2.Environment:
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(Path(__file__).parent / "templates"),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
        autoescape=False,
    )
    env.filters["regex_replace"] = lambda value, pattern, replacement: re.sub(pattern, replacement, value)
    return env


def role_vars(cfg: MailRelayConfig, secrets: SecretValues) -> dict[str, Any]:
    values = cfg.model_dump(mode="json", by_alias=True, exclude={"service_name", "user", "site_path", "secrets"})
    values.update(
        tls_cert=cfg.tls_cert or f"/etc/letsencrypt/live/{cfg.hostname}/fullchain.pem",
        tls_key=cfg.tls_key or f"/etc/letsencrypt/live/{cfg.hostname}/privkey.pem",
        srs_exclude_domains=cfg.srs_exclude_domains if cfg.srs_exclude_domains is not None else cfg.domains,
        sasl_password=secrets.get("sasl_password", ""),
        srs_secret=secrets.get("srs_secret", ""),
    )
    return {"mail_relay_" + key: value for key, value in values.items()}


def render_role(template: str, cfg: MailRelayConfig, secrets: SecretValues) -> str:
    return environment().get_template(template).render(**role_vars(cfg, secrets))
