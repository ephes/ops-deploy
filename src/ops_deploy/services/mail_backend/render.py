"""Render the backend role's unmodified configuration resources."""

from __future__ import annotations

from functools import cache
from pathlib import Path
from typing import Any

import jinja2

from ops_deploy.core.secrets import SecretValues
from ops_deploy.services.mail_backend.config import MailBackendConfig


@cache
def environment() -> jinja2.Environment:
    return jinja2.Environment(
        loader=jinja2.FileSystemLoader(Path(__file__).parent / "templates"),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
        autoescape=False,
    )


def role_vars(cfg: MailBackendConfig, secrets: SecretValues) -> dict[str, Any]:
    values = cfg.model_dump(mode="json", exclude={"service_name", "user", "site_path", "secrets"})
    values.update(
        dovecot_mail_location=cfg.dovecot_mail_location or f"maildir:{cfg.vmail_path}/%d/%n",
        sieve_dir=cfg.sieve_dir or f"{cfg.vmail_path}/%d/%n/sieve",
        sieve_active=cfg.sieve_active or f"{cfg.vmail_path}/%d/%n/.dovecot.sieve",
        dkim_signing_domains=list(dict.fromkeys((*cfg.domains, *cfg.sender_only_domains))),
        required_aliases=[
            {**alias.model_dump(), "destination_localpart": alias.destination_localpart or cfg.initial_user}
            for alias in cfg.required_aliases
        ],
        postgres_password=secrets.get("postgres_password", ""),
        relay_password=secrets.get("relay_password", ""),
    )
    return {"mail_backend_" + key: value for key, value in values.items()}


def render_role(template: str, cfg: MailBackendConfig, secrets: SecretValues) -> str:
    return environment().get_template(template).render(**role_vars(cfg, secrets))
