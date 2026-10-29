"""Render the relay role's unmodified configuration resources."""

from __future__ import annotations

import re
from functools import cache
from pathlib import Path, PurePosixPath
from typing import Any, Literal

import jinja2

from ops_deploy.core.secrets import SecretValues
from ops_deploy.services.mail_relay.config import MailRelayConfig

# postsrsd 2.x serves Postfix over this socketmap socket (the package default).
# Postfix daemons run in the queue directory and cleanup is chrooted there, so
# main.cf names the socket relative to it.
POSTFIX_QUEUE_DIRECTORY = PurePosixPath("/var/spool/postfix")
SRS_SOCKET = POSTFIX_QUEUE_DIRECTORY / "srs"
SRS_SOCKETMAP_TABLE = "socketmap:unix:" + str(SRS_SOCKET.relative_to(POSTFIX_QUEUE_DIRECTORY))

PostsrsdMajor = Literal[1, 2]


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


def role_vars(cfg: MailRelayConfig, secrets: SecretValues, *, postsrsd_major: PostsrsdMajor = 1) -> dict[str, Any]:
    values = cfg.model_dump(mode="json", by_alias=True, exclude={"service_name", "user", "site_path", "secrets"})
    values.update(
        tls_cert=cfg.tls_cert or f"/etc/letsencrypt/live/{cfg.hostname}/fullchain.pem",
        tls_key=cfg.tls_key or f"/etc/letsencrypt/live/{cfg.hostname}/privkey.pem",
        srs_exclude_domains=cfg.srs_exclude_domains if cfg.srs_exclude_domains is not None else cfg.domains,
        sasl_password=secrets.get("sasl_password", ""),
        srs_secret=secrets.get("srs_secret", ""),
        # postsrsd 1.x: tcp: lookup tables; 2.x: socketmap: tables only.
        postsrsd_socketmap=postsrsd_major == 2,
        srs_socket=str(SRS_SOCKET),
        srs_socketmap_table=SRS_SOCKETMAP_TABLE,
    )
    return {"mail_relay_" + key: value for key, value in values.items()}


def render_role(
    template: str, cfg: MailRelayConfig, secrets: SecretValues, *, postsrsd_major: PostsrsdMajor = 1
) -> str:
    return environment().get_template(template).render(**role_vars(cfg, secrets, postsrsd_major=postsrsd_major))
