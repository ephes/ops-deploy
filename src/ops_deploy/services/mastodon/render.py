"""Unmodified role templates with a restricted subset of role defaults."""

from __future__ import annotations

import json
import re
from importlib.resources import files
from typing import Any

import jinja2

from ops_deploy.core.secrets import SecretContent, SecretValues
from ops_deploy.services.mastodon.config import MastodonConfig

PACKAGE = "ops_deploy.services.mastodon"
SECRET_KEYS = (
    "secret_key_base",
    "otp_secret",
    "vapid_public_key",
    "vapid_private_key",
    "active_record_encryption_primary_key",
    "active_record_encryption_deterministic_key",
    "active_record_encryption_key_derivation_salt",
    "postgres_password",
    "smtp_password",
)


def environment() -> jinja2.Environment:
    env = jinja2.Environment(
        loader=jinja2.PackageLoader(PACKAGE, "templates"),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
        autoescape=False,
    )
    env.filters["bool"] = bool
    env.filters["ternary"] = lambda value, yes, no: yes if value else no
    env.filters["basename"] = lambda value: str(value).rsplit("/", 1)[-1]
    env.filters["regex_replace"] = lambda value, pattern, replacement: re.sub(pattern, replacement, value)
    return env


def role_vars(cfg: MastodonConfig, secrets: SecretValues | None = None) -> dict[str, Any]:
    values: dict[str, Any] = json.loads(files(PACKAGE).joinpath("templates/defaults.json").read_text())
    unresolved = {key for key, value in values.items() if isinstance(value, str) and "{{" in value}
    overrides = {"mastodon_" + key: value for key, value in cfg.model_dump().items()}
    values.update(overrides)
    unresolved -= overrides.keys()
    values.update(
        {
            "mastodon_ruby_version_effective": cfg.ruby_version,
            "mastodon_runtime_path": (
                f"{cfg.home_path}/.nvm/versions/node/v{cfg.node_version}/bin:"
                f"{cfg.home_path}/.rbenv/bin:{cfg.home_path}/.rbenv/shims:/usr/local/bin:/usr/bin:/bin"
            ),
        }
    )
    if secrets is not None:
        secrets.require(SECRET_KEYS)
        for key in SECRET_KEYS:
            value = secrets[key]
            if any(c in value for c in '\r\n\x00"\\$`') or value == "CHANGEME":
                raise ValueError(f"mastodon: {key} is not a supported literal environment value")
            values["mastodon_" + key] = value
    env = environment()
    # Resolve only expressions in the vendored defaults, never supplied strings.
    for _ in range(20):
        if not unresolved:
            return values
        for key in tuple(unresolved):
            value = env.from_string(values[key]).render(**values)
            values[key] = value
            if "{{" not in value:
                unresolved.remove(key)
    raise ValueError("mastodon: unresolved role defaults")


def render(cfg: MastodonConfig, template: str) -> str:
    return environment().get_template(template).render(**role_vars(cfg))


def render_env(cfg: MastodonConfig, secrets: SecretValues) -> SecretContent:
    return SecretContent(environment().get_template("mastodon.env.j2").render(**role_vars(cfg, secrets)))
