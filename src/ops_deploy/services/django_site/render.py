"""The canonical file set: ``.env``, launcher, unit, Traefik route and fish config.

Every site gets the same files (``docs/services/django_site.md`` lists them
and how they differ from the Ansible roles' files). All of them are rendered
on the controller before the deploy connects anywhere, so a bad value fails
the run before any change.
"""

from __future__ import annotations

from functools import cache

import jinja2

from ops_deploy.core.secrets import SecretContent, SecretValues
from ops_deploy.services.django_site.config import DjangoSiteConfig, EnvValue, Secret, env_value_problem

TEMPLATE_PACKAGE = "ops_deploy.services.django_site"
MANAGED = "Managed by ops-deploy (django_site). Local changes are overwritten by the next deploy."
# Values the role's asserts refuse in a secret.
PLACEHOLDERS = frozenset({"CHANGEME", "CHANGE_ME"})


@cache
def _templates() -> jinja2.Environment:
    return jinja2.Environment(
        loader=jinja2.PackageLoader(TEMPLATE_PACKAGE, "templates"),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
        autoescape=False,
    )


def render(template: str, cfg: DjangoSiteConfig) -> str:
    return _templates().get_template(template).render(cfg=cfg, managed=MANAGED, writable=writable_paths(cfg))


def writable_paths(cfg: DjangoSiteConfig) -> list[str]:
    """``ReadWritePaths=`` of the hardened unit: the site, the cache, and data kept outside the site."""

    paths = [cfg.site_path, cfg.cache_dir]
    paths += [p for p in (cfg.db_path.parent, cfg.media_root) if not p.is_relative_to(cfg.site_path)]
    return list(dict.fromkeys(str(p) for p in paths))


def check_secrets(cfg: DjangoSiteConfig, secrets: SecretValues) -> None:
    """Every referenced secret is set, single-line and no placeholder. Errors name keys only."""

    secrets.require(cfg.required_secret_keys)
    for key in cfg.required_secret_keys:
        value = secrets[key]
        if value.strip() in PLACEHOLDERS or "CHANGEME" in value:
            raise ValueError(f"secret {key} must be set and not a placeholder")
        if any(c in value for c in "\r\n\0"):
            raise ValueError(f"secret {key} must be a single line")


def resolve(value: EnvValue, secrets: SecretValues) -> str:
    return secrets[value.secret] if isinstance(value, Secret) else value


def render_env(cfg: DjangoSiteConfig, secrets: SecretValues) -> SecretContent:
    """``.env``: one ``KEY='value'`` line per entry, after a header comment."""

    check_secrets(cfg, secrets)
    lines = [f"# {MANAGED}"]
    for key, value in cfg.env_entries_unresolved():
        text = resolve(value, secrets)
        problem = env_value_problem(text)
        if problem:
            source = f"secret {value.secret}" if isinstance(value, Secret) else "value"
            raise ValueError(f"{source} for {key} {problem}")
        lines.append(f"{key}='{text}'")
    return SecretContent("".join(f"{line}\n" for line in lines))
