"""The canonical file set: ``.env``, launchers, units, Traefik route and fish config.

Every site gets the same files (``docs/services/django_site.md`` lists them
and how they differ from the Ansible roles' files). All of them are rendered
on the controller before the deploy connects anywhere, so a bad value fails
the run before any change.
"""

from __future__ import annotations

from functools import cache
from pathlib import PurePosixPath
from urllib.parse import quote

import jinja2

from ops_deploy.core.secrets import MissingSecretKeysError, SecretContent, SecretValues
from ops_deploy.services.django_site.config import (
    DjangoSiteConfig,
    EnvValue,
    Joined,
    PathSecrets,
    PostgresDb,
    Secret,
    env_value_problem,
)

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


def render(template: str, cfg: DjangoSiteConfig, **context: object) -> str:
    return (
        _templates()
        .get_template(template)
        .render(
            cfg=cfg,
            managed=MANAGED,
            writable=writable_paths(cfg),
            next_rule=next_rule(cfg, cfg.route.host_rule),
            next_tls_rule=next_rule(cfg, cfg.route.tls_host_rule or cfg.route.host_rule),
            **context,
        )
    )


def writable_paths(cfg: DjangoSiteConfig) -> list[str]:
    """``ReadWritePaths=`` of the hardened units: the site, the cache, and data kept outside the site.

    A data directory inside another one outside the site (media under a data
    directory) is covered by it and not repeated.
    """

    paths = [cfg.site_path, cfg.cache_dir]
    outside: list[PurePosixPath] = []
    for path in cfg.outside_dirs:
        if not any(path.is_relative_to(other) for other in outside):
            outside.append(path)
    return list(dict.fromkeys(str(p) for p in (*paths, *outside)))


def next_rule(cfg: DjangoSiteConfig, host_rule: str) -> str:
    """A frontend router's rule: the site router's host rule and the frontend's path prefixes."""

    if cfg.frontend is None:
        return ""
    grouped = f"({host_rule})" if "||" in host_rule else host_rule
    paths = " || ".join(f"Path(`{p}`) || PathPrefix(`{p}/`)" for p in cfg.frontend.path_prefixes)
    return f"{grouped} && ({paths})"


def check_secrets(cfg: DjangoSiteConfig, secrets: SecretValues) -> None:
    """Every referenced secret is set, single-line and no placeholder, and meets its own checks.

    Errors name keys only.
    """

    secrets.require(cfg.required_secret_keys)
    missing = sorted({ref.secret for ref in cfg.secret_refs if ref.secret not in secrets})
    if missing:
        raise MissingSecretKeysError(f"{secrets.ref} is missing referenced keys: {', '.join(missing)}")
    for ref in cfg.secret_refs:
        key = ref.secret
        value = secrets[key]
        if value.strip() in PLACEHOLDERS or "CHANGEME" in value:
            raise ValueError(f"secret {key} must be set and not a placeholder")
        if any(c in value for c in "\r\n\0"):
            raise ValueError(f"secret {key} must be a single line")
    for ref in cfg.secret_refs:
        if len(secrets[ref.secret]) < ref.min_length:
            raise ValueError(f"secret {ref.secret} must have at least {ref.min_length} characters")
        if ref.equals is not None and secrets[ref.secret] != ref.equals:
            raise ValueError(f"secret {ref.secret} must be the configured value")
    if cfg.env.url_paths is not None:
        _check_paths(cfg, cfg.env.url_paths, secrets)


def _slashed(path: str) -> str:
    return "/" + path.strip("/") + "/"


def _check_paths(cfg: DjangoSiteConfig, spec: PathSecrets, secrets: SecretValues) -> None:
    refused = {_slashed(p) for p in spec.refused}
    prefixes = cfg.frontend.path_prefixes if cfg.frontend else ()
    reserved = tuple(_slashed(p) for p in (*prefixes, *spec.reserved))
    seen: dict[str, str] = {}
    for ref in spec.secrets:
        key, value = ref.secret, secrets[ref.secret]
        if not value.strip("/") or not all(c.isascii() and (c.isalnum() or c in "._~/-") for c in value):
            raise ValueError(f"secret {key} must be a URL path (letters, digits and . _ ~ / -)")
        path = _slashed(value)
        if path in refused:
            raise ValueError(f"secret {key} must not be a refused path")
        if path.startswith(reserved):
            raise ValueError(f"secret {key} must not be under a reserved prefix")
        if path in seen:
            raise ValueError(f"secrets {seen[path]} and {key} must differ")
        seen[path] = key


def resolve(value: EnvValue, secrets: SecretValues) -> str:
    if isinstance(value, Joined):
        return "".join(resolve(part, secrets) for part in value.parts)
    if isinstance(value, Secret):
        return secrets[value.secret].strip(value.strip) if value.strip else secrets[value.secret]
    return value


def render_env(cfg: DjangoSiteConfig, secrets: SecretValues) -> SecretContent:
    """``.env``: one ``KEY='value'`` line per entry, after a header comment."""

    check_secrets(cfg, secrets)
    lines = [f"# {MANAGED}"]
    if isinstance(cfg.database, PostgresDb):
        db = cfg.database
        password = resolve(db.password, secrets)
        if not password.isascii():
            raise ValueError("PostgreSQL password must be ASCII")
        url = f"postgres://{db.user}:{quote(password, safe='')}@{db.host}:{db.port}/{db.name}"
        lines.append(f"DATABASE_URL='{url}'")
    omit = {e.key for e in cfg.env.extra if e.omit_empty}
    for key, value in cfg.env_entries_unresolved():
        text = resolve(value, secrets)
        if not text and key in omit:
            continue
        problem = env_value_problem(text)
        if problem:
            source = f"secret {value.secret}" if isinstance(value, Secret) else "value"
            raise ValueError(f"{source} for {key} {problem}")
        lines.append(f"{key}='{text}'")
    return SecretContent("".join(f"{line}\n" for line in lines))
