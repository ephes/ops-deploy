"""The role's templates, rendered the way Ansible's ``template`` module renders them.

The five templates (``bind_macros.j2`` included) are shipped unchanged, so
``named.conf``, ``named.conf.options``, ``named.conf.local`` and
``named.conf.keys`` are byte-identical to the role's for the same inputs
(``tests/test_infra_bind_parity.py`` compares them with files Ansible itself
rendered). Ansible renders with ``trim_blocks``, strips the final newline like
Jinja2 does by default and restores one when the template ended in a newline.
The only Ansible filter the templates use is ``bool``.
"""

from __future__ import annotations

from collections.abc import Mapping
from functools import cache
from typing import Any

import jinja2
from pydantic import SecretStr

from ops_deploy.core.secrets import SecretContent
from ops_deploy.infra.bind.config import AclList, BindConfig, BindZone

PACKAGE = "ops_deploy.infra.bind"


def ansible_bool(value: Any) -> bool:
    """Ansible's ``bool`` filter for booleans and the usual strings."""

    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("yes", "on", "1", "true")


@cache
def _environment() -> jinja2.Environment:
    env = jinja2.Environment(
        loader=jinja2.PackageLoader(PACKAGE, "templates"),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=False,
        autoescape=False,
    )
    env.filters["bool"] = ansible_bool
    return env


def render_template(name: str, variables: Mapping[str, Any]) -> str:
    env = _environment()
    assert env.loader is not None
    source = env.loader.get_source(env, name)[0]
    text = env.get_template(name).render(**variables)
    if source.endswith("\n") and not text.endswith("\n"):
        text += "\n"
    return text


def _acl(value: AclList) -> str | list[str]:
    return value if isinstance(value, str) else list(value)


def _zone(zone: BindZone) -> dict[str, Any]:
    """The zone entry as the role sees it: only the keys that are set."""

    entry: dict[str, Any] = {"name": zone.name, "file": zone.file}
    if zone.type is not None:
        entry["type"] = zone.type
    if zone.dynamic is not None:
        entry["dynamic"] = zone.dynamic
    for key in ("primaries", "update_policy", "allow_transfer"):
        value = getattr(zone, key)
        if value is not None:
            entry[key] = _acl(value)
    if zone.extra_config is not None:
        entry["extra_config"] = list(zone.extra_config)
    return entry


def role_vars(cfg: BindConfig, builtin_zones_file: str, secrets: Mapping[str, str] | None = None) -> dict[str, Any]:
    """The role variables the templates read; key secrets only when ``secrets`` is given."""

    return {
        "bind_config_dir": cfg.config_dir,
        "bind_working_dir": cfg.working_dir,
        "bind_dynamic_zone_dir": cfg.dynamic_zone_dir,
        "bind_builtin_zones_file": builtin_zones_file,
        "bind_zone_default_type": cfg.zone_default_type,
        "bind_zone_transfer_backed_types": list(cfg.zone_transfer_backed_types),
        "bind_zones": [_zone(zone) for zone in cfg.zones],
        "bind_recursion": cfg.recursion,
        "bind_recursion_acl": list(cfg.recursion_acl),
        "bind_allow_query": _acl(cfg.allow_query),
        "bind_allow_query_cache": _acl(cfg.query_cache_acl),
        "bind_allow_transfer": _acl(cfg.allow_transfer),
        "bind_dnssec_validation": cfg.dnssec_validation,
        "bind_listen_on": _acl(cfg.listen_on),
        "bind_listen_on_v6": _acl(cfg.listen_on_v6),
        "bind_extra_options": list(cfg.extra_options),
        "bind_tsig_keys_file": cfg.keys_file,
        "bind_tsig_keys": [
            {"name": key.name, "algorithm": key.algorithm, "secret": (secrets or {}).get(key.name, "")}
            for key in cfg.tsig_keys
        ],
    }


def builtin_zones_file(cfg: BindConfig, distribution: str, major_version: int | None) -> str:
    """``bind_builtin_zones_file``: the role's default from Ansible's distribution facts."""

    if cfg.builtin_zones_file is not None:
        return cfg.builtin_zones_file
    debian13 = distribution == "Debian" and major_version is not None and major_version >= 13
    return f"{cfg.config_dir}/{'named.conf.root-hints' if debian13 else 'named.conf.default-zones'}"


def render_named_conf(cfg: BindConfig, builtin_zones_file: str) -> str:
    return render_template("named.conf.j2", role_vars(cfg, builtin_zones_file))


def render_options(cfg: BindConfig) -> str:
    return render_template("named.conf.options.j2", role_vars(cfg, ""))


def render_local(cfg: BindConfig) -> str:
    return render_template("named.conf.local.j2", role_vars(cfg, ""))


def keys_text(cfg: BindConfig, secrets: Mapping[str, SecretStr]) -> str:
    """``named.conf.keys`` as text, for the deploy's stdin request only (it holds the key material)."""

    plain = {name: secret.get_secret_value() for name, secret in secrets.items()}
    return render_template("named.conf.keys.j2", role_vars(cfg, "", plain))


def render_keys(cfg: BindConfig, secrets: Mapping[str, SecretStr]) -> SecretContent:
    """``named.conf.keys`` (the only file with key material)."""

    return SecretContent(keys_text(cfg, secrets))
