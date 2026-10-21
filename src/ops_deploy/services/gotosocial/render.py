"""The role's four templates, rendered the way Ansible's ``template`` module renders them.

The templates are shipped unchanged (headers included), so ``config.yaml``, the
unit, the admin wrapper and the Traefik route are byte-identical to the role's
for the same inputs (``tests/test_gotosocial_parity.py`` compares them with
files rendered by Ansible itself). Ansible renders with ``trim_blocks``, strips
the template's final newline like Jinja2 does by default and then restores one
when the template ended in a newline and the result does not; ``config.yaml``
depends on that (``to_nice_yaml`` output already ends in a newline). The
filters the templates use (``combine``, ``to_nice_yaml``, ``bool``) behave as
Ansible's for the data a :class:`GotosocialConfig` can hold.
"""

from __future__ import annotations

from collections.abc import Mapping
from functools import cache
from typing import Any

import jinja2
import yaml
from pydantic import SecretStr

from ops_deploy.core.secrets import SecretContent
from ops_deploy.services.gotosocial.config import GotosocialConfig

PACKAGE = "ops_deploy.services.gotosocial"
# Ansible's AnsibleDumper derives from libyaml's CSafeDumper when available.
_DUMPER: Any = getattr(yaml, "CSafeDumper", yaml.SafeDumper)


def combine(*terms: Mapping[str, Any], recursive: bool = False) -> dict[str, Any]:
    """Ansible's ``combine`` (``list_merge='replace'``): later mappings win, nested ones merge when recursive."""

    def merge(base: Mapping[str, Any], other: Mapping[str, Any]) -> dict[str, Any]:
        result = dict(base)
        for key, value in other.items():
            if recursive and isinstance(result.get(key), Mapping) and isinstance(value, Mapping):
                result[key] = merge(result[key], value)
            else:
                result[key] = value
        return result

    combined: dict[str, Any] = {}
    for term in terms:
        combined = merge(combined, term)
    return combined


def to_nice_yaml(data: Any, indent: int = 4, **kwargs: Any) -> str:
    """Ansible's ``to_nice_yaml``: block-style YAML through the safe dumper."""

    return str(yaml.dump(data, Dumper=_DUMPER, indent=indent, allow_unicode=True, default_flow_style=False, **kwargs))


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
    env.filters["combine"] = combine
    env.filters["to_nice_yaml"] = to_nice_yaml
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


def role_vars(cfg: GotosocialConfig, smtp_password: str = "") -> dict[str, Any]:
    """The role variables the templates read, derived as ``defaults/main.yml`` derives them."""

    return {
        "gotosocial_user": cfg.user,
        "gotosocial_group": cfg.group,
        "gotosocial_current_link": cfg.current_link,
        "gotosocial_config_path": cfg.config_path,
        "gotosocial_data_dir": cfg.data_dir,
        "gotosocial_db_path": cfg.db_path,
        "gotosocial_storage_dir": cfg.storage_dir,
        "gotosocial_cache_dir": cfg.cache_dir,
        "gotosocial_service_name": cfg.service_name,
        "gotosocial_host": cfg.host,
        "gotosocial_account_domain": cfg.account_domain,
        "gotosocial_bind_address": cfg.bind_address,
        "gotosocial_port": cfg.port,
        "gotosocial_trusted_proxies": list(cfg.trusted_proxies),
        "gotosocial_application_name": cfg.application_name,
        "gotosocial_landing_page_user": cfg.landing_page_user,
        "gotosocial_instance_languages": list(cfg.instance_languages),
        "gotosocial_accounts_registration_open": cfg.accounts_registration_open,
        "gotosocial_instance_expose_public_timeline": cfg.instance_expose_public_timeline,
        "gotosocial_instance_robots_allow_indexing": cfg.instance_robots_allow_indexing,
        "gotosocial_media_remote_cache_duration": cfg.media_remote_cache_duration,
        "gotosocial_cache_memory_target": cfg.cache_memory_target,
        "gotosocial_log_level": cfg.log_level,
        "gotosocial_log_client_ip": cfg.log_client_ip,
        "gotosocial_smtp_host": cfg.smtp_host,
        "gotosocial_smtp_port": cfg.smtp_port,
        "gotosocial_smtp_username": cfg.smtp_username,
        "gotosocial_smtp_password": smtp_password,
        "gotosocial_smtp_from": cfg.smtp_from,
        "gotosocial_extra_config": cfg.extra_config,
        "gotosocial_systemd_memory_max": cfg.systemd_memory_max,
        "gotosocial_traefik_host": cfg.route_host,
        "gotosocial_traefik_entrypoints": list(cfg.traefik_entrypoints),
        "gotosocial_traefik_http_entrypoint": cfg.traefik_http_entrypoint,
        "gotosocial_traefik_cert_resolver": cfg.traefik_cert_resolver,
        "gotosocial_traefik_middlewares": list(cfg.traefik_middlewares),
    }


def render_config(cfg: GotosocialConfig, smtp_password: SecretStr | None = None) -> SecretContent:
    """``config.yaml`` (it carries the SMTP password when one is set)."""

    password = smtp_password.get_secret_value() if smtp_password is not None else ""
    return SecretContent(render_template("config.yaml.j2", role_vars(cfg, password)))


def render_unit(cfg: GotosocialConfig) -> str:
    return render_template("gotosocial.service.j2", role_vars(cfg))


def render_admin_wrapper(cfg: GotosocialConfig) -> str:
    return render_template("gotosocial-admin.sh.j2", role_vars(cfg))


def render_route(cfg: GotosocialConfig) -> str:
    return render_template("traefik.yml.j2", role_vars(cfg))
