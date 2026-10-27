"""Unchanged authoritative role templates with explicit target-derived inputs."""

from __future__ import annotations

import json
import posixpath
from functools import cache
from typing import Any

import jinja2

from ops_deploy.services.dns.config import DnsConfig


@cache
def environment() -> jinja2.Environment:
    env = jinja2.Environment(
        loader=jinja2.PackageLoader("ops_deploy.services.dns", "templates"),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        autoescape=False,
    )
    env.filters.update(
        bool=bool,
        basename=posixpath.basename,
        flatten=lambda xs: [v for x in xs for v in (x if isinstance(x, list) else [x])],
        ternary=lambda value, yes, no: yes if value else no,
        to_nice_json=lambda value: json.dumps(value, indent=4, sort_keys=True, ensure_ascii=True),
    )
    env.tests["truthy"] = lambda value: bool(value)
    return env


def role_vars(cfg: DnsConfig, lan: str, tailscale: str, cpus: int) -> dict[str, Any]:
    result = {"dns_" + k: v for k, v in cfg.model_dump(mode="json").items()}
    result.update(
        ansible_processor_vcpus=cpus,
        dns_split_lan_ip=lan,
        dns_split_tailscale_ip=tailscale,
        dns_unbound_config_dir="/etc/unbound/unbound.conf.d",
        dns_unbound_blocklist_dir="/var/lib/unbound",
        dns_resolver_nameservers=["127.0.0.1", lan],
        dns_resolver_search_domains=[],
        dns_resolver_options=["edns0", "trust-ad"],
        dns_ddns_effective_providers=["rfc2136"],
        dns_ddns_config_dir="/etc/ddns",
        dns_ddns_state_dir="/var/lib/ddns",
        dns_ddns_status_path="/var/lib/ddns/status.json",
        dns_ddns_log_dir="/var/log/ddns",
        dns_ddns_script_path="/usr/local/bin/ddns-update",
        dns_ddns_gandi_api_base="https://api.gandi.net/v5/livedns",
    )
    if cfg.endpoint:
        e = cfg.endpoint
        result.update(
            dns_ddns_status_endpoint_bind=tailscale,
            dns_ddns_status_endpoint_port=e.port,
            dns_ddns_status_endpoint_path=e.path,
            dns_ddns_status_endpoint_server_path=str(e.server_path),
            dns_ddns_status_endpoint_htpasswd_path=str(e.htpasswd_path),
        )
    return result


def render(name: str, variables: dict[str, Any]) -> str:
    env = environment()
    assert env.loader is not None
    source = env.loader.get_source(env, name)[0]
    text = env.get_template(name).render(variables)
    return text + ("\n" if source.endswith("\n") and not text.endswith("\n") else "")


CONFIG_TEMPLATES = {
    "00-base.conf": "unbound-base-full.conf.j2",
    "05-forward-zones.conf": "unbound-forward-zones.conf.j2",
    "06-local-records.conf": "unbound-local-records.conf.j2",
    "10-split-dns.conf": "unbound-split-dns.conf.j2",
}


def configuration(cfg: DnsConfig, variables: dict[str, Any]) -> dict[str, str | None]:
    result: dict[str, str | None] = {
        "/etc/unbound/unbound.conf.d/" + target: render(template, variables)
        for target, template in CONFIG_TEMPLATES.items()
    }
    if not cfg.forward_zones:
        result["/etc/unbound/unbound.conf.d/05-forward-zones.conf"] = None
    if not cfg.local_records:
        result["/etc/unbound/unbound.conf.d/06-local-records.conf"] = None
    result["/var/lib/unbound/allowlist.conf"] = render("unbound-allowlist.conf.j2", variables)
    return result
