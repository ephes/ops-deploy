"""static_site files are byte-identical to the static_site_deploy role's output.

The role templates are vendored under ``tests/parity/ansible`` (checked against
ops-library by ``test_traefik_parity.test_vendored_templates_match_ops_library``)
and rendered the way Ansible's ``template`` module does. Identical bytes mean
switching a host between Ansible and ops-deploy rewrites nothing and restarts
nothing.
"""

import json
from pathlib import Path
from typing import Any

import jinja2
import pytest

from ops_deploy.services.static_site import StaticSiteConfig
from ops_deploy.services.static_site.deploy import render_route, render_server, render_unit
from tests.static_site_fixtures import make_source

VENDORED = Path(__file__).parent / "parity" / "ansible"


def render_ansible(template: str, variables: dict[str, Any]) -> str:
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(VENDORED),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters["to_json"] = json.dumps
    return env.get_template(f"static_site_deploy__{template}").render(**variables)


def role_vars(cfg: StaticSiteConfig) -> dict[str, Any]:
    return {
        "static_site_service_name": cfg.service_name,
        "static_site_user": cfg.user,
        "static_site_group": cfg.group_name,
        "static_site_path": str(cfg.site_path),
        "static_site_python_path": str(cfg.python_path),
        "static_site_server_path": str(cfg.server_path),
        "static_site_bind_host": cfg.bind_host,
        "static_site_port": cfg.port,
        "static_site_host": cfg.traefik_host,
        "static_site_traefik_entrypoints": list(cfg.traefik_entrypoints),
        "static_site_traefik_http_entrypoint": cfg.traefik_http_entrypoint,
        "static_site_traefik_cert_resolver": cfg.traefik_cert_resolver,
        "static_site_traefik_allowed_networks": list(cfg.traefik_allowed_networks),
    }


VARIANTS: dict[str, dict[str, Any]] = {
    "defaults": {},
    "benchmarks": {
        "service_name": "benchmarks-static",
        "port": 10061,
        "traefik_cert_resolver": "letsencrypt",
        "restrict_to_required_files": True,
    },
    "allowlist": {"traefik_allowed_networks": ("10.0.0.0/8", "fd7a:115c:a1e0::/48"), "private": True},
    "other group and entrypoints": {
        "group": "web-readers",
        "traefik_entrypoints": ("web-secure", "alt"),
        "traefik_http_entrypoint": "plain",
        "python_path": "/usr/local/bin/python3",
        "server_path": "/opt/bin/site.py",
        "site_path": "/srv/x/site",
    },
}


def make(tmp_path: Path, **overrides: Any) -> StaticSiteConfig:
    return StaticSiteConfig(source_path=make_source(tmp_path), traefik_host="static.test.example", **overrides)


@pytest.mark.parametrize("name", VARIANTS)
def test_unit_parity(tmp_path: Path, name: str) -> None:
    cfg = make(tmp_path, **VARIANTS[name])

    assert render_unit(cfg) == render_ansible("static-site.service.j2", role_vars(cfg))


@pytest.mark.parametrize("name", VARIANTS)
def test_server_script_parity(tmp_path: Path, name: str) -> None:
    cfg = make(tmp_path, **VARIANTS[name])

    assert render_server(cfg) == render_ansible("static-site-httpd.py.j2", role_vars(cfg))


@pytest.mark.parametrize("name", VARIANTS)
def test_route_parity(tmp_path: Path, name: str) -> None:
    cfg = make(tmp_path, **VARIANTS[name])

    assert render_route(cfg) == render_ansible("static-site.traefik.yml.j2", role_vars(cfg))
