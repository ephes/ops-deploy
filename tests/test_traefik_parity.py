"""Parity of ``traefik_route`` output with the Ansible roles' Traefik templates.

The role templates are vendored under ``tests/parity/ansible`` (named
``<role>__<template>``) and rendered with Jinja2 configured like Ansible's
``template`` module. Our output must match line for line once comments and
blank lines are dropped, and must parse to the same YAML. Comments differ on
purpose (the header names ops-deploy).
"""

import os
from pathlib import Path
from typing import Any

import jinja2
import pytest
import yaml
from pydantic import SecretStr

from ops_deploy.helpers.traefik import (
    DEFAULT_INTERNAL_IP_RANGES,
    BasicAuth,
    HealthCheck,
    RedirectRegex,
    TraefikRoute,
    render_route,
)

VENDORED = Path(__file__).parent / "parity" / "ansible"
HASH = "$2y$05$29Gfrp5dhiYLdDhT79roVeQM45oGC/gI9VBinrDYyO5ucrXoLooD6"
AUTH = BasicAuth(user="admin", password=SecretStr("fixture-password"))
HOST = "app.example.com"


def render_ansible(template: str, variables: dict[str, Any]) -> str:
    # ansible.builtin.template defaults: trim_blocks on, lstrip_blocks off.
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(VENDORED),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
    )
    return env.get_template(template).render(**variables)


def significant_lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]


def assert_parity(ours: str, ansible: str) -> None:
    assert significant_lines(ours) == significant_lines(ansible)
    assert yaml.safe_load(ours) == yaml.safe_load(ansible)


def nyxmon_vars(*, auth: bool, cert_resolver: str = "", middlewares: tuple[str, ...] = ()) -> dict[str, Any]:
    return {
        "nyxmon_basic_auth_enabled": auth,
        "nyxmon_traefik_host": HOST,
        "nyxmon_internal_ip_ranges": list(DEFAULT_INTERNAL_IP_RANGES),
        "nyxmon_traefik_middlewares": list(middlewares),
        "nyxmon_traefik_cert_resolver": cert_resolver,
        "nyxmon_basic_auth_user": "admin",
        "nyxmon_basic_auth_password_hash": HASH,
        "nyxmon_app_host": "127.0.0.1",
        "nyxmon_app_port": 10017,
    }


@pytest.mark.parametrize("auth", [True, False])
@pytest.mark.parametrize(("cert_resolver", "middlewares"), [("", ()), ("letsencrypt", ("ratelimit@file", "extra"))])
def test_nyxmon_template_parity(auth: bool, cert_resolver: str, middlewares: tuple[str, ...]) -> None:
    route = TraefikRoute(
        name="nyxmon",
        title="Nyxmon",
        host=HOST,
        app_port=10017,
        basic_auth=AUTH if auth else None,
        cert_resolver=cert_resolver,
        middlewares=middlewares,
    )

    ours = render_route(route, HASH if auth else None)
    ansible = render_ansible(
        "nyxmon_deploy__traefik-nyxmon.yml.j2",
        nyxmon_vars(auth=auth, cert_resolver=cert_resolver, middlewares=middlewares),
    )

    assert_parity(ours, ansible)


@pytest.mark.parametrize("auth", [True, False])
def test_fastdeploy_template_parity(auth: bool) -> None:
    route = TraefikRoute(
        name="fastdeploy",
        title="FastDeploy",
        host=HOST,
        app_port=9999,
        basic_auth=AUTH if auth else None,
        frame_options="SAMEORIGIN",
        redirect=RedirectRegex(regex="^(https?://[^/]+)/$", replacement="${1}/static/index.html"),
        health_check=HealthCheck(),
    )

    ours = render_route(route, HASH if auth else None)
    ansible = render_ansible(
        "fastdeploy_deploy__traefik.yml.j2",
        {
            "fastdeploy_basic_auth_enabled": auth,
            "fastdeploy_service_name": "fastdeploy",
            "fastdeploy_traefik_host": HOST,
            "fastdeploy_internal_ip_ranges": list(DEFAULT_INTERNAL_IP_RANGES),
            "fastdeploy_traefik_middlewares": [],
            "fastdeploy_traefik_cert_resolver": "",
            "fastdeploy_basic_auth_user": "admin",
            "fastdeploy_basic_auth_password_hash": HASH,
            "fastdeploy_app_host": "127.0.0.1",
            "fastdeploy_app_port": 9999,
        },
    )

    assert_parity(ours, ansible)


def test_rendered_route_ends_with_one_newline() -> None:
    ours = render_route(TraefikRoute(name="nyxmon", host=HOST, app_port=10017), None)

    assert ours.endswith('"\n')
    assert not ours.endswith("\n\n")


OPS_LIBRARY = os.environ.get("OPS_LIBRARY_PATH")


@pytest.mark.skipif(not OPS_LIBRARY, reason="OPS_LIBRARY_PATH not set")
@pytest.mark.parametrize("vendored", sorted(VENDORED.glob("*.j2")), ids=lambda p: p.name)
def test_vendored_templates_match_ops_library(vendored: Path) -> None:
    assert OPS_LIBRARY is not None
    role, template = vendored.name.split("__", 1)
    source = Path(OPS_LIBRARY) / "roles" / role / "templates" / template

    assert vendored.read_text() == source.read_text(), f"{source} changed; re-vendor and re-check parity"
