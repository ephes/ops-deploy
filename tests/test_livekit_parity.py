"""livekit against the ``livekit_deploy`` role (templates vendored under ``tests/parity/ansible``).

The route is byte-identical. The config files and the compose file are
compose_app's canonical renders, so they are compared as data: the same
YAML values, the same images (by tag; the port adds the digest), names,
network mode, privileges and mounts. The unit is compose_app's; its
differences are the documented ones.
"""

from __future__ import annotations

from typing import Any

import pytest
import yaml

from ops_deploy.core import SecretValues
from ops_deploy.services.compose_app.render import MANAGED, render_compose, render_config, render_unit
from ops_deploy.services.livekit import LivekitConfig, render_route
from tests.livekit_fixtures import livekit_config, render_ansible, role_vars, values


@pytest.fixture
def cfg() -> LivekitConfig:
    return livekit_config()


@pytest.fixture
def secrets(cfg: LivekitConfig) -> SecretValues:
    return values(cfg)


# ``roles/livekit_deploy/defaults/main.yml`` (ops-library 49d2f16; tests/test_ops_library_drift.py
# notices a change). Host names and the webhook URL have no public default here.
ROLE_DEFAULTS = {
    "livekit_service_name": "livekit",
    "livekit_site_dir": "/opt/livekit",
    "livekit_config_dir": "/etc/livekit",
    "livekit_http_port": 7880,
    "livekit_rtc_tcp_port": 7881,
    "livekit_rtc_port_range_start": 50000,
    "livekit_rtc_port_range_end": 50100,
    "livekit_s3_endpoint": "http://127.0.0.1:9001",
    "livekit_s3_bucket": "recorder",
    "livekit_healthcheck_timeout": 60,
}


def test_the_defaults_are_the_roles() -> None:
    fields = LivekitConfig.model_fields
    ours = {
        "livekit_service_name": fields["service_name"].default,
        "livekit_site_dir": str(fields["site_path"].default),
        "livekit_config_dir": str(fields["config_dir"].default),
        "livekit_http_port": fields["http_port"].default,
        "livekit_rtc_tcp_port": fields["rtc_tcp_port"].default,
        "livekit_rtc_port_range_start": fields["rtc_port_range_start"].default,
        "livekit_rtc_port_range_end": fields["rtc_port_range_end"].default,
        "livekit_s3_endpoint": fields["s3_endpoint"].default,
        "livekit_s3_bucket": fields["s3_bucket"].default,
        "livekit_healthcheck_timeout": fields["healthcheck_timeout"].default,
    }

    assert ours == ROLE_DEFAULTS
    assert fields["webhook_url"].is_required()
    assert fields["traefik_host"].is_required()


def test_the_route_is_the_roles_byte_for_byte(cfg: LivekitConfig, secrets: SecretValues) -> None:
    assert render_route(cfg) == render_ansible("livekit-traefik.yml.j2", role_vars(cfg, secrets))


def test_the_route_is_one_public_router_with_forwarded_headers(cfg: LivekitConfig) -> None:
    doc = yaml.safe_load(render_route(cfg))["http"]

    assert list(doc["routers"]) == ["livekit"]
    router = doc["routers"]["livekit"]
    assert router == {
        "rule": "Host(`livekit.example.invalid`)",
        "entryPoints": ["web-secure"],
        "middlewares": ["livekit-headers"],
        "service": "livekit",
        "tls": {},
    }
    assert doc["middlewares"]["livekit-headers"]["headers"]["customRequestHeaders"] == {
        "X-Forwarded-Proto": "https",
        "X-Forwarded-Host": "livekit.example.invalid",
    }
    assert doc["services"]["livekit"]["loadBalancer"]["servers"] == [{"url": "http://127.0.0.1:7880"}]


@pytest.mark.parametrize(("index", "template"), [(0, "livekit.yaml.j2"), (1, "egress.yaml.j2")])
def test_the_config_files_hold_the_roles_values(
    cfg: LivekitConfig, secrets: SecretValues, index: int, template: str
) -> None:
    config = cfg.compose_app().config_files[index]
    ours, has_secret = render_config(config, secrets)

    assert has_secret
    assert ours.startswith(f"# {MANAGED}\n")
    assert yaml.safe_load(ours) == yaml.safe_load(render_ansible(template, role_vars(cfg, secrets)))


def test_values_yaml_would_retype_stay_strings(cfg: LivekitConfig) -> None:
    # The role writes secrets inside double quotes; the canonical render quotes where YAML needs it.
    tricky = values(cfg, api_key="123", api_secret="yes", redis_password="a: b #c", s3_secret_key="null")
    server, egress = (yaml.safe_load(render_config(c, tricky)[0]) for c in cfg.compose_app().config_files)

    assert server["keys"] == {"123": "yes"}
    assert server["redis"]["password"] == "a: b #c"
    assert server["webhook"]["api_key"] == "123"
    assert (egress["api_key"], egress["api_secret"], egress["s3"]["secret"]) == ("123", "yes", "null")


def _short_volume(volume: str) -> dict[str, Any]:
    source, target, *options = volume.split(":")
    return {"source": source, "target": target, "read_only": options == ["ro"]}


def test_the_compose_services_are_the_roles(cfg: LivekitConfig, secrets: SecretValues) -> None:
    ours = yaml.safe_load(render_compose(cfg.compose_app()))
    role = yaml.safe_load(render_ansible("livekit-compose.yml.j2", role_vars(cfg, secrets)))

    assert ours["name"] == "livekit"  # the role's project: its site directory's name
    assert list(ours["services"]) == list(role["services"])
    sizes = {"1gb": 1 << 30, "1g": 1 << 30}
    for name, theirs in role["services"].items():
        service = ours["services"][name]
        assert service["image"].partition("@")[0] == theirs["image"]
        for key in ("container_name", "network_mode", "restart", "command", "environment", "cap_add"):
            assert service.get(key) == theirs.get(key), (name, key)
        assert sizes.get(service.get("shm_size")) == sizes.get(theirs.get("shm_size")), name
        assert [
            {k: v.get(k, False) if k == "read_only" else v[k] for k in ("source", "target", "read_only")}
            for v in service["volumes"]
        ] == [_short_volume(v) for v in theirs["volumes"]]
        assert all(v["bind"] == {"create_host_path": False} for v in service["volumes"])
        assert "ports" not in service


def test_the_unit_differs_from_the_roles_only_as_documented(cfg: LivekitConfig, secrets: SecretValues) -> None:
    ours = render_unit(cfg.compose_app()).splitlines()
    role = render_ansible("livekit.service.j2", role_vars(cfg, secrets)).splitlines()

    added = [line for line in ours if line not in role]
    removed = [line for line in role if line not in ours]
    assert added == [
        f"# {MANAGED}",
        "Description=LiveKit Stack (Docker Compose project livekit)",
        "ExecStart=/usr/bin/docker compose -p livekit -f /opt/livekit/docker-compose.yml up -d --remove-orphans",
        "ExecReload=/usr/bin/docker compose -p livekit -f /opt/livekit/docker-compose.yml up -d --remove-orphans",
        "ExecStop=/usr/bin/docker compose -p livekit -f /opt/livekit/docker-compose.yml down",
        "TimeoutStartSec=300",
    ]
    assert removed == [
        "# Managed by Ansible (livekit_deploy). Do not edit on the host.",
        "Description=LiveKit Stack (Docker Compose)",
        "ExecStart=/usr/bin/docker compose -f /opt/livekit/docker-compose.yml up -d --remove-orphans",
        "ExecStop=/usr/bin/docker compose -f /opt/livekit/docker-compose.yml down",
        "TimeoutStartSec=0",
    ]
