"""graphyard's host files stay byte for byte what hosts have today.

The goldens under ``tests/golden/graphyard`` were recorded when these
renders still equalled the retired graphyard roles' output (role defaults
overlaid by the playbooks' values); identical bytes mean the next deploy
rewrites nothing and restarts nothing (see tests/goldens.py).
"""

import json
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.services.graphyard import agent, core, ingress, vector
from tests.goldens import assert_golden
from tests.graphyard_fixtures import (
    RELEASE_SOURCES,
    core_config,
    ingress_config,
    macmini_core_config,
    make_source,
    secrets_values,
    vector_config,
)

GOLDEN = Path(__file__).parent / "golden" / "graphyard"
RUNTIME_CHANGES: dict[str, Any] = {
    "runtime": {"service_name": "gy-runtime", "compose_project_name": "gyp", "docker_network_name": "net-x"},
    "influx": {
        "image": "influxdb:2.8",
        "container_name": "influx-x",
        "host_port": 9086,
        "data_dir": "/data/influx",
        "config_dir": "/data/influx-config",
        "init_username": "root-x",
        "bucket": "bkt",
    },
    "grafana": {
        "image": "grafana/grafana-oss:12.4.0",
        "container_name": "grafana-x",
        "host_bind_address": "0.0.0.0",
        "host_port": 4300,
        "data_dir": "/data/grafana",
        "admin_user": "boss",
        "allow_sign_up": True,
        "influx_username": "reader",
        "provisioning_path": "/srv/prov",
        "dashboards_path": "/srv/dash",
    },
}
# ``None``: the macmini-shaped config of the fixtures.
CORE_VARIANTS: dict[str, dict[str, Any] | None] = {"defaults": {}, "macmini": None, "runtime": RUNTIME_CHANGES}
CORE_TEMPLATES = (
    "graphyard.env.j2",
    "graphyard-web.service.j2",
    "graphyard-agent.service.j2",
    "graphyard-runtime.service.j2",
    "docker-compose.yml.j2",
    "inventory-releases.service.j2",
    "inventory-releases.timer.j2",
)


@pytest.mark.parametrize("variant", sorted(CORE_VARIANTS))
def test_core_files_are_golden(tmp_path: Path, variant: str) -> None:
    changes = CORE_VARIANTS[variant]
    source = make_source(tmp_path)
    cfg = macmini_core_config(source) if changes is None else core_config(source, **changes)

    for template in CORE_TEMPLATES:
        rendered = core.render(template, cfg, secrets_values())
        assert_golden(GOLDEN / "core" / variant / template.removesuffix(".j2"), rendered)


def test_agent_dropin_is_golden(tmp_path: Path) -> None:
    cfg = core_config(make_source(tmp_path), agent_impl="rust", agent_rust_sha256="0" * 64, agent_rust_version="0.1.0")

    dropin = agent.render_dropin(cfg)

    assert_golden(GOLDEN / "core" / "agent-impl.conf", dropin)
    assert dropin.endswith(
        f"ExecStart=\nExecStart=/opt/graphyard-agent/0.1.0/graphyard-agent --db {cfg.django_path}/db.sqlite3\n"
    )


def test_metric_specs_are_golden_with_secrets_injected(tmp_path: Path) -> None:
    cfg = macmini_core_config(make_source(tmp_path))

    specs = core.render_specs(cfg, secrets_values())

    assert_golden(GOLDEN / "core" / "metric-collection-specs.json", specs)
    assert '"basic_password_secret_ref"' not in specs
    assert '"password_secret_ref"' not in specs


def test_release_registry_is_nice_json() -> None:
    expected = json.dumps(list(RELEASE_SOURCES), indent=4, sort_keys=True, separators=(",", ": ")) + "\n"
    assert core.render_releases(RELEASE_SOURCES) == expected


INGRESS_VARIANTS: dict[str, dict[str, Any]] = {
    "defaults": {},
    "inventory": {"inventory_enabled": True},
    "no-auth": {"basic_auth_enabled": False, "traefik_cert_resolver": ""},
}
INGRESS_AUTH_HASH = "$2y$05$" + "a" * 53


@pytest.mark.parametrize("variant", sorted(INGRESS_VARIANTS))
def test_ingress_route_is_golden(variant: str) -> None:
    changes = INGRESS_VARIANTS[variant]
    auth_hash = None if changes.get("basic_auth_enabled") is False else INGRESS_AUTH_HASH

    route = ingress.render_route(ingress_config(**changes), auth_hash)

    assert_golden(GOLDEN / "ingress" / variant / "traefik-graphyard.yml", route)


VECTOR_VARIANTS: dict[str, dict[str, Any]] = {
    "defaults": {},
    "macmini": {
        "collectors": ("cpu", "disk", "filesystem", "load", "network"),
        "metric_prefixes": ("cpu_", "disk_", "filesystem_", "load", "network_"),
        "source_tag": "macmini-vector",
    },
}


@pytest.mark.parametrize("variant", sorted(VECTOR_VARIANTS))
def test_vector_fragment_is_golden(variant: str) -> None:
    fragment = vector.render_fragment(vector_config(**VECTOR_VARIANTS[variant]), secrets_values()).reveal().decode()

    assert_golden(GOLDEN / "vector" / variant / "vector.yaml", fragment)


def test_vector_global_config() -> None:
    assert vector.render_global(vector_config()) == 'data_dir: "/var/lib/vector"\n'
