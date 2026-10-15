"""logyard files are byte-identical to what the logyard roles' templates produce.

The deploy ships the roles' templates unchanged; this renders the vendored
copies (``tests/parity/ansible/<role>__*``, checked against ops-library by
``test_traefik_parity.test_vendored_templates_match_ops_library``) with a
Jinja2 environment configured like Ansible's ``template`` module, with the
role defaults overlaid by the playbooks' values, and compares the result with
what the deploy writes. The variables here are written out independently of
``role_vars()`` so a mapping mistake cannot cancel itself out.
"""

import base64
import json
from pathlib import Path
from typing import Any

import jinja2
import pytest

from ops_deploy.services.logyard import core, ingress, vector
from ops_deploy.services.logyard.core import HEALTH_SCRIPT
from tests.logyard_fixtures import core_config, ingress_config, make_source, vector_config

VENDORED = Path(__file__).parent / "parity" / "ansible"
PACKAGED = Path(__file__).parents[1] / "src/ops_deploy/services/logyard/templates"


def render_ansible(role: str, template: str, variables: dict[str, Any]) -> str:
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(VENDORED),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters["bool"] = lambda value: value if isinstance(value, bool) else str(value).lower() in ("1", "true", "yes")
    env.filters["ternary"] = lambda value, yes, no=None: yes if value else no
    env.filters["to_json"] = json.dumps
    env.filters["b64encode"] = lambda value: base64.b64encode(value.encode()).decode()
    return env.get_template(f"{role}__{template}").render(**variables)


# logyard_deploy/defaults/main.yml
CORE_DEFAULTS: dict[str, Any] = {
    "logyard_user": "logyard",
    "logyard_group": "logyard",
    "logyard_home": "/opt/apps/logyard",
    "logyard_service_name": "logyard",
    "logyard_compose_path": "/opt/apps/logyard/docker-compose.yml",
    "logyard_config_path": "/etc/logyard/loki-config.yml",
    "logyard_docker_network_name": "graphyard-monitoring",
    "logyard_loki_image": "grafana/loki:3.5.11",
    "logyard_loki_container_name": "logyard-loki",
    "logyard_loki_host_port": 3101,
    "logyard_loki_http_port": 3100,
    "logyard_loki_data_dir": "/var/lib/logyard/loki",
    "logyard_loki_schema_from": "2024-01-01",
    "logyard_loki_index_prefix": "logyard_index_",
    "logyard_retention_period": "336h",
    "logyard_volume_enabled": True,
    "logyard_query_cache_max_size_mb": 100,
    "logyard_grafana_datasource_name": "Logyard Loki",
    "logyard_grafana_datasource_uid": "logyard-loki",
    "logyard_grafana_datasource_is_default": False,
    "logyard_health_script_path": "/usr/local/bin/logyard_health_httpd.py",
    "logyard_health_bind_host": "127.0.0.1",
    "logyard_health_port": 9105,
    "logyard_health_path": "/.well-known/logyard",
    "logyard_health_selector": '{host="macmini",source_type="journald"}',
    "logyard_health_warning_window_seconds": 900,
    "logyard_health_critical_window_seconds": 3600,
    "logyard_health_timeout_seconds": 10,
    "logyard_health_systemctl_timeout_seconds": 5,
    "logyard_health_units": [],
}
CORE_VARIANTS: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {
    "defaults": ({}, {}),
    "playbook": (
        {"health": core.HealthEndpoint(units=({"id": "vector", "unit": "vector.service"},))},
        {"logyard_health_units": [{"id": "vector", "unit": "vector.service"}]},
    ),
    "everything": (
        {
            "loki": core.Loki(
                image="grafana/loki:3.6.0",
                container_name="loki-x",
                host_port=3200,
                http_port=3300,
                retention_period="720h",
                volume_enabled=False,
                query_cache_max_size_mb=50,
                schema_from="2025-02-03",
                index_prefix="x_",
            ),
            "docker_network_name": "net-x",
            "grafana": core.GrafanaWiring(
                datasource_name="Loki X", datasource_uid="loki-x", datasource_is_default=True
            ),
            "health": core.HealthEndpoint(
                bind_host="0.0.0.0",
                port=9200,
                path="/x",
                selector='{host="a",job="x y"}',
                warning_window_seconds=60,
                critical_window_seconds=120,
                timeout_seconds=3,
                systemctl_timeout_seconds=2,
                units=({"id": "a", "unit": "a.service"}, {"id": "b", "unit": "b.service"}),
            ),
        },
        {
            "logyard_loki_image": "grafana/loki:3.6.0",
            "logyard_loki_container_name": "loki-x",
            "logyard_loki_host_port": 3200,
            "logyard_loki_http_port": 3300,
            "logyard_retention_period": "720h",
            "logyard_volume_enabled": False,
            "logyard_query_cache_max_size_mb": 50,
            "logyard_loki_schema_from": "2025-02-03",
            "logyard_loki_index_prefix": "x_",
            "logyard_docker_network_name": "net-x",
            "logyard_grafana_datasource_name": "Loki X",
            "logyard_grafana_datasource_uid": "loki-x",
            "logyard_grafana_datasource_is_default": True,
            "logyard_health_bind_host": "0.0.0.0",
            "logyard_health_port": 9200,
            "logyard_health_path": "/x",
            "logyard_health_selector": '{host="a",job="x y"}',
            "logyard_health_warning_window_seconds": 60,
            "logyard_health_critical_window_seconds": 120,
            "logyard_health_timeout_seconds": 3,
            "logyard_health_systemctl_timeout_seconds": 2,
            "logyard_health_units": [{"id": "a", "unit": "a.service"}, {"id": "b", "unit": "b.service"}],
        },
    ),
}
CORE_TEMPLATES = {
    "loki-config.yml.j2": core.render_loki_config,
    "docker-compose.yml.j2": core.render_compose,
    "logyard.service.j2": core.render_service_unit,
    "grafana-logyard-datasource.yml.j2": core.render_datasource,
    "logyard-health-endpoint.service.j2": core.render_health_unit,
}


@pytest.mark.parametrize("variant", CORE_VARIANTS)
@pytest.mark.parametrize("template", CORE_TEMPLATES)
def test_core_parity(tmp_path: Path, template: str, variant: str) -> None:
    fields, role_vars = CORE_VARIANTS[variant]
    cfg = core_config(make_source(tmp_path), **fields)

    ours = CORE_TEMPLATES[template](cfg)
    assert ours == render_ansible("logyard_deploy", template, {**CORE_DEFAULTS, **role_vars})


def test_health_script_is_the_roles_file() -> None:
    assert (VENDORED / "logyard_deploy__logyard_health_httpd.py.j2").read_text() == HEALTH_SCRIPT


def test_health_units_survive_systemd_verbatim(tmp_path: Path) -> None:
    units = ({"id": "vector", "unit": "vector.service"},)
    cfg = core_config(make_source(tmp_path), health=core.HealthEndpoint(units=units))

    unit = core.render_health_unit(cfg)
    (line,) = [line for line in unit.splitlines() if line.startswith("Environment=LOGYARD_HEALTH_UNITS_B64=")]
    assert json.loads(base64.b64decode(line.partition("=")[2].partition("=")[2])) == list(units)


# logyard_ingress_deploy/defaults/main.yml
INGRESS_DEFAULTS: dict[str, Any] = {
    "logyard_ingress_traefik_cert_resolver": "",
    "logyard_ingress_host": "logyard.example.com",
    "logyard_ingress_backend_url": "http://127.0.0.1:3101",
    "logyard_ingress_root_redirect_enabled": True,
    "logyard_ingress_root_redirect_url": "https://grafana.home.xn--wersdrfer-47a.de/d/logyard-home/logyard-overview",
    "logyard_ingress_middlewares": [],
    "logyard_ingress_allowed_paths": [
        {"path": "/loki/api/v1/push", "methods": ["POST"]},
        {"path": "/ready", "methods": ["GET", "HEAD"]},
    ],
    "logyard_ingress_internal_ip_ranges": [
        "192.168.0.0/16",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "100.64.0.0/10",
        "fd7a:115c:a1e0::/48",
        "fd50:3e45:c454:0::/64",
    ],
}
INGRESS_VARIANTS: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {
    "playbook": (
        {},
        {"logyard_ingress_host": "logyard.example.invalid", "logyard_ingress_traefik_cert_resolver": "letsencrypt"},
    ),
    "no resolver, no redirect": (
        {"traefik_cert_resolver": "", "root_redirect_enabled": False},
        {
            "logyard_ingress_host": "logyard.example.invalid",
            "logyard_ingress_traefik_cert_resolver": "",
            "logyard_ingress_root_redirect_enabled": False,
        },
    ),
    "everything": (
        {
            "backend_url": "http://127.0.0.1:3300",
            "root_redirect_url": "https://grafana.example.invalid/d/x",
            "middlewares": ("auth@file", "limit"),
            "allowed_paths": (
                ingress.AllowedPath(path="/loki/api/v1/push", methods=("POST", "PUT")),
                ingress.AllowedPath(path="/metrics", methods=("GET",)),
                ingress.AllowedPath(path="/ready", methods=("GET", "HEAD")),
            ),
            "internal_ip_ranges": ("10.0.0.0/8", "2001:db8::/32"),
        },
        {
            "logyard_ingress_host": "logyard.example.invalid",
            "logyard_ingress_traefik_cert_resolver": "letsencrypt",
            "logyard_ingress_backend_url": "http://127.0.0.1:3300",
            "logyard_ingress_root_redirect_url": "https://grafana.example.invalid/d/x",
            "logyard_ingress_middlewares": ["auth@file", "limit"],
            "logyard_ingress_allowed_paths": [
                {"path": "/loki/api/v1/push", "methods": ["POST", "PUT"]},
                {"path": "/metrics", "methods": ["GET"]},
                {"path": "/ready", "methods": ["GET", "HEAD"]},
            ],
            "logyard_ingress_internal_ip_ranges": ["10.0.0.0/8", "2001:db8::/32"],
        },
    ),
}


@pytest.mark.parametrize("variant", INGRESS_VARIANTS)
def test_ingress_parity(variant: str) -> None:
    fields, role_vars = INGRESS_VARIANTS[variant]
    cfg = ingress_config(**fields)

    assert ingress.render_route(cfg) == render_ansible(
        "logyard_ingress_deploy", "traefik-logyard.yml.j2", {**INGRESS_DEFAULTS, **role_vars}
    )


# logyard_vector_deploy/defaults/main.yml
VECTOR_DEFAULTS: dict[str, Any] = {
    "logyard_vector_ingest_endpoint": "http://127.0.0.1:3101",
    "logyard_vector_host_id": "macmini",
    "logyard_vector_environment": "prod",
    "logyard_vector_source_type": "journald",
    "logyard_vector_include_units": [],
    "logyard_vector_exclude_units": [],
    "logyard_vector_include_matches": [],
    "logyard_vector_current_boot_only": False,
    "logyard_vector_http_timeout_secs": 15,
    "logyard_vector_request_concurrency": 1,
    "logyard_vector_retry_initial_backoff_secs": 1,
    "logyard_vector_retry_max_duration_secs": 3600,
    "logyard_vector_batch_timeout_secs": 5,
    "logyard_vector_batch_max_events": 200,
    "logyard_vector_buffer_max_size": 268435488,
    "logyard_vector_healthcheck_enabled": False,
    "logyard_vector_allow_unconfined_label_templates": True,
    "logyard_vector_supports_template_confinement": True,
}
VECTOR_VARIANTS: dict[str, tuple[dict[str, Any], bool | None, dict[str, Any]]] = {
    "defaults": ({}, None, {}),
    "old vector": ({}, False, {"logyard_vector_supports_template_confinement": False}),
    "no unconfined labels": (
        {"allow_unconfined_label_templates": False},
        True,
        {"logyard_vector_allow_unconfined_label_templates": False},
    ),
    "everything": (
        {
            "ingest_endpoint": "https://logyard.example.invalid",
            "host_id": "fractal",
            "environment": "staging",
            "include_units": ("ssh.service", 'odd"unit.service'),
            "exclude_units": ("noisy.service",),
            "include_matches": (
                vector.Match(key="_COMM", value="sshd"),
                vector.Match(key="PRIORITY", value=("0", "1", "2")),
            ),
            "current_boot_only": True,
            "healthcheck_enabled": True,
            "http_timeout_secs": 30,
            "request_concurrency": 2,
            "retry_initial_backoff_secs": 2,
            "retry_max_duration_secs": 60,
            "batch_timeout_secs": 10,
            "batch_max_events": 50,
            "buffer_max_size": 1048576,
        },
        True,
        {
            "logyard_vector_ingest_endpoint": "https://logyard.example.invalid",
            "logyard_vector_host_id": "fractal",
            "logyard_vector_environment": "staging",
            "logyard_vector_include_units": ["ssh.service", 'odd"unit.service'],
            "logyard_vector_exclude_units": ["noisy.service"],
            "logyard_vector_include_matches": [
                {"key": "_COMM", "value": "sshd"},
                {"key": "PRIORITY", "value": ["0", "1", "2"]},
            ],
            "logyard_vector_current_boot_only": True,
            "logyard_vector_healthcheck_enabled": True,
            "logyard_vector_http_timeout_secs": 30,
            "logyard_vector_request_concurrency": 2,
            "logyard_vector_retry_initial_backoff_secs": 2,
            "logyard_vector_retry_max_duration_secs": 60,
            "logyard_vector_batch_timeout_secs": 10,
            "logyard_vector_batch_max_events": 50,
            "logyard_vector_buffer_max_size": 1048576,
        },
    ),
}


@pytest.mark.parametrize("variant", VECTOR_VARIANTS)
def test_vector_parity(variant: str) -> None:
    fields, supports, role_vars = VECTOR_VARIANTS[variant]
    cfg = vector_config(**fields)

    assert vector.render_fragment(cfg, supports) == render_ansible(
        "logyard_vector_deploy", "vector.yaml.j2", {**VECTOR_DEFAULTS, **role_vars}
    )


def test_global_fragment_is_the_roles_content() -> None:
    # copy: content: "data_dir: {{ logyard_vector_data_dir | to_json }}\n"
    cfg = vector_config(data_dir="/srv/vector")

    assert vector.render_global(cfg) == f"data_dir: {json.dumps('/srv/vector')}\n"


@pytest.mark.parametrize("template", sorted(path.name for path in PACKAGED.glob("*.j2")))
def test_packaged_templates_are_the_vendored_ones(template: str) -> None:
    (vendored,) = [p for p in VENDORED.glob(f"logyard_*__{template}")]

    assert (PACKAGED / template).read_text() == vendored.read_text()
