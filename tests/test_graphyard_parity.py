"""graphyard files are byte-identical to what the graphyard roles' templates produce.

The deploy ships the roles' templates unchanged; this renders the vendored
copies (``tests/parity/ansible/<role>__*``, checked against ops-library by
``test_traefik_parity.test_vendored_templates_match_ops_library``) with a
Jinja2 environment configured like Ansible's ``template`` module, with the
role defaults overlaid by the playbooks' values, and compares the result with
what the deploy writes. The variables here are written out independently of
``role_vars()`` so a mapping mistake cannot cancel itself out.
"""

import json
from pathlib import Path
from typing import Any

import jinja2
import pytest

from ops_deploy.services.graphyard import agent, core, ingress, vector
from tests.graphyard_fixtures import (
    RELEASE_SOURCES,
    SECRETS,
    core_config,
    ingress_config,
    macmini_core_config,
    make_source,
    secrets_values,
    vector_config,
)

VENDORED = Path(__file__).parent / "parity" / "ansible"
PACKAGED = Path(__file__).parents[1] / "src/ops_deploy/services/graphyard/templates"


def to_nice_json(value: Any) -> str:
    # ansible.plugins.filter.core.to_nice_json
    return json.dumps(value, indent=4, sort_keys=True, separators=(",", ": "))


def render_ansible(role: str, template: str, variables: dict[str, Any]) -> str:
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(VENDORED),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters["bool"] = lambda value: value if isinstance(value, bool) else str(value).lower() in ("1", "true", "yes")
    env.filters["to_json"] = json.dumps
    env.filters["to_nice_json"] = to_nice_json
    return env.get_template(f"{role}__{template}").render(**variables)


# graphyard_deploy/defaults/main.yml, resolved (secrets from the fixture file).
CORE_DEFAULTS: dict[str, Any] = {
    "graphyard_user": "graphyard",
    "graphyard_group": "graphyard",
    "graphyard_home": "/opt/apps/graphyard",
    "graphyard_django_path": "/opt/apps/graphyard/site/src/django",
    "graphyard_venv_bin": "/opt/apps/graphyard/site/.venv/bin",
    "graphyard_env_dir": "/etc/graphyard",
    "graphyard_env_path": "/etc/graphyard/graphyard.env",
    "graphyard_django_settings_module": "config.settings.production",
    "graphyard_django_secret_key": SECRETS["django_secret_key"],
    "graphyard_django_allowed_hosts": ["127.0.0.1", "localhost"],
    "graphyard_django_csrf_trusted_origins": [],
    "graphyard_django_admin_url": "hidden_admin/",
    "graphyard_django_login_url": "/login/",
    "graphyard_django_login_redirect_url": "/",
    "graphyard_django_session_cookie_age_seconds": 86400,
    "graphyard_inventory_monitor_token": SECRETS["inventory_monitor_token"],
    "graphyard_influx_url": "http://127.0.0.1:8086",
    "graphyard_influx_token": SECRETS["influx_token"],
    "graphyard_influx_org": "graphyard",
    "graphyard_influx_bucket": "graphyard",
    "graphyard_influx_measurement": "graphyard_metrics",
    "graphyard_influx_api_mode": "v2",
    "graphyard_influx_timeout_ms": 10000,
    "graphyard_grafana_base_url": "",
    "graphyard_metric_collection_interval_seconds": 60,
    "graphyard_condition_eval_interval_seconds": 60,
    "graphyard_ingest_heartbeat_min_interval_seconds": 15,
    "graphyard_heartbeat_warning_seconds": 900,
    "graphyard_heartbeat_critical_seconds": 3600,
    "graphyard_condition_data_stale_warning_seconds": 600,
    "graphyard_sqlite_timeout_seconds": 30,
    "graphyard_sqlite_busy_timeout_ms": 30000,
    "graphyard_sqlite_journal_mode": "WAL",
    "graphyard_sqlite_synchronous": "NORMAL",
    "graphyard_runtime_enabled": True,
    "graphyard_runtime_service_name": "graphyard-runtime",
    "graphyard_compose_project_name": "graphyard-runtime",
    "graphyard_compose_path": "/opt/apps/graphyard/docker-compose.yml",
    "graphyard_docker_network_name": "graphyard-monitoring",
    "graphyard_influx_image": "influxdb:2.7",
    "graphyard_influx_container_name": "graphyard-influxdb",
    "graphyard_influx_host_bind_address": "127.0.0.1",
    "graphyard_influx_host_port": 8086,
    "graphyard_influx_container_port": 8086,
    "graphyard_influx_data_dir": "/var/lib/graphyard/influxdb2",
    "graphyard_influx_config_dir": "/var/lib/graphyard/influxdb2-config",
    "graphyard_influx_init_username": "graphyard_admin",
    "graphyard_influx_init_password": SECRETS["influx_token"],
    "graphyard_influx_init_admin_token": SECRETS["influx_token"],
    "graphyard_grafana_image": "grafana/grafana-oss",
    "graphyard_grafana_container_name": "graphyard-grafana",
    "graphyard_grafana_host_bind_address": "127.0.0.1",
    "graphyard_grafana_host_port": 3300,
    "graphyard_grafana_container_port": 3000,
    "graphyard_grafana_data_dir": "/var/lib/graphyard/grafana",
    "graphyard_grafana_provisioning_path": "/opt/apps/graphyard/site/deploy/grafana/provisioning",
    "graphyard_grafana_dashboards_path": "/opt/apps/graphyard/site/deploy/grafana/dashboards",
    "graphyard_grafana_admin_user": "admin",
    "graphyard_grafana_admin_password": SECRETS["grafana_admin_password"],
    "graphyard_grafana_allow_sign_up": False,
    "graphyard_grafana_default_home_dashboard_path": (
        "/etc/grafana/provisioning/dashboards-json/overview/graphyard-home.json"
    ),
    "graphyard_grafana_influx_username": "grafana",
    "graphyard_grafana_influx_password": SECRETS["grafana_influx_password"],
    "graphyard_grafana_influx_database": "graphyard",
    "graphyard_web_bind_host": "127.0.0.1",
    "graphyard_web_bind_port": 8051,
    "graphyard_web_workers": 1,
    "graphyard_web_restart_sec": 5,
    "graphyard_agent_restart_sec": 5,
}
# The macmini-shaped variant: what deploy-graphyard-core.yml and macmini's host vars set.
MACMINI = {
    "graphyard_sqlite_synchronous": "FULL",
    "graphyard_grafana_base_url": "https://grafana.example.invalid",
    "graphyard_django_allowed_hosts": ["127.0.0.1", "localhost", "graphyard.example.invalid"],
    "graphyard_django_csrf_trusted_origins": ["http://127.0.0.1", "https://graphyard.example.invalid"],
}
EVERYTHING: tuple[dict[str, Any], dict[str, Any]] = (
    {
        "runtime": None,
        "user": "gy",
        "group": "gyg",
        "home": "/srv/gy",
        "site_path": "/srv/gy/app",
        "env_dir": "/etc/gy",
        "web_service_name": "gy-web",
        "agent_service_name": "gy-agent",
        "web_bind_host": "0.0.0.0",
        "web_bind_port": 9051,
        "web_workers": 3,
        "web_restart_sec": 2,
        "agent_restart_sec": 9,
        "metric_collection_interval_seconds": 30,
        "django": {"admin_url": "admin/", "session_cookie_age_seconds": 60},
        "influx": {"url": "http://influx.invalid:8086", "org": "o", "bucket": "b", "timeout_ms": 5},
    },
    {
        "graphyard_runtime_enabled": False,
        "graphyard_user": "gy",
        "graphyard_group": "gyg",
        "graphyard_home": "/srv/gy",
        "graphyard_django_path": "/srv/gy/app/src/django",
        "graphyard_venv_bin": "/srv/gy/app/.venv/bin",
        "graphyard_env_dir": "/etc/gy",
        "graphyard_env_path": "/etc/gy/graphyard.env",
        "graphyard_web_bind_host": "0.0.0.0",
        "graphyard_web_bind_port": 9051,
        "graphyard_web_workers": 3,
        "graphyard_web_restart_sec": 2,
        "graphyard_agent_restart_sec": 9,
        "graphyard_metric_collection_interval_seconds": 30,
        "graphyard_django_admin_url": "admin/",
        "graphyard_django_session_cookie_age_seconds": 60,
        "graphyard_influx_url": "http://influx.invalid:8086",
        "graphyard_influx_org": "o",
        "graphyard_influx_bucket": "b",
        "graphyard_influx_timeout_ms": 5,
    },
)
RUNTIME_CHANGES: tuple[dict[str, Any], dict[str, Any]] = (
    {
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
    },
    {
        "graphyard_runtime_service_name": "gy-runtime",
        "graphyard_compose_project_name": "gyp",
        "graphyard_docker_network_name": "net-x",
        "graphyard_influx_image": "influxdb:2.8",
        "graphyard_influx_container_name": "influx-x",
        "graphyard_influx_host_port": 9086,
        "graphyard_influx_data_dir": "/data/influx",
        "graphyard_influx_config_dir": "/data/influx-config",
        "graphyard_influx_init_username": "root-x",
        "graphyard_influx_bucket": "bkt",
        "graphyard_grafana_influx_database": "bkt",
        "graphyard_grafana_image": "grafana/grafana-oss:12.4.0",
        "graphyard_grafana_container_name": "grafana-x",
        "graphyard_grafana_host_bind_address": "0.0.0.0",
        "graphyard_grafana_host_port": 4300,
        "graphyard_grafana_data_dir": "/data/grafana",
        "graphyard_grafana_admin_user": "boss",
        "graphyard_grafana_allow_sign_up": True,
        "graphyard_grafana_influx_username": "reader",
        "graphyard_grafana_provisioning_path": "/srv/prov",
        "graphyard_grafana_dashboards_path": "/srv/dash",
    },
)
# ``None`` as the changes: the macmini-shaped config of the fixtures.
CORE_VARIANTS: dict[str, tuple[dict[str, Any] | None, dict[str, Any]]] = {
    "defaults": ({}, {}),
    "macmini": (None, MACMINI),
    "everything": EVERYTHING,
    "runtime": RUNTIME_CHANGES,
}
CORE_TEMPLATES = (
    "graphyard.env.j2",
    "graphyard-web.service.j2",
    "graphyard-agent.service.j2",
    "graphyard-runtime.service.j2",
    "docker-compose.yml.j2",
    "inventory-releases.service.j2",
    "inventory-releases.timer.j2",
)


def _core(tmp_path: Path, variant: str) -> tuple[core.GraphyardConfig, dict[str, Any]]:
    changes, overlay = CORE_VARIANTS[variant]
    source = make_source(tmp_path)
    cfg = macmini_core_config(source) if changes is None else core_config(source, **changes)
    return cfg, {**CORE_DEFAULTS, **overlay}


@pytest.mark.parametrize("template", CORE_TEMPLATES)
@pytest.mark.parametrize("variant", sorted(CORE_VARIANTS))
def test_core_files_match_the_role(tmp_path: Path, variant: str, template: str) -> None:
    cfg, variables = _core(tmp_path, variant)
    if template in ("graphyard-runtime.service.j2", "docker-compose.yml.j2") and cfg.runtime is None:
        pytest.skip("no runtime in this variant")

    assert core.render(template, cfg, secrets_values()) == render_ansible("graphyard_deploy", template, variables)


@pytest.mark.parametrize(
    ("changes", "overlay"),
    [
        (
            {"agent_rust_version": "0.1.0"},
            {"graphyard_agent_rust_binary": "/opt/graphyard-agent/0.1.0/graphyard-agent"},
        ),
        (
            {
                "agent_rust_version": "1.2.3-rc.1",
                "agent_rust_install_root": "/srv/agents",
                "site_path": "/srv/gy/app",
            },
            {
                "graphyard_agent_rust_binary": "/srv/agents/1.2.3-rc.1/graphyard-agent",
                "graphyard_django_path": "/srv/gy/app/src/django",
            },
        ),
    ],
)
def test_agent_dropin_matches_the_role(tmp_path: Path, changes: dict[str, Any], overlay: dict[str, Any]) -> None:
    cfg = core_config(make_source(tmp_path), agent_impl="rust", agent_rust_sha256="0" * 64, **changes)
    expected = render_ansible("graphyard_deploy", "agent-impl.conf.j2", {**CORE_DEFAULTS, **overlay})

    assert agent.render_dropin(cfg) == expected
    binary = overlay["graphyard_agent_rust_binary"]
    assert expected.endswith(f"ExecStart=\nExecStart={binary} --db {cfg.django_path}/db.sqlite3\n")


def test_metric_specs_match_the_playbook_and_role(tmp_path: Path) -> None:
    """The playbook's secret injection (written out by hand here) and the role's to_nice_json."""

    cfg = macmini_core_config(make_source(tmp_path))
    resolved = [
        {
            "name": "Home Assistant Environment Scan",
            "enabled": True,
            "spec_type": "home_assistant_env_scan",
            "interval_seconds": 60,
            "config": {
                "base_url": "http://homeassistant.invalid:10020",
                "host_id": "homeassistant",
                "access_token": SECRETS["homeassistant_api_token"],
            },
        },
        {
            "name": "Fractal backup metrics",
            "spec_type": "http_json_metric",
            "config": {
                "url": "http://fractal.invalid:9101/metrics",
                "basic_username": "nyxmon",
                "basic_password": SECRETS["nyxmon_storage_metrics_password"],
                "scale": 0.001,
            },
        },
        {
            "name": "UniFi switch traffic",
            "spec_type": "unifi_device_traffic",
            "interval_seconds": 300,
            "config": {"url": "https://unifi.invalid", "password": SECRETS["homeassistant_unifi_password"]},
        },
        {
            "name": "Plain page probe",
            "enabled": False,
            "spec_type": "http_page_probe",
            "config": {"url": "https://x.invalid"},
        },
    ]
    expected = render_ansible(
        "graphyard_deploy", "metric-collection-specs.json.j2", {"graphyard_metric_collection_specs": resolved}
    )

    assert core.render_specs(cfg, secrets_values()) == expected
    assert '"basic_password_secret_ref"' not in expected
    assert '"password_secret_ref"' not in expected


def test_release_registry_matches_the_roles_copy() -> None:
    # copy: content: "{{ graphyard_inventory_release_sources | to_nice_json }}\n"
    assert core.render_releases(RELEASE_SOURCES) == to_nice_json(list(RELEASE_SOURCES)) + "\n"


# graphyard_ingress_deploy/defaults/main.yml with the playbook's values.
INGRESS_DEFAULTS: dict[str, Any] = {
    "graphyard_ingress_traefik_cert_resolver": "letsencrypt",
    "graphyard_ingress_graphyard_host": "graphyard.example.invalid",
    "graphyard_ingress_grafana_host": "grafana.example.invalid",
    "graphyard_ingress_graphyard_backend_url": "http://127.0.0.1:8051",
    "graphyard_ingress_grafana_backend_url": "http://127.0.0.1:3300",
    "graphyard_ingress_graphyard_middlewares": [],
    "graphyard_ingress_grafana_middlewares": [],
    "graphyard_ingress_basic_auth_enabled": True,
    "graphyard_ingress_basic_auth_user": "admin",
    "graphyard_ingress_basic_auth_password_hash": "$2y$05$" + "a" * 53,
    "graphyard_ingress_internal_ip_ranges": [
        "192.168.0.0/16",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "100.64.0.0/10",
        "fd7a:115c:a1e0::/48",
        "fd50:3e45:c454:0::/64",
    ],
    "graphyard_ingress_inventory_enabled": False,
}
INGRESS_VARIANTS: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {
    "defaults": ({}, {}),
    "inventory": ({"inventory_enabled": True}, {"graphyard_ingress_inventory_enabled": True}),
    "no-auth": (
        {"basic_auth_enabled": False, "traefik_cert_resolver": ""},
        {"graphyard_ingress_basic_auth_enabled": False, "graphyard_ingress_traefik_cert_resolver": ""},
    ),
    "everything": (
        {
            "graphyard_middlewares": ("a@file", "b"),
            "grafana_middlewares": ("c",),
            "internal_ip_ranges": ("10.0.0.0/8", "203.0.113.7/32"),
            "graphyard_backend_url": "http://127.0.0.1:9051",
            "grafana_backend_url": "http://127.0.0.1:4300",
            "basic_auth_user": "ops",
            "inventory_enabled": True,
        },
        {
            "graphyard_ingress_graphyard_middlewares": ["a@file", "b"],
            "graphyard_ingress_grafana_middlewares": ["c"],
            "graphyard_ingress_internal_ip_ranges": ["10.0.0.0/8", "203.0.113.7/32"],
            "graphyard_ingress_graphyard_backend_url": "http://127.0.0.1:9051",
            "graphyard_ingress_grafana_backend_url": "http://127.0.0.1:4300",
            "graphyard_ingress_basic_auth_user": "ops",
            "graphyard_ingress_inventory_enabled": True,
        },
    ),
}


@pytest.mark.parametrize("variant", sorted(INGRESS_VARIANTS))
def test_ingress_route_matches_the_role(variant: str) -> None:
    changes, overlay = INGRESS_VARIANTS[variant]
    variables = {**INGRESS_DEFAULTS, **overlay}
    auth_hash = variables["graphyard_ingress_basic_auth_password_hash"]
    if not variables["graphyard_ingress_basic_auth_enabled"]:
        auth_hash = None
    expected = render_ansible("graphyard_ingress_deploy", "traefik-graphyard.yml.j2", variables)

    assert ingress.render_route(ingress_config(**changes), auth_hash) == expected


# graphyard_vector_deploy/defaults/main.yml (Linux) with the playbook's values.
VECTOR_DEFAULTS: dict[str, Any] = {
    "graphyard_vector_scrape_interval_secs": 60,
    "graphyard_vector_collectors": ["cpu", "disk", "filesystem", "load", "memory", "network"],
    "graphyard_vector_filesystem_mountpoint_excludes": ["/run/docker/netns/*", "/var/lib/docker/*"],
    "graphyard_vector_metric_prefixes": ["filesystem_", "disk_", "memory_", "cpu_", "load", "network_"],
    "graphyard_vector_host_id": "macmini",
    "graphyard_vector_service_id": "host_metrics",
    "graphyard_vector_source_tag": "vector-host-metrics",
    "graphyard_vector_ingest_url": "http://127.0.0.1:8051/v1/metrics",
    "graphyard_vector_ingest_token": SECRETS["vector_ingest_token"],
    "graphyard_vector_http_timeout_secs": 15,
    "graphyard_vector_request_concurrency": 1,
    "graphyard_vector_retry_initial_backoff_secs": 1,
    "graphyard_vector_retry_max_duration_secs": 3600,
    "graphyard_vector_batch_timeout_secs": 5,
    "graphyard_vector_batch_max_events": 50,
    "graphyard_vector_buffer_max_size": 268435488,
}
VECTOR_VARIANTS: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {
    "defaults": ({}, {}),
    "macmini": (
        {
            "collectors": ("cpu", "disk", "filesystem", "load", "network"),
            "metric_prefixes": ("cpu_", "disk_", "filesystem_", "load", "network_"),
            "source_tag": "macmini-vector",
        },
        {
            "graphyard_vector_collectors": ["cpu", "disk", "filesystem", "load", "network"],
            "graphyard_vector_metric_prefixes": ["cpu_", "disk_", "filesystem_", "load", "network_"],
            "graphyard_vector_source_tag": "macmini-vector",
        },
    ),
    "no-filesystem": (
        {"collectors": ("cpu",), "filesystem_mountpoint_excludes": (), "host_id": "fractal"},
        {
            "graphyard_vector_collectors": ["cpu"],
            "graphyard_vector_filesystem_mountpoint_excludes": [],
            "graphyard_vector_host_id": "fractal",
        },
    ),
    "excludes": (
        {"filesystem_mountpoint_excludes": ("/mnt/*",), "ingest_url": "https://graphyard.invalid/v1/metrics"},
        {
            "graphyard_vector_filesystem_mountpoint_excludes": ["/mnt/*"],
            "graphyard_vector_ingest_url": "https://graphyard.invalid/v1/metrics",
        },
    ),
}


@pytest.mark.parametrize("variant", sorted(VECTOR_VARIANTS))
def test_vector_fragment_matches_the_role(variant: str) -> None:
    changes, overlay = VECTOR_VARIANTS[variant]
    expected = render_ansible("graphyard_vector_deploy", "vector.yaml.j2", {**VECTOR_DEFAULTS, **overlay})

    assert vector.render_fragment(vector_config(**changes), secrets_values()).reveal().decode() == expected


def test_vector_global_config_is_the_roles_copy_content() -> None:
    assert vector.render_global(vector_config()) == 'data_dir: "/var/lib/vector"\n'


@pytest.mark.parametrize(
    ("packaged", "vendored"),
    [
        *(
            (name, f"graphyard_deploy__{name}")
            for name in (*CORE_TEMPLATES, "metric-collection-specs.json.j2", "agent-impl.conf.j2")
        ),
        ("traefik-graphyard.yml.j2", "graphyard_ingress_deploy__traefik-graphyard.yml.j2"),
        ("vector.yaml.j2", "graphyard_vector_deploy__vector.yaml.j2"),
    ],
)
def test_packaged_templates_are_the_vendored_ones(packaged: str, vendored: str) -> None:
    assert (PACKAGED / packaged).read_bytes() == (VENDORED / vendored).read_bytes()
