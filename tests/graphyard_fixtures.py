"""A minimal Graphyard tree, fixture secrets and the configs the graphyard tests share."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ops_deploy.core import SecretRef, SecretValues
from ops_deploy.services.graphyard import (
    GraphyardAuthConfig,
    GraphyardConfig,
    GraphyardIngressConfig,
    GraphyardStackConfig,
    GraphyardVectorConfig,
    MetricSpecs,
)

REF = SecretRef("secrets/prod/graphyard.yml")
SECRETS = {
    "django_secret_key": "graphyard-fixture-django-secret-key",
    "influx_token": "graphyard-fixture-influx-token",
    "grafana_admin_password": "graphyard-fixture-grafana-admin",
    "grafana_influx_password": "graphyard-fixture-grafana-influx",
    "inventory_monitor_token": "graphyard-fixture-inventory-monitor-token-0123456789",
    "vector_ingest_token": "graphyard-fixture-vector-ingest-token",
    "basic_auth_password": "graphyard-fixture-basic-auth",
    "django_bootstrap_username": "graphyard-fixture-admin",
    "django_bootstrap_password": "graphyard-fixture-bootstrap-password",
    "homeassistant_api_token": "graphyard-fixture-homeassistant-token",
    "nyxmon_storage_metrics_password": "graphyard-fixture-nyxmon-password",
    "homeassistant_unifi_password": "graphyard-fixture-unifi-password",
}
# A spec of each kind the playbook fills in from secrets, plus a plain one.
SPECS: tuple[dict[str, Any], ...] = (
    {
        "name": "Home Assistant Environment Scan",
        "enabled": True,
        "spec_type": "home_assistant_env_scan",
        "interval_seconds": 60,
        "config": {"base_url": "http://homeassistant.invalid:10020", "host_id": "homeassistant"},
    },
    {
        "name": "Fractal backup metrics",
        "spec_type": "http_json_metric",
        "config": {
            "url": "http://fractal.invalid:9101/metrics",
            "basic_username": "nyxmon",
            "basic_password_secret_ref": "nyxmon_storage_metrics_password",
            "scale": 0.001,
        },
    },
    {
        "name": "UniFi switch traffic",
        "spec_type": "unifi_device_traffic",
        "interval_seconds": 300,
        "config": {"url": "https://unifi.invalid", "password_secret_ref": "homeassistant_unifi_password"},
    },
    {
        "name": "Plain page probe",
        "enabled": False,
        "spec_type": "http_page_probe",
        "config": {"url": "https://x.invalid"},
    },
)
RELEASE_SOURCES: tuple[dict[str, Any], ...] = (
    {"kind": "pypi", "project": "django", "targets": [{"kind": "python", "name": "django"}]},
)


def make_source(root: Path) -> Path:
    """The paths the role requires, plus the Grafana provisioning tree."""

    source = root / "graphyard"
    files = {
        "pyproject.toml": "[project]\nname = 'graphyard'\n",
        "uv.lock": "version = 1\n",
        "src/django/manage.py": "print('manage')\n",
        "src/graphyard/__init__.py": "",
        "deploy/grafana/provisioning/datasources/graphyard.yaml": (
            "apiVersion: 1\ndatasources:\n  - name: x\n    access: proxy\n    url: http://graphyard-influxdb:8086\n"
        ),
        "deploy/grafana/dashboards/overview/graphyard-home.json": "{}\n",
    }
    for name, text in files.items():
        (source / name).parent.mkdir(parents=True, exist_ok=True)
        (source / name).write_text(text)
    return source


def secrets_values(**changes: str) -> SecretValues:
    return SecretValues(REF, {**SECRETS, **changes})


def core_config(source: Path, **changes: object) -> GraphyardConfig:
    fields: dict[str, object] = {"source_path": source, "secrets": REF}
    fields.update(changes)
    return GraphyardConfig.model_validate(fields)


def macmini_core_config(source: Path, **changes: object) -> GraphyardConfig:
    """The shape of macmini's: specs, release refresh, retention, FULL sync, public hosts."""

    fields: dict[str, object] = {
        "metric_specs": MetricSpecs(specs=SPECS, prune=True),
        "inventory_release_sources": RELEASE_SOURCES,
        "sqlite_synchronous": "FULL",
        "influx": {"retention_apply": True, "bucket_retention": "180d"},
        "grafana": {"base_url": "https://grafana.example.invalid"},
        "django": {
            "allowed_hosts": ("127.0.0.1", "localhost", "graphyard.example.invalid"),
            "csrf_trusted_origins": ("http://127.0.0.1", "https://graphyard.example.invalid"),
        },
    }
    fields.update(changes)
    return core_config(source, **fields)


def ingress_config(**changes: object) -> GraphyardIngressConfig:
    return GraphyardIngressConfig.model_validate(
        {
            "graphyard_host": "graphyard.example.invalid",
            "grafana_host": "grafana.example.invalid",
            "traefik_cert_resolver": "letsencrypt",
            **changes,
        }
    )


def vector_config(**changes: object) -> GraphyardVectorConfig:
    return GraphyardVectorConfig.model_validate(
        {"host_id": "macmini", "ingest_url": "http://127.0.0.1:8051/v1/metrics", **changes}
    )


def auth_config(**changes: object) -> GraphyardAuthConfig:
    return GraphyardAuthConfig.model_validate({"grafana_shared_network_name": "graphyard-monitoring", **changes})


def stack_config(source: Path) -> GraphyardStackConfig:
    return GraphyardStackConfig(
        core=core_config(source), vector=vector_config(), ingress=ingress_config(), auth=auth_config()
    )
