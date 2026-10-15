"""A minimal Logyard checkout and the configs the logyard tests share."""

from __future__ import annotations

from pathlib import Path

from ops_deploy.core import SecretRef, SecretValues
from ops_deploy.services.logyard import (
    HealthEndpoint,
    LogyardConfig,
    LogyardIngressConfig,
    LogyardStackConfig,
    LogyardVectorConfig,
    NyxmonChecks,
)

REF = SecretRef("secrets/prod/nyxmon.yml")
PASSWORD = "logyard-fixture-nyxmon-password"
DASHBOARD = '{"title": "Logyard overview"}\n'
EXTRA_DASHBOARD = '{"title": "Logyard extra"}\n'


def make_source(root: Path) -> Path:
    """The files the role requires, plus a second dashboard in a subdirectory."""

    source = root / "logyard"
    files = {
        "README.md": "# Logyard\n",
        "docs/operational-assumptions.md": "assumptions\n",
        "deploy/grafana/dashboards/logyard/logyard-home.json": DASHBOARD,
        "deploy/grafana/dashboards/logyard/extra/more.json": EXTRA_DASHBOARD,
    }
    for name, text in files.items():
        (source / name).parent.mkdir(parents=True, exist_ok=True)
        (source / name).write_text(text)
    return source


def secrets_values(**changes: str) -> SecretValues:
    return SecretValues(REF, {"nyxmon_storage_metrics_password": PASSWORD, **changes})


def core_config(source: Path, **changes: object) -> LogyardConfig:
    fields: dict[str, object] = {
        "source_path": source,
        "secrets": REF,
        "health": HealthEndpoint(selector='{host="macmini",source_type="journald"}'),
        "nyxmon": NyxmonChecks(
            suppression_url="http://macmini:9106/.well-known/os-apt-maintenance", suppression_reason="macmini"
        ),
    }
    fields.update(changes)
    return LogyardConfig.model_validate(fields)


def ingress_config(**changes: object) -> LogyardIngressConfig:
    return LogyardIngressConfig.model_validate(
        {"host": "logyard.example.invalid", "traefik_cert_resolver": "letsencrypt", **changes}
    )


def vector_config(**changes: object) -> LogyardVectorConfig:
    return LogyardVectorConfig.model_validate({"host_id": "macmini", **changes})


def stack_config(source: Path) -> LogyardStackConfig:
    return LogyardStackConfig(core=core_config(source), ingress=ingress_config(), vector=vector_config())
