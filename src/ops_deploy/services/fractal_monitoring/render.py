"""Render original role/inline resources; no collector policy rewriting."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from .config import BackupEndpointConfig, ReplicationLagConfig, StorageEndpointConfig, StorageExporterConfig

ENV = Environment(
    loader=FileSystemLoader(Path(__file__).parent / "templates"),
    undefined=StrictUndefined,
    keep_trailing_newline=True,
    trim_blocks=True,
    lstrip_blocks=True,
)
ENV.filters["bool"] = bool
ENV.filters["to_json"] = lambda value: json.dumps(value)
ENV.filters["ternary"] = lambda value, yes, no: yes if value else no


def render(
    cfg: StorageExporterConfig | StorageEndpointConfig | BackupEndpointConfig | ReplicationLagConfig, resource: str
) -> str:
    if isinstance(cfg, StorageExporterConfig):
        prefix = "nyxmon_storage_exporter_"
    elif isinstance(cfg, StorageEndpointConfig):
        prefix = "storage_metrics_endpoint_"
    elif isinstance(cfg, BackupEndpointConfig):
        prefix = "backup_metrics_endpoint_"
    else:
        prefix = "fractal_minio_replication_monitor_"
    values: dict[str, Any] = {prefix + k: v for k, v in cfg.model_dump(mode="json").items()}
    return ENV.get_template(resource + ".j2").render(**values)


def lag_script() -> str:
    return (Path(__file__).parent / "files/minio_replication_lag_probe.py").read_text()
