"""Exact original Tailscale endpoint templates and rendering vocabulary."""

from __future__ import annotations

import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from .metrics_config import TailscaleMetricsConfig

ENV = Environment(
    loader=FileSystemLoader(Path(__file__).parent / "templates"),
    undefined=StrictUndefined,
    keep_trailing_newline=True,
    trim_blocks=True,
    lstrip_blocks=True,
)
ENV.filters.update(bool=bool, to_json=json.dumps)


def render(cfg: TailscaleMetricsConfig, resource: str) -> str:
    return ENV.get_template(resource + ".j2").render(
        **{"tailscale_metrics_endpoint_" + key: value for key, value in cfg.model_dump(mode="json").items()}
    )
