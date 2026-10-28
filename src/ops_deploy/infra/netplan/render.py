"""Original role templates with the small Ansible rendering filter vocabulary."""

from __future__ import annotations

import shlex
from pathlib import Path
from typing import Any

import yaml
from jinja2 import Environment, FileSystemLoader, StrictUndefined

from .config import NetplanConfig

ENV = Environment(
    loader=FileSystemLoader(Path(__file__).parent / "templates"),
    undefined=StrictUndefined,
    keep_trailing_newline=True,
    trim_blocks=True,
    lstrip_blocks=True,
)
ENV.filters.update(
    bool=bool,
    ternary=lambda condition, yes, no: yes if condition else no,
    quote=shlex.quote,
    to_nice_yaml=lambda value: yaml.safe_dump(value, default_flow_style=False, allow_unicode=True, indent=4, width=80),
)


def render(cfg: NetplanConfig, template: str) -> str:
    values: dict[str, Any] = {
        "netplan_config_" + name: value
        for name, value in cfg.model_dump(mode="json", exclude_none=True, by_alias=True).items()
        if name != "route_guard"
    }
    values.update(
        {"netplan_config_route_guard_" + name: value for name, value in cfg.route_guard.model_dump(mode="json").items()}
    )
    return ENV.get_template(template + ".j2").render(**values)
