"""Byte-preserving rendering of the original physical service units."""

from functools import cache
from typing import Literal

import jinja2

from ops_deploy.core.templates import template_loader

from .runtime_config import HomeAssistantRuntimeConfig


@cache
def templates() -> jinja2.Environment:
    return jinja2.Environment(
        loader=template_loader("ops_deploy.services.homeassistant"),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
        autoescape=False,
    )


def render_unit(cfg: HomeAssistantRuntimeConfig, unit: Literal["homeassistant", "matter-server"]) -> str:
    return (
        templates()
        .get_template(unit + ".service.j2")
        .render(**{f"homeassistant_{key}": value for key, value in cfg.model_dump().items()})
    )
