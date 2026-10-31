"""Original templates, including the protected shell companion; no target access."""

from __future__ import annotations

import json
from functools import cache
from typing import Any

import jinja2

from ops_deploy.core.secrets import SecretContent

from .config import OperationsApiConfig, OperationsApiPins


@cache
def templates() -> jinja2.Environment:
    env = jinja2.Environment(
        loader=jinja2.PackageLoader(__package__, "templates"),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
        autoescape=False,
    )
    env.filters["to_json"] = json.dumps
    env.filters["to_nice_json"] = lambda value: json.dumps(value, indent=4, sort_keys=True)
    return env


def context(cfg: OperationsApiConfig, pins: OperationsApiPins) -> dict[str, Any]:
    values = cfg.model_dump(exclude={"postgres", "source_path"})
    values.update(
        site=str(cfg.site_path),
        venv=str(cfg.venv_path),
        storage_path=cfg.storage_path or cfg.home,
        secret_key=pins.secret_key.get_secret_value(),
        database_password=pins.database_password.get_secret_value(),
        database_url=cfg.connection_url(pins),
        signing_keys={k: v.get_secret_value() for k, v in pins.signing_keys.items()},
        signing_key_id=pins.signing_key_id,
        profiles=[row.revealed() for row in pins.profiles],
    )
    # Original integer-valued default horizons render as30/14, not30.0/14.0.
    for name in ("capacity_warn_days", "capacity_critical_days"):
        if values[name].is_integer():
            values[name] = int(values[name])
    return {"daybook_operations_api_" + k: v for k, v in values.items()}


def render_config(cfg: OperationsApiConfig, pins: OperationsApiPins) -> dict[str, SecretContent]:
    values = context(cfg, pins)
    result = {
        name: SecretContent(templates().get_template(name + ".j2").render(**values))
        for name in ("environment", "profiles.json", "lifecycle.json")
    }
    result["environment.shell"] = SecretContent(
        templates().get_template("environment.j2").render(**values, task_shell_environment=True)
    )
    return result


def render_unit(cfg: OperationsApiConfig, kind: str) -> str:
    if kind not in {"api", "reconcile"}:
        raise ValueError("Unsupported Operations API unit")
    values = {"daybook_operations_api_" + k: v for k, v in cfg.model_dump().items()}
    values.update(daybook_operations_api_site=str(cfg.site_path), daybook_operations_api_venv=str(cfg.venv_path))
    return templates().get_template("service.j2").render(**values, item=kind)


def render_route(cfg: OperationsApiConfig) -> str:
    return (
        templates()
        .get_template("traefik.yml.j2")
        .render(
            daybook_operations_api_domain=cfg.domain,
            daybook_operations_api_allowed_networks=cfg.allowed_networks,
            daybook_operations_api_port=cfg.port,
        )
    )
