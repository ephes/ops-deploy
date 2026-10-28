"""Role-exact serialization, templates and shared fixed unit names."""

from __future__ import annotations

import json
from functools import cache
from importlib.resources import files as resources
from io import StringIO
from typing import Any

import jinja2
from pyinfra.api.operation import OperationMeta
from pyinfra.operations import files, systemd

from ops_deploy.services.software_live.config import SoftwareLiveConfig

RESOURCE = resources("ops_deploy.services.software_live")
PRODUCTION = ("software-live-collector.service", "software-live-collector.timer", "software-live-endpoint.service")
SHADOW = (
    "software-live-shadow-collector.service",
    "software-live-shadow-collector.timer",
    "software-live-shadow-endpoint.service",
)


def nice_json(value: Any) -> str:
    # ansible.builtin.to_nice_json: indent4, sorted keys, ensure_ascii=True.
    return json.dumps(value, indent=4, sort_keys=True) + "\n"


@cache
def environment() -> jinja2.Environment:
    return jinja2.Environment(
        loader=jinja2.PackageLoader("ops_deploy.services.software_live", "templates"),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
        autoescape=False,
    )


def render(template: str, cfg: SoftwareLiveConfig) -> str:
    values = {"software_live_" + key: value for key, value in cfg.model_dump(mode="json").items()}
    values.update(
        _software_live_rust_binary=str(cfg.binary),
        _software_live_shadow_dir=str(cfg.data_dir / "shadow"),
        _software_live_shadow_config=str(cfg.config_dir / "shadow-endpoint.json"),
    )
    rendered = environment().get_template(template).render(**values)
    # Ansible template preserves the source trailing newline after a final block.
    return rendered if rendered.endswith("\n") else rendered + "\n"


def put(path: str, content: str, *, group: str = "root", mode: str = "0644", name: str | None = None) -> OperationMeta:
    return files.put(
        name=name or f"Write {path}", src=StringIO(content), dest=path, user="root", group=group, mode=mode
    )


def unit(cfg: SoftwareLiveConfig, name: str, template: str) -> OperationMeta:
    return put(str(cfg.systemd_dir / name), render(template, cfg), name=f"Install {name}")


def restart(name: str, triggers: list[OperationMeta]) -> OperationMeta:
    return systemd.service(
        name=f"Restart {name}",
        service=name,
        running=None,
        restarted=True,
        _if=lambda: any(op.did_change() for op in triggers),
    )


def endpoint_json(cfg: SoftwareLiveConfig, bind: str, *, shadow: bool = False) -> str:
    return nice_json(
        {
            "bind": "127.0.0.1" if shadow else bind,
            "port": cfg.shadow_port if shadow else cfg.port,
            "path": "/.well-known/software-live",
            "state": str(cfg.state_path),
            "auth_user": cfg.auth_user,
            "htpasswd": str(cfg.config_dir / "htpasswd"),
        }
    )
