"""Deterministic public TOML, systemd and route renderers."""

from __future__ import annotations

import json
import math
import re

from ops_deploy.core.templates import render
from ops_deploy.helpers.traefik import TraefikRoute
from ops_deploy.services.native_app.config import NativeAppConfig, TomlData, TomlScalar


def _scalar(value: TomlScalar) -> str:
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("TOML floats must be finite")
    return str(value)


def render_toml(data: TomlData) -> str:
    lines = ["# Managed by ops-deploy"]
    for key, value in data.items():
        if not re.fullmatch(r"[A-Za-z0-9_-]+", key):
            raise ValueError("TOML keys must be plain names")
        if not isinstance(value, dict):
            lines.append(f"{key} = {_scalar(value)}")
    for key, value in data.items():
        if isinstance(value, dict):
            lines += ["", f"[{key}]"]
            for subkey, item in value.items():
                if not re.fullmatch(r"[A-Za-z0-9_-]+", subkey):
                    raise ValueError("TOML keys must be plain names")
                lines.append(f"{subkey} = {_scalar(item)}")
    return "\n".join(lines) + "\n"


def systemd_word(value: str) -> str:
    # systemd's argv parser is not a shell; escape its specifiers and env expansion.
    return json.dumps(value.replace("%", "%%").replace("$", "$$"))


def environment_word(value: str) -> str:
    # Environment= expands specifiers, but does not expand dollar variables.
    return json.dumps(value.replace("%", "%%"))


def render_unit(cfg: NativeAppConfig) -> str:
    return render(
        "ops_deploy.services.native_app", "unit.service.j2", cfg=cfg, word=systemd_word, env_word=environment_word
    )


def render_route(route: TraefikRoute, auth_hash: str | None) -> str:
    return render("ops_deploy.services.native_app", "route.yml.j2", route=route, auth_hash=auth_hash)
