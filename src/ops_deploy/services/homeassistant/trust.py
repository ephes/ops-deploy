"""Prepared original unit trust admission; no drop-in or service mutations."""

from __future__ import annotations

import base64
import hashlib
import json
import shlex
from importlib.resources import files
from typing import Literal

from pyinfra.api import DeployError

from ops_deploy.helpers.probes import probe

from .runtime_config import HomeAssistantRuntimeConfig


def dropin_text() -> str:
    return files("ops_deploy.services.homeassistant").joinpath("templates/uv-system-certs.conf.j2").read_text()


def trust_command(
    cfg: HomeAssistantRuntimeConfig,
    mode: Literal["preflight", "verify"],
    *,
    allow_missing_unit: bool = False,
) -> str:
    source = files("ops_deploy.services.homeassistant").joinpath("files/uv_system_certs_check.py").read_bytes()
    encoded = base64.b64encode(source).decode()
    launcher = f"import base64;exec(compile(base64.b64decode('{encoded}'),'<ha-unit-trust>','exec'))"
    args = [
        "/usr/bin/python3",
        "-I",
        "-B",
        "-c",
        launcher,
        "--unit",
        cfg.service_name + ".service",
        "--dropin",
        cfg.uv_system_certs_dropin_path,
        "--dropin-sha256",
        hashlib.sha256(dropin_text().encode()).hexdigest(),
        "--mode",
        mode,
    ]
    if allow_missing_unit:
        args.append("--allow-missing-unit")
    args.extend("--allow-dropin=" + path for path in cfg.uv_system_certs_allowed_dropins)
    return shlex.join(args)


def inspect_trust(
    cfg: HomeAssistantRuntimeConfig,
    mode: Literal["preflight", "verify"],
    *,
    allow_missing_unit: bool = False,
) -> dict[str, object]:
    """Run the unchanged original host program; expose only its fixed schema."""
    result = probe(
        trust_command(cfg, mode, allow_missing_unit=allow_missing_unit),
        name=f"Home Assistant unit trust {mode}",
    )
    try:
        value = json.loads(result or "")
        base = {"load_state", "active_state", "managed_dropin", "problems"}
        if not isinstance(value, dict):
            raise ValueError
        expected = base | {"running_managed_value"} if value.get("load_state") == "loaded" else base
        if set(value) != expected:
            raise ValueError
        if not all(type(value[key]) is str for key in ("load_state", "active_state")):
            raise ValueError
        if type(value["managed_dropin"]) is not bool:
            raise ValueError
        if "running_managed_value" in value and type(value["running_managed_value"]) is not bool:
            raise ValueError
        if type(value["problems"]) is not list or not all(type(item) is str for item in value["problems"]):
            raise ValueError
    except (TypeError, ValueError):
        raise DeployError("Home Assistant unit trust inspection returned an invalid status") from None
    if value["problems"]:
        # Unchanged original messages contain keys/paths only, never values.
        raise DeployError("Home Assistant unit trust: " + "; ".join(value["problems"]))
    return dict(value)
