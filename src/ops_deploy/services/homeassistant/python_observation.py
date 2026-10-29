"""Prepared service-user observation, preserving pre/post replacement ordering."""

from __future__ import annotations

import base64
import json
from dataclasses import fields, replace
from importlib.resources import files
from pathlib import PurePosixPath
from typing import Literal

from pyinfra.api import DeployError

from ops_deploy.helpers.probes import probe
from ops_deploy.helpers.python import _as_user

from .python_state import EnvironmentState, homeassistant_decision, matter_decision
from .runtime_config import HomeAssistantRuntimeConfig

Kind = Literal["homeassistant", "matter"]
Phase = Literal["environment", "application"]


def observation_command(cfg: HomeAssistantRuntimeConfig) -> str:
    source = files("ops_deploy.services.homeassistant").joinpath("files/python_observe.py").read_bytes()
    encoded = base64.b64encode(source).decode()
    launcher = f"import base64;exec(compile(base64.b64decode('{encoded}'),'<ha-python-observation>','exec'))"
    return _as_user(
        cfg.user, PurePosixPath(cfg.home), {"PYTHONDONTWRITEBYTECODE": "1"}, ["python3", "-I", "-B", "-c", launcher]
    )


def _observe(cfg: HomeAssistantRuntimeConfig, kind: Kind, phase: Phase) -> EnvironmentState:
    venv = cfg.virtualenv_path if kind == "homeassistant" else cfg.matter_server_virtualenv_path
    answer = probe(
        observation_command(cfg),
        stdin=json.dumps({"venv": venv, "kind": kind, "phase": phase}),
        name=f"Home Assistant {kind} {phase} state",
    )
    try:
        value = json.loads(answer or "")
        if not isinstance(value, dict) or set(value) != {f.name for f in fields(EnvironmentState)}:
            raise ValueError
        for field, expected in (
            ("python_exists", bool),
            ("application_exists", bool),
            ("python_stdout", str),
            ("installed_version", str),
            ("pip_status", int),
            ("legacy_matter_status", int),
            ("chip_status", int),
        ):
            if type(value[field]) is not expected:
                raise ValueError
        return EnvironmentState(**value)
    except (TypeError, ValueError):
        raise DeployError("Home Assistant Python state inspection failed") from None


def inspect_environment(
    cfg: HomeAssistantRuntimeConfig, kind: Kind, *, llama_cpp_rebuild: bool = False
) -> EnvironmentState:
    current = _observe(cfg, kind, "environment")
    decision = (
        homeassistant_decision(cfg, current, llama_cpp_rebuild=llama_cpp_rebuild)
        if kind == "homeassistant"
        else matter_decision(cfg, current)
    )
    # Original replacement removes the old environment before querying hass or
    # importing chip. Never run those old application imports when replacing it.
    if decision.replace:
        return current
    application = _observe(cfg, kind, "application")
    return replace(
        current,
        application_exists=application.application_exists,
        installed_version=application.installed_version,
        chip_status=application.chip_status,
    )
