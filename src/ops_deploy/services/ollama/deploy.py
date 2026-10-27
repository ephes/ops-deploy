"""Idempotent native Darwin deployment; no changes to retained model contents."""

from __future__ import annotations

import base64
import json
import shlex
from collections.abc import Generator
from importlib.resources import files
from typing import Any

import jinja2
from pyinfra import host
from pyinfra.api import StringCommand, deploy, operation
from pyinfra.facts.server import Command
from pyinfra.operations import server

from ops_deploy.helpers import mark_read_only

from .config import OllamaConfig

PACKAGE = "ops_deploy.services.ollama"
HOST_SCRIPT = files(PACKAGE).joinpath("files/ollama_host.py").read_text()
AUTO_BINARY = "__OPS_DEPLOY_OLLAMA_BINARY__"


def template_vars(cfg: OllamaConfig, binary_path: str) -> dict[str, Any]:
    return {
        "ollama_launchd_label": cfg.launchd_label,
        "ollama_binary_path_resolved": binary_path,
        "ollama_launchd_command": cfg.launchd_command,
        "ollama_launchd_command_args": cfg.launchd_command_args,
        "ollama_env": cfg.env,
        "ollama_service_user": cfg.user,
        "ollama_service_group": cfg.group,
        "ollama_service_home": str(cfg.site_path),
        "ollama_log_dir": str(cfg.log_dir),
    }


def render_plist(cfg: OllamaConfig, binary_path: str) -> str:
    environment = jinja2.Environment(
        loader=jinja2.PackageLoader(PACKAGE, "templates"),
        undefined=jinja2.StrictUndefined,
        keep_trailing_newline=True,
        trim_blocks=True,
        autoescape=True,
    )
    return environment.get_template("ollama.launchd.plist.j2").render(**template_vars(cfg, binary_path))


def host_command(cfg: OllamaConfig, action: str) -> str:
    data = cfg.model_dump(mode="json")
    data["plist"] = render_plist(cfg, str(cfg.binary_path) if cfg.binary_path else AUTO_BINARY)
    script = base64.b64encode(HOST_SCRIPT.encode()).decode()
    config = base64.b64encode(json.dumps(data).encode()).decode()
    launcher = f"import base64;exec(compile(base64.b64decode('{script}'),'<ollama-host>','exec'))"
    return shlex.join(["/usr/bin/python3", "-B", "-c", launcher, action, config])


@operation()
def _converge(cfg: OllamaConfig) -> Generator[StringCommand, None, None]:
    current = host.get_fact(Command, command=host_command(cfg, "status"))
    if current != "current":
        yield StringCommand(host_command(cfg, "apply"))


@deploy("Deploy native Ollama on macOS")
def deploy_ollama(cfg: OllamaConfig) -> None:
    if not cfg.enabled:
        return
    _converge(name="Converge Ollama Homebrew, identity, directories and launchd", cfg=cfg)
    mark_read_only(
        server.shell(name="Verify Ollama launchd and optional HTTP health", commands=[host_command(cfg, "verify")])
    )
