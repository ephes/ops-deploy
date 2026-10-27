"""Native pinned remote worker with retained model and tool environments."""

from __future__ import annotations

import base64
import json
import shlex
from collections.abc import Mapping
from importlib.resources import files
from typing import Any

from pyinfra import host
from pyinfra.api import deploy
from pyinfra.facts.server import Command
from pyinfra.operations import server

from ops_deploy.core.secrets import SecretContent
from ops_deploy.helpers import mark_read_only
from ops_deploy.ops import secret_stdin

from .config import PACKAGE, VoxhelmRemoteWorkerConfig
from .render import payload


def worker_host_command(data: dict[str, Any], action: str) -> str:
    public = {key: value for key, value in data.items() if key != "contents"}
    public["contents"] = {
        path: {key: value for key, value in resource.items() if key != "content"}
        for path, resource in data.get("contents", {}).items()
    }
    script = files(PACKAGE).joinpath("files/voxhelm_remote_worker_host.py").read_bytes()
    launcher = (
        "import base64;exec(compile(base64.b64decode('"
        + base64.b64encode(script).decode()
        + "'),'<voxhelm-remote-worker>','exec'))"
    )
    return shlex.join(
        [
            "/usr/bin/python3",
            "-B",
            "-c",
            launcher,
            action,
            base64.b64encode(json.dumps(public).encode()).decode(),
        ]
    )


@deploy("Deploy native Voxhelm remote worker")
def deploy_voxhelm_remote_worker(cfg: VoxhelmRemoteWorkerConfig, secrets: Mapping[str, str]) -> None:
    if not cfg.voxhelm_remote_worker_enabled:
        return
    data = payload(cfg, secrets)
    if host.get_fact(Command, command=worker_host_command(data, "status")) != "current":
        secret_stdin(
            name="Converge native worker package, profiles, environment and launchd",
            command=worker_host_command(data, "apply"),
            content=SecretContent(json.dumps(data) + "\n"),
        )
    mark_read_only(
        server.shell(name="Verify native Voxhelm worker state", commands=[worker_host_command(data, "verify")])
    )
