"""Full native OpsGate role sequence, with changed-only source/runtime work."""

from __future__ import annotations

import base64
import hashlib
import json
import shlex
import tomllib
from collections.abc import Callable, Mapping
from importlib.resources import files
from pathlib import Path
from typing import Any

from pyinfra import host
from pyinfra.api import deploy
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.server import Command
from pyinfra.operations import server

from ops_deploy.core.rsync import RsyncRunner, subprocess_rsync_runner
from ops_deploy.core.secrets import SecretContent
from ops_deploy.helpers import mark_read_only
from ops_deploy.ops import secret_stdin, sync_tree

from .config import PACKAGE, OpsGateConfig
from .render import payload


def opsgate_host_command(data: dict[str, Any], action: str) -> str:
    private_fields = {
        "contents",
        "archive_payload",
        "opsgate_ui_username",
        "opsgate_ops_git_user_name",
        "opsgate_ops_git_user_email",
        "opsgate_ops_github_username",
    }
    public = {key: value for key, value in data.items() if key not in private_fields}
    public["contents"] = {
        path: {key: value for key, value in resource.items() if key != "content"}
        | {"sha256": hashlib.sha256(resource["content"].encode()).hexdigest()}
        for path, resource in data["contents"].items()
    }
    code = files(PACKAGE).joinpath("files/opsgate_host.py").read_bytes()
    launcher = (
        "import base64;exec(compile(base64.b64decode('"
        + base64.b64encode(code).decode()
        + "'),'<opsgate-host>','exec'))"
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


# The rollback environment is an editable ``uv sync`` of the setuptools
# project, which writes ``src/opsgate.egg-info`` into the synced tree. It is not
# source, so ``--delete`` would remove it on every run and re-trigger the sync.
BUILD_METADATA = ["*.egg-info"]


def _source(
    cfg: OpsGateConfig, data: dict[str, Any], unit: str, prepared: OperationMeta, rsync: RsyncRunner
) -> OperationMeta:
    source: OperationMeta
    # Evaluated during execution, after all operation metadata is registered.
    # The marker precedes the actual source transfer, so a failed later step
    # cannot lose a Python restart/dependency update triggered by that transfer.
    server.shell(
        name=f"Remember pending {unit} source update",
        commands=[opsgate_host_command(data, "mark-" + unit)],
        _if=lambda: source.will_change,
    )
    path = cfg.opsgate_app_dir if unit == "api" else cfg.opsgate_runner_app_dir
    user = cfg.control_service_user if unit == "api" else cfg.ops_user
    group = cfg.control_service_group if unit == "api" else cfg.ops_group
    source = sync_tree(
        name=f"Sync OpsGate {unit} application source",
        src=cfg.opsgate_source_path,
        dest=path,
        user=user,
        group=group,
        excludes=[*cfg.opsgate_rsync_excludes, *BUILD_METADATA],
        chmod="D0750,F0750",
        rsync_path=cfg.remote_rsync_path,
        prepared_by=prepared,
        runner=rsync,
    )
    return source


def _runtime_needed(source: OperationMeta, needed: bool) -> Callable[[], bool]:
    return lambda: needed or source.did_change()


@deploy("Deploy native OpsGate API and runner")
def deploy_opsgate(
    cfg: OpsGateConfig, secrets: Mapping[str, Any], *, rsync: RsyncRunner = subprocess_rsync_runner
) -> None:
    data = payload(cfg, secrets)
    try:
        data["project_version"] = tomllib.loads((Path(cfg.opsgate_source_path) / "pyproject.toml").read_text())[
            "project"
        ]["version"]
    except (OSError, ValueError, KeyError, TypeError):
        raise ValueError("OpsGate source must declare its application version") from None
    prepare_needed = host.get_fact(Command, command=opsgate_host_command(data, "prepare-status")) != "current"
    prepared = server.shell(
        name="Prepare native OpsGate accounts and directories",
        commands=[opsgate_host_command(data, "prepare-apply")],
        _if=lambda: prepare_needed,
    )
    sources = {}
    runtimes = {}
    for unit in ("api", "runner"):
        source = _source(cfg, data, unit, prepared, rsync)
        runtime_needed = (
            host.get_fact(Command, command=opsgate_host_command(data, "runtime-status-" + unit)) != "current"
        )
        runtime = server.shell(
            name=f"Sync OpsGate {unit} Python rollback environment",
            commands=[opsgate_host_command(data, "runtime-apply-" + unit)],
            _if=_runtime_needed(source, runtime_needed),
        )
        sources[unit], runtimes[unit] = source, runtime
    config_needed = host.get_fact(Command, command=opsgate_host_command(data, "config-status")) != "current"
    secret_stdin(
        name="Converge native OpsGate credentials, workspaces, pinned release and launchd",
        command=opsgate_host_command(data, "config-apply"),
        content=SecretContent(json.dumps(data) + "\n"),
        _if=lambda: config_needed or any(op.did_change() for op in [*sources.values(), *runtimes.values()]),
    )
    mark_read_only(
        server.shell(
            name="Verify native OpsGate implementations and API", commands=[opsgate_host_command(data, "verify")]
        )
    )
