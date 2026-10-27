"""Full native Voxhelm role sequence without incidental runtime syncs."""

from __future__ import annotations

import base64
import json
import os
import shlex
import subprocess
import tomllib
from collections.abc import Callable, Mapping
from importlib.resources import files
from io import StringIO
from pathlib import Path, PurePosixPath
from typing import Any

from pyinfra import host
from pyinfra.api import deploy
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.server import Command
from pyinfra.operations import files as remote_files
from pyinfra.operations import server

from ops_deploy.core.rsync import RsyncRunner, subprocess_rsync_runner
from ops_deploy.core.secrets import SecretContent
from ops_deploy.helpers import mark_read_only
from ops_deploy.helpers.probes import probe, verify_probe
from ops_deploy.ops import secret_stdin, sync_tree

from .config import PACKAGE, VoxhelmConfig
from .render import payload


def voxhelm_host_command(data: dict[str, Any], action: str) -> str:
    private_fields = {
        "contents",
        "bootstrap",
        "voxhelm_bootstrap_operator_username",
        "voxhelm_bootstrap_operator_email",
    }
    public = {key: value for key, value in data.items() if key not in private_fields}
    public["contents"] = {
        path: {key: value for key, value in resource.items() if key != "content"}
        for path, resource in data["contents"].items()
    }
    script = files(PACKAGE).joinpath("files/voxhelm_host.py").read_bytes()
    launcher = (
        "import base64;exec(compile(base64.b64decode('"
        + base64.b64encode(script).decode()
        + "'),'<voxhelm-host>','exec'))"
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


def _owed(needed: bool, *operations: OperationMeta) -> Callable[[], bool]:
    return lambda: needed or any(op.did_change() for op in operations)


def source_overrides(cfg: VoxhelmConfig) -> dict[str, str]:
    """Retain old public blobs only for the explicitly selected clean revision.

    A changed revision or working tree resumes ordinary rsync behavior. Status
    cannot refresh the source index, and no source cache is created.
    """
    if not cfg.source_overrides:
        return {}
    env = {**os.environ, "GIT_OPTIONAL_LOCKS": "0"}
    prefix = ["git", "--no-optional-locks", "-C", cfg.voxhelm_source_path]
    head = subprocess.run([*prefix, "rev-parse", "HEAD"], capture_output=True, text=True, env=env, timeout=30)
    if head.returncode or head.stdout.strip() != cfg.source_preservation_revision:
        return {}
    status = subprocess.run(
        [*prefix, "status", "--porcelain", "--untracked-files=normal"],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )
    if status.returncode:
        raise ValueError("Voxhelm source selection could not be inspected")
    return {} if status.stdout.strip() else dict(cfg.source_overrides)


def generated_launchers(cfg: VoxhelmConfig) -> list[str]:
    """Anchored excludes for rendered launchers inside the synced application tree.

    They are not part of the source, so ``--delete`` would remove them on every
    run (the role protects only prune.sh, then re-renders the rest). Disabled
    components' scripts are retained too, as their deployments stay unmanaged.
    """

    app = PurePosixPath(cfg.voxhelm_app_dir)
    paths = [
        cfg.voxhelm_start_script_path,
        cfg.voxhelm_worker_script_path,
        cfg.voxhelm_wyoming_stt_script_path,
        cfg.voxhelm_whisperkit_script_path,
        cfg.voxhelm_prune_script_path,
    ]
    inside = [PurePosixPath(path) for path in paths if PurePosixPath(path).is_relative_to(app)]
    return sorted({"/" + str(path.relative_to(app)) for path in inside})


@deploy("Deploy native Voxhelm control plane")
def deploy_voxhelm(
    cfg: VoxhelmConfig, secrets: Mapping[str, str], *, rsync: RsyncRunner = subprocess_rsync_runner
) -> None:
    data = payload(cfg, secrets)
    try:
        data["project_version"] = tomllib.loads((Path(cfg.voxhelm_source_path) / "pyproject.toml").read_text())[
            "project"
        ]["version"]
    except (OSError, ValueError, KeyError, TypeError):
        raise ValueError("Voxhelm source must declare its application version") from None

    def owed(action: str) -> bool:
        return host.get_fact(Command, command=voxhelm_host_command(data, action + "-status")) != "current"

    prepare_needed = owed("prepare")
    prepared = server.shell(
        name="Prepare native Voxhelm directories and logs",
        commands=[voxhelm_host_command(data, "prepare-apply")],
        _if=lambda: prepare_needed,
    )
    source_operations: list[OperationMeta] = []
    server.shell(
        name="Remember pending Voxhelm source update",
        commands=[voxhelm_host_command(data, "mark")],
        _if=lambda: any(op.will_change for op in source_operations),
    )
    retained = source_overrides(cfg)
    source_operations.append(
        sync_tree(
            name="Sync Voxhelm application source",
            src=cfg.voxhelm_source_path,
            dest=cfg.voxhelm_app_dir,
            user="root",
            group="wheel",
            chmod="D0755,F0755",
            excludes=[*cfg.voxhelm_sync_excludes, *generated_launchers(cfg), *("/" + path for path in retained)],
            rsync_path=cfg.remote_rsync_path,
            prepared_by=prepared,
            runner=rsync,
        )
    )
    for relative, content in retained.items():
        source_operations.append(
            remote_files.put(
                name="Retain selected Voxhelm source blob " + relative,
                src=StringIO(content),
                dest=cfg.voxhelm_app_dir + "/" + relative,
                user="root",
                group="wheel",
                mode="0755",
            )
        )
    runtime = server.shell(
        name="Sync selected Voxhelm Python environment",
        commands=[voxhelm_host_command(data, "runtime-apply")],
        _if=_owed(owed("runtime"), *source_operations),
    )
    server.shell(
        name="Provision missing Voxhelm packages and models",
        commands=[voxhelm_host_command(data, "models-apply")],
        _if=_owed(owed("models")),
    )
    config = secret_stdin(
        name="Render native Voxhelm environment, launchers and plists",
        command=voxhelm_host_command(data, "config-apply"),
        content=SecretContent(json.dumps(data) + "\n"),
        _if=_owed(owed("config")),
    )
    server.shell(
        name="Apply pending Voxhelm database migrations",
        commands=[voxhelm_host_command(data, "migrations-apply")],
        _if=_owed(owed("migrations"), *source_operations, runtime),
    )
    bootstrap_input = json.dumps(data) + "\n"
    bootstrap_state = probe(
        voxhelm_host_command(data, "bootstrap-check"),
        name="Voxhelm operator password and flags",
        stdin=bootstrap_input,
    )
    if bootstrap_state not in {"current", "drift", None}:
        raise ValueError("Voxhelm bootstrap probe returned an unexpected state")
    secret_stdin(
        name="Reconcile Voxhelm bootstrap operator only when needed",
        command=voxhelm_host_command(data, "bootstrap-apply"),
        content=SecretContent(bootstrap_input),
        _if=lambda: bootstrap_state != "current",
    )
    verify_probe(
        voxhelm_host_command(data, "bootstrap-check"),
        name="Voxhelm operator password and flags",
        expect="current",
        stdin=bootstrap_input,
    )
    launchd_needed = owed("launchd")
    launchd = server.shell(
        name="Converge native Voxhelm launchd services and pruning schedule",
        commands=[voxhelm_host_command(data, "launchd-apply")],
        _if=_owed(launchd_needed, *source_operations, runtime, config),
    )
    server.shell(
        name="Complete verified Voxhelm restart intent",
        commands=[voxhelm_host_command(data, "finish")],
        _if=_owed(False, *source_operations, runtime, config, launchd),
    )
    mark_read_only(
        server.shell(name="Verify native Voxhelm health and listeners", commands=[voxhelm_host_command(data, "verify")])
    )
