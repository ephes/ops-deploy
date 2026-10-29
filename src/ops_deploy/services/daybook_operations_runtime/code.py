"""Original Atlas user-owned code prerequisite, source-only work in progress."""

from __future__ import annotations

import base64
import io
import json
import shlex
import uuid
from importlib.resources import files
from pathlib import Path
from typing import Any, cast

from pyinfra import host
from pyinfra.api import DeployError, deploy
from pyinfra.facts.server import Command, Os
from pyinfra.operations import files as file_ops

from ops_deploy.core.git_source import SourceTree
from ops_deploy.core.secrets import SecretContent
from ops_deploy.helpers import mark_read_only
from ops_deploy.ops import secret_stdin
from ops_deploy.services.daybook_sessions import DaybookSessionsConfig
from ops_deploy.services.daybook_sessions.source import (
    register_transfer_cleanup,
    source_payload,
    upload_sessions_bundle,
    verify_controller_bundle,
)

from .config import DaybookRuntimeConfig

PACKAGE = "ops_deploy.services.daybook_operations_runtime"


def source_config(cfg: DaybookRuntimeConfig) -> DaybookSessionsConfig:
    # This is the declared Atlas no-become path. Studio's root code remains the
    # separate original Inbox dependency; it does not enter this component.
    if cfg.install_root is None or cfg.python is None:
        raise ValueError("Original runtime code needs declared absolute paths")
    if cfg.owner != "user" or cfg.python != cfg.install_root / "daybook/.venv/bin/python":
        raise ValueError("User-owned runtime code requires its original checkout interpreter")
    return DaybookSessionsConfig(
        daybook_sessions_enabled=True,
        daybook_sessions_service_user=cfg.user,
        daybook_sessions_service_group="staff",
        daybook_sessions_service_home=str(cfg.home),
        daybook_sessions_checkout_path=str(cfg.install_root / "daybook"),
        daybook_sessions_repo_ref=cfg.revision,
        daybook_sessions_repo_bundle_path=str(cfg.install_root / "daybook.bundle"),
        daybook_sessions_repo_update=True,
        daybook_sessions_checkout_force=False,
        daybook_sessions_uv_bin=str(cfg.uv_bin),
        daybook_sessions_python_version=cfg.python_version,
        daybook_sessions_uv_sync_args=[
            "sync",
            "--frozen",
            "--no-dev",
            "--no-python-downloads",
            "--python",
            cfg.python_version,
        ],
        daybook_sessions_launchd_scope="user",
        daybook_sessions_launchd_manage_state=False,
        daybook_archive_quote_classifier_enabled=False,
        daybook_weeknotes_reconcile_enabled=False,
    )


def code_command(action: str) -> str:
    if action not in {"status", "guard", "prepare-transfer", "apply", "verify"}:
        raise ValueError("Unsupported original runtime code prerequisite action")
    parts = ["import base64,sys,types"]
    for module, package, resource in (
        ("ops_daybook_observer", PACKAGE, "files/runtime_state.py"),
        ("ops_daybook_guards", PACKAGE, "guards.py"),
        ("ops_daybook_stage", PACKAGE, "files/runtime_stage.py"),
        ("ops_runtime_code_source", "ops_deploy.services.daybook_sessions", "files/source_host.py"),
    ):
        encoded = base64.b64encode(files(package).joinpath(resource).read_bytes()).decode()
        parts.append(
            f"m=types.ModuleType('{module}');sys.modules[m.__name__]=m;exec(compile(base64.b64decode('{encoded}'),'<{module}>','exec'),m.__dict__)"
        )
    encoded = base64.b64encode(files(PACKAGE).joinpath("files/runtime_code_guard.py").read_bytes()).decode()
    parts.append(f"exec(compile(base64.b64decode('{encoded}'),'<runtime-code>','exec'),{{'__name__':'__main__'}})")
    return shlex.join(["/usr/bin/python3", "-I", "-B", "-c", ";".join(parts), action])


@deploy("Install original user-owned runtime source without activation")
def _install_user_code(cfg: DaybookRuntimeConfig, source: SourceTree, bundle: Path) -> None:
    if host.get_fact(Os) != "Darwin":
        raise DeployError("Original user-owned runtime code supports Darwin targets only")
    legacy = source_config(cfg)
    verify_controller_bundle(bundle, cfg.revision)
    data = {**source_payload(legacy, source), "label": cfg.label}
    body = json.dumps(data) + "\n"
    with io.StringIO(body) as stream:
        state = host.get_fact(Command, command=code_command("status"), _stdin=stream, _get_pty=False)
    if state not in {"current", "change"}:
        raise DeployError("Original runtime code precondition is unavailable")
    # A queued guard precedes every managed directory/install/transfer operation.
    # Metadata planning cannot silently stand in for that execution-time guard.
    mark_read_only(
        secret_stdin(
            name="Verify original runtime code is current or quiescent",
            command=code_command("guard"),
            content=SecretContent(body),
        )
    )
    file_ops.directory(
        name="Ensure original user-owned runtime install root",
        path=str(cfg.install_root),
        user=cfg.user,
        group="staff",
        mode="0755",
    )
    if state == "change":
        data["transfer_dir"] = "/private/var/tmp/ops-deploy-daybook-source-" + uuid.uuid4().hex
        data["bundle_path"] = str(Path(data["transfer_dir"]) / "daybook.bundle")
        # Always transfer on a genuine source/env replacement: original code.yml
        # removes a readable different checkout, including its old object store.
        prepared = secret_stdin(
            name="Prepare private existing-identity runtime code transfer",
            command=code_command("prepare-transfer"),
            content=SecretContent(json.dumps(data) + "\n"),
        )
        uploaded = cast(Any, upload_sessions_bundle)(
            name="Upload exact original runtime Main bundle", src=str(bundle), dest=data["bundle_path"]
        )
        data["staged_bundle"] = True
        applied = secret_stdin(
            name="Converge original user-owned runtime code and locked environment",
            command=code_command("apply"),
            content=SecretContent(json.dumps(data) + "\n"),
        )
        register_transfer_cleanup(data, prepared, uploaded, applied)
    mark_read_only(
        secret_stdin(
            name="Verify original runtime code and environment without application calls",
            command=code_command("verify"),
            content=SecretContent(json.dumps({**data, "staged_bundle": False}) + "\n"),
        )
    )


@deploy("Install original Atlas runtime source and locked environment")
def install_daybook_runtime_code(cfg: DaybookRuntimeConfig, source: SourceTree, bundle: Path) -> None:
    source_config(cfg)  # Validate before entering any host operation/fact.
    cast(Any, _install_user_code)(
        cfg,
        source,
        bundle,
        _sudo=False,
        _sudo_user="",
        _su_user="",
        _doas=False,
        _doas_user="",
        _dzdo=False,
        _dzdo_user="",
    )
