"""Original Sessions checkout/locked environment using the shared Main bundle."""

from __future__ import annotations

import base64
import io
import json
import shlex
import subprocess
import uuid
from collections.abc import Generator
from importlib.resources import files
from pathlib import Path
from typing import Any

from pyinfra import host, logger
from pyinfra.api import DeployError, Host, State, StringCommand, deploy, operation
from pyinfra.api.arguments import ConnectorArguments
from pyinfra.api.command import FileUploadCommand
from pyinfra.api.exceptions import ConnectError
from pyinfra.api.operation import OperationMeta
from pyinfra.api.state import BaseStateCallback
from pyinfra.facts.server import Command, Os

from ops_deploy.core.git_source import SourceTree
from ops_deploy.core.secrets import SecretContent
from ops_deploy.helpers import mark_read_only
from ops_deploy.ops import secret_stdin
from ops_deploy.services.daybook_operations_runtime.inspect import daybook_code_manifest

from .config import PACKAGE, DaybookSessionsConfig


def source_payload(cfg: DaybookSessionsConfig, source: SourceTree) -> dict[str, Any]:
    arguments = cfg.daybook_sessions_uv_sync_args
    if (
        not arguments
        or arguments[0] != "sync"
        or "--python" not in arguments
        or arguments.count("--python") != 1
        or arguments[arguments.index("--python") + 1 :] == []
        or arguments[arguments.index("--python") + 1] != cfg.daybook_sessions_python_version
        or any(
            arg.split("=", 1)[0] in {"--directory", "--project", "--active", "--script", "--system", "-p"}
            or (arg.startswith("--python") and arg != "--python")
            or arg.startswith("-p")
            or arg.split("=", 1)[0] in {"--no-managed-python", "--managed-python", "--config-file", "--no-config"}
            for arg in arguments
        )
        or any(any(c in argument for c in "\x00\r\n") for argument in arguments)
    ):
        raise ValueError("Sessions sync must retain its declared checkout and Python selector")
    require_reconcile = cfg.daybook_sessions_launchd_scope == "system" and cfg.daybook_sessions_launchd_manage_state
    if require_reconcile and (
        cfg.daybook_weeknotes_reconcile_launchd_label != "de.wersdoerfer.daybook.weeknotes-reconcile"
        or cfg.daybook_weeknotes_reconcile_launchd_plist_path
        != "/Library/LaunchDaemons/de.wersdoerfer.daybook.weeknotes-reconcile.plist"
    ):
        raise ValueError("Sessions source requires the original system reconcile identity")
    return {
        "require_reconcile_quiescence": require_reconcile,
        "user": cfg.daybook_sessions_service_user,
        "group": cfg.daybook_sessions_service_group,
        "owner": "user",
        "checkout": cfg.daybook_sessions_checkout_path,
        "python": cfg.daybook_sessions_checkout_path + "/.venv/bin/python",
        "python_version": cfg.daybook_sessions_python_version,
        "uv_bin": cfg.daybook_sessions_uv_bin,
        "path": cfg.daybook_sessions_launchd_path,
        "revision": cfg.daybook_sessions_repo_ref,
        "repo_url": cfg.daybook_sessions_repo_url,
        "force": cfg.daybook_sessions_checkout_force,
        "allow_create": cfg.daybook_sessions_repo_update,
        "bundle_path": cfg.daybook_sessions_repo_bundle_path,
        "source_hashes": daybook_code_manifest(source, cfg.daybook_sessions_repo_ref),
        "sync_args": arguments,
        "staged_bundle": False,
    }


def source_command(action: str) -> str:
    if action not in {"status", "prepare-transfer", "cleanup-transfer", "apply", "verify"}:
        raise ValueError("Unsupported Sessions source action")
    runtime = "ops_deploy.services.daybook_operations_runtime"
    parts = ["import base64,sys,types"]
    for module, package, resource in (
        ("ops_daybook_observer", runtime, "files/runtime_state.py"),
        ("ops_daybook_guards", runtime, "guards.py"),
        ("ops_daybook_stage", runtime, "files/runtime_stage.py"),
    ):
        body = base64.b64encode(files(package).joinpath(resource).read_bytes()).decode()
        parts.append(
            f"m=types.ModuleType('{module}');sys.modules[m.__name__]=m;"
            f"exec(compile(base64.b64decode('{body}'),'<{module}>','exec'),m.__dict__)"
        )
    body = base64.b64encode(files(PACKAGE).joinpath("files/source_host.py").read_bytes()).decode()
    parts.append(f"exec(compile(base64.b64decode('{body}'),'<sessions-source>','exec'))")
    return shlex.join(["/usr/bin/python3", "-I", "-B", "-c", ";".join(parts), action])


def inspect_sessions_source(cfg: DaybookSessionsConfig, source: SourceTree) -> dict[str, bool]:
    data = source_payload(cfg, source)
    with io.StringIO(json.dumps(data) + "\n") as stream:
        result = host.get_fact(Command, command=source_command("status"), _stdin=stream, _get_pty=False)
    try:
        state = json.loads(result or "")
        if not isinstance(state, dict) or set(state) != {
            "current",
            "needs_bundle",
            "delegate",
            "reconcile_ready",
        }:
            raise ValueError
        if any(type(value) is not bool for value in state.values()):
            raise ValueError
    except (ValueError, TypeError):
        raise DeployError("Sessions source inspection is unavailable") from None
    return state


def verify_controller_bundle(bundle: Path, revision: str) -> None:
    if not bundle.is_file() or bundle.is_symlink():
        raise ValueError("Sessions source requires the run's immutable controller bundle")
    heads = subprocess.run(["/usr/bin/git", "bundle", "list-heads", str(bundle)], capture_output=True, timeout=30)
    if heads.returncode or not any(
        line.startswith(revision.encode() + b" refs/") for line in heads.stdout.splitlines()
    ):
        raise ValueError("Sessions controller bundle does not carry the declared commit")


class BundleUploadCommand(FileUploadCommand):
    """Keep SFTP-setup errors in normal failed-op/callback accounting."""

    def execute(self, state: State, target: Host, connector_arguments: ConnectorArguments) -> bool:
        try:
            return bool(super().execute(state, target, connector_arguments))
        except ConnectError:
            # pyinfra's upload executor catches OSError/SSHException but not
            # ConnectError. A false result triggers its ordinary failure cleanup
            # callback; the transfer is never relabeled successful.
            logger.error("Sessions source SFTP setup failed")
            return False


@operation()
def upload_sessions_bundle(src: str, dest: str) -> Generator[FileUploadCommand | StringCommand, None, None]:
    # Ordinary existing-identity SFTP; no sudo upload/shared plaintext staging.
    # The parent is already owner-private 0700 until descriptor publication.
    yield BundleUploadCommand(src, dest)
    yield StringCommand(shlex.join(["/bin/chmod", "0600", dest]))


def register_transfer_cleanup(
    data: dict[str, Any],
    prepared: OperationMeta,
    uploaded: OperationMeta,
    applied: OperationMeta,
) -> None:
    armed = {"value": False}

    class TransferCleanup(BaseStateCallback):
        @staticmethod
        def operation_host_success(state: State, target: Host, op_hash: str, retry_count: int = 0) -> None:
            operation = state.get_op_data_for_host(target, op_hash).operation_meta
            if operation is prepared:
                armed["value"] = True
            elif operation is applied:
                armed["value"] = False

        @staticmethod
        def operation_host_error(
            state: State,
            target: Host,
            op_hash: str,
            retry_count: int = 0,
            max_retries: int = 0,
        ) -> None:
            operation = state.get_op_data_for_host(target, op_hash).operation_meta
            if armed["value"] and (operation is uploaded or operation is applied):
                armed["value"] = False
                try:
                    with io.StringIO(json.dumps(data) + "\n") as stream:
                        success, _ = target.run_shell_command(
                            source_command("cleanup-transfer"),
                            _stdin=stream,
                            _get_pty=False,
                        )
                except Exception:
                    success = False
                if not success:
                    # Preserve the original failed op; no child error/body dump.
                    logger.error("Sessions source temporary transport cleanup failed")

    host.state.add_callback_handler(TransferCleanup())


@deploy("Install exact Sessions source and locked managed environment")
def install_sessions_source(cfg: DaybookSessionsConfig, source: SourceTree, bundle: Path) -> None:
    if not cfg.daybook_sessions_enabled:
        return
    if host.get_fact(Os) != "Darwin":
        raise DeployError("Daybook Sessions supports Darwin targets only")
    verify_controller_bundle(bundle, cfg.daybook_sessions_repo_ref)
    data = source_payload(cfg, source)
    state = inspect_sessions_source(cfg, source)
    if not state["current"]:
        if state["needs_bundle"]:
            data["transfer_dir"] = "/private/var/tmp/ops-deploy-daybook-source-" + uuid.uuid4().hex
            data["bundle_path"] = str(Path(data["transfer_dir"]) / Path(cfg.daybook_sessions_repo_bundle_path).name)
            prepared = secret_stdin(
                name="Prepare private temporary Daybook source upload directory",
                command=source_command("prepare-transfer"),
                content=SecretContent(json.dumps(data) + "\n"),
            )
            uploaded = upload_sessions_bundle(
                name="Stage exact Daybook Main source bundle",
                src=str(bundle),
                dest=data["bundle_path"],
            )
            data["staged_bundle"] = True
        applied = secret_stdin(
            name="Converge declared Sessions checkout and locked managed Python",
            command=source_command("apply"),
            content=SecretContent(json.dumps(data) + "\n"),
        )
        if state["needs_bundle"]:
            register_transfer_cleanup(data, prepared, uploaded, applied)
    mark_read_only(
        secret_stdin(
            name="Verify Sessions source and environment without application calls",
            command=source_command("verify"),
            content=SecretContent(json.dumps({**data, "staged_bundle": False}) + "\n"),
        )
    )
