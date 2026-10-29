"""Original protected Photos installation and exact-label launchd convergence.

The source bundle is prepared once by the ordinary controller Main resolver.
Only Photos is quiesced; no unrelated operations keeper or private data is read.
"""

from __future__ import annotations

import base64
import io
import json
import shlex
import uuid
from collections.abc import Generator
from importlib.resources import files
from pathlib import Path
from typing import Any

from pyinfra import host, logger
from pyinfra.api import DeployError, Host, State, StringCommand, deploy, operation
from pyinfra.api.command import FileUploadCommand
from pyinfra.api.operation import OperationMeta
from pyinfra.api.state import BaseStateCallback
from pyinfra.facts.server import Command, Os

from ops_deploy.core.git_source import SourceTree
from ops_deploy.core.secrets import SecretContent
from ops_deploy.helpers import mark_read_only
from ops_deploy.ops import secret_stdin
from ops_deploy.services.daybook_sessions.source import BundleUploadCommand

from .config import PACKAGE, DaybookPhotosOffloadConfig
from .payload import component_payload

ACTIONS = frozenset(
    {
        "status",
        "verify",
        "quiesce",
        "source",
        "python",
        "directories",
        "resources",
        "activate",
        "prepare-transfer",
        "cleanup-transfer",
    }
)


def component_command(action: str, *, user: str | None = None) -> str:
    if action not in ACTIONS or (user is not None and action not in {"directories", "resources"}):
        raise ValueError("Unsupported Photos component action/context")
    pieces = ["import base64,sys,types"]
    for module, package, resource in (
        ("ops_photos_filesystem", "ops_deploy.services.daybook_sessions", "files/resources_host.py"),
        ("ops_photos_source", PACKAGE, "files/photos_source.py"),
        ("ops_photos_environment", PACKAGE, "files/photos_environment.py"),
        ("ops_photos_controls", PACKAGE, "files/photos_controls.py"),
        ("ops_photos_resources", PACKAGE, "files/photos_resources.py"),
        ("ops_photos_transfer", PACKAGE, "files/photos_transfer.py"),
    ):
        encoded = base64.b64encode(files(package).joinpath(resource).read_bytes()).decode()
        pieces.append(
            f"m=types.ModuleType('{module}');sys.modules[m.__name__]=m;"
            f"exec(compile(base64.b64decode('{encoded}'),'<{module}>','exec'),m.__dict__)"
        )
    entry = base64.b64encode(files(PACKAGE).joinpath("files/photos_host.py").read_bytes()).decode()
    pieces.append(f"exec(compile(base64.b64decode('{entry}'),'<photos-component>','exec'),{{'__name__':'__main__'}})")
    argv = ["/usr/bin/python3", "-I", "-B", "-c", ";".join(pieces), action]
    if user is not None:
        # Original template/log publication uses the real GUI identity and -H -i.
        argv = ["/usr/bin/sudo", "-n", "-H", "-i", "-u", user, "--", *argv]
    return shlex.join(argv)


def inspect_photos(data: dict[str, Any]) -> dict[str, bool]:
    with io.StringIO(json.dumps(data) + "\n") as stream:
        result = host.get_fact(Command, command=component_command("status"), _stdin=stream, _get_pty=False)
    try:
        value = json.loads(result or "")
        if (
            not isinstance(value, dict)
            or set(value)
            != {
                "source_current",
                "environment_current",
                "directories_current",
                "resources_current",
                "quiescent",
                "state_current",
            }
            or any(type(item) is not bool for item in value.values())
        ):
            raise ValueError
    except (ValueError, TypeError):
        raise DeployError("Photos component observation is unavailable") from None
    return value


@operation()
def upload_photos_bundle(src: str, dest: str) -> Generator[FileUploadCommand | StringCommand, None, None]:
    # SFTP always uses the existing connecting identity. Explicit private parent
    # preparation and descriptor-checked root publication happen separately.
    yield BundleUploadCommand(
        src, dest, _sudo=False, _sudo_user="", _su_user="", _doas=False, _doas_user="", _dzdo=False, _dzdo_user=""
    )
    yield StringCommand(
        shlex.join(["/bin/chmod", "0600", dest]),
        _sudo=False,
        _sudo_user="",
        _su_user="",
        _doas=False,
        _doas_user="",
        _dzdo=False,
        _dzdo_user="",
    )


def _connecting_uid() -> int:
    value = host.get_fact(
        Command,
        command="/usr/bin/id -u",
        _sudo=False,
        _sudo_user="",
        _su_user="",
        _doas=False,
        _doas_user="",
        _dzdo=False,
        _dzdo_user="",
    )
    if not value or not value.isdecimal():
        raise DeployError("Photos original connecting uid is unavailable")
    return int(value)


def _transfer_operation(data: dict[str, Any], *, cleanup: bool = False) -> OperationMeta:
    return secret_stdin(
        name="Clean private existing-identity Photos source transfer"
        if cleanup
        else "Prepare private existing-identity Photos source transfer",
        command=component_command("cleanup-transfer" if cleanup else "prepare-transfer"),
        content=SecretContent(json.dumps(data) + "\n"),
        _sudo=False,
        _sudo_user="",
        _su_user="",
        _doas=False,
        _doas_user="",
        _dzdo=False,
        _dzdo_user="",
    )


def _cleanup_transfer_now(target: Host, data: dict[str, Any]) -> bool:
    with io.StringIO(json.dumps(data) + "\n") as stream:
        success, _ = target.run_shell_command(
            component_command("cleanup-transfer"),
            _stdin=stream,
            _get_pty=False,
            _sudo=False,
            _sudo_user="",
            _su_user="",
            _doas=False,
            _doas_user="",
            _dzdo=False,
            _dzdo_user="",
        )
    return bool(success)


def transfer_cleanup(
    data: dict[str, Any], prepared: OperationMeta, uploaded: OperationMeta, applied: OperationMeta
) -> None:
    armed = {"value": False}

    class Cleanup(BaseStateCallback):
        @staticmethod
        def operation_host_success(state: State, target: Host, op_hash: str, retry_count: int = 0) -> None:
            operation = state.get_op_data_for_host(target, op_hash).operation_meta
            if operation is prepared:
                armed["value"] = True
            elif operation is applied:
                armed["value"] = False

        @staticmethod
        def operation_host_error(
            state: State, target: Host, op_hash: str, retry_count: int = 0, max_retries: int = 0
        ) -> None:
            operation = state.get_op_data_for_host(target, op_hash).operation_meta
            if armed["value"] and (operation is uploaded or operation is applied):
                armed["value"] = False
                try:
                    success = _cleanup_transfer_now(target, data)
                except Exception:
                    success = False
                if not success:
                    logger.error("Photos source temporary transport cleanup failed")

    host.state.add_callback_handler(Cleanup())


@deploy("Install original protected Photos offload components")
def install_daybook_photos_offload(cfg: DaybookPhotosOffloadConfig, source: SourceTree, bundle: Path) -> None:
    """Converge original code/environment/resources, leaving disabled by default.

    No Photos application/library scan, ledger/status query or activation is
    performed unless the original launchd_enabled declaration selects it.
    Pass the derived single-Main bundle from photos_main_bundle and keep that
    controller context alive through actual operation execution.
    """
    if not cfg.daybook_photos_offload_enabled:
        return
    if host.get_fact(Os) != "Darwin":
        raise DeployError("Photos offload supports Darwin targets only")
    user = cfg.daybook_photos_offload_service_user
    uid_raw = host.get_fact(Command, command=shlex.join(["/usr/bin/id", "-u", user]))
    if not uid_raw or not uid_raw.isdecimal() or int(uid_raw) <= 0:
        raise DeployError("Photos GUI account uid is unavailable")
    data = component_payload(cfg, source, bundle, uid=int(uid_raw))
    state = inspect_photos(data)

    def managed(name: str, action: str) -> OperationMeta:
        return secret_stdin(
            name=name,
            command=component_command(action, user=user if action in {"directories", "resources"} else None),
            content=SecretContent(json.dumps(data) + "\n"),
        )

    keys = ("source_current", "environment_current", "directories_current", "resources_current", "state_current")
    if not all(state[key] for key in keys):
        if not state["quiescent"]:
            managed("Quiesce original Photos offload label", "quiesce")
        if not state["source_current"]:
            temporary = "/private/var/tmp/ops-deploy-daybook-photos-" + uuid.uuid4().hex
            data.update(
                transfer_dir=temporary, uploaded_bundle=temporary + "/source.bundle", transfer_uid=_connecting_uid()
            )
            prepared = _transfer_operation(data)
            uploaded = upload_photos_bundle(
                name="Upload exact Photos Main bundle", src=str(bundle), dest=data["uploaded_bundle"]
            )
            applied = managed("Converge original protected Photos checkout", "source")
            transfer_cleanup(data, prepared, uploaded, applied)
        if not state["environment_current"] or not state["source_current"]:
            managed("Converge original GUI-user Photos Python environment", "python")
        if not state["directories_current"]:
            managed("Prepare original Photos directories and preserved logs", "directories")
        if not state["resources_current"]:
            managed("Converge original GUI-user Photos launcher and plist", "resources")
        if cfg.daybook_photos_offload_launchd_enabled:
            managed("Activate original declared Photos LaunchAgent", "activate")
    mark_read_only(managed("Verify Photos source, Python and declared resources", "verify"))
