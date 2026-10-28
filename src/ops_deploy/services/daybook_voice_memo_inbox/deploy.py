"""Original disabled-first Inbox component installation and pure verification.

The runtime update wrapper must execute its original stop/window sequence before
calling a noncurrent installer. Current enabled keeper composition is verified
without stopping it. Activation remains a distinct explicit lifecycle action.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import shlex
import uuid
from collections.abc import Generator, Mapping
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
from ops_deploy.services.daybook_operations_runtime import DaybookRuntimeConfig
from ops_deploy.services.daybook_operations_runtime.decision import InstalledRuntime
from ops_deploy.services.daybook_sessions.source import BundleUploadCommand

from .config import PACKAGE, DaybookInboxConfig
from .resource_payload import resource_payload
from .source import source_payload

ACTIONS = frozenset(
    {
        "status",
        "verify",
        "verify-installed",
        "quiesce",
        "directories",
        "source",
        "python",
        "resources",
        "smoke",
        "prepare-transfer",
        "cleanup-transfer",
    }
)


def component_command(action: str) -> str:
    if action not in ACTIONS:
        raise ValueError("Unsupported Inbox component action")
    pieces = ["import base64,sys,types"]
    for module, package, resource in (
        ("ops_daybook_observer", "ops_deploy.services.daybook_operations_runtime", "files/runtime_state.py"),
        ("ops_inbox_filesystem", "ops_deploy.services.daybook_sessions", "files/resources_host.py"),
        ("ops_inbox_controls", PACKAGE, "files/inbox_controls.py"),
        ("ops_inbox_source", PACKAGE, "files/inbox_source.py"),
        ("ops_inbox_python", PACKAGE, "files/inbox_python.py"),
        ("ops_inbox_resources", PACKAGE, "files/inbox_resources.py"),
        ("ops_inbox_transfer", PACKAGE, "files/inbox_transfer.py"),
    ):
        encoded = base64.b64encode(files(package).joinpath(resource).read_bytes()).decode()
        pieces.append(
            f"m=types.ModuleType('{module}');sys.modules[m.__name__]=m;"
            f"exec(compile(base64.b64decode('{encoded}'),'<{module}>','exec'),m.__dict__)"
        )
    entry = base64.b64encode(files(PACKAGE).joinpath("files/inbox_host.py").read_bytes()).decode()
    pieces.append(f"exec(compile(base64.b64decode('{entry}'),'<inbox-component>','exec'),{{'__name__':'__main__'}})")
    return shlex.join(["/usr/bin/python3", "-I", "-B", "-c", ";".join(pieces), action])


def component_payload(
    cfg: DaybookInboxConfig,
    secrets: Mapping[str, str],
    source: SourceTree,
    bundle: Path,
    *,
    uid: int,
    runtime: DaybookRuntimeConfig | None = None,
    installed: InstalledRuntime | None = None,
) -> dict[str, Any]:
    return {
        **source_payload(cfg, source, bundle, uid=uid),
        **resource_payload(cfg, secrets, uid=uid, runtime=runtime, installed=installed),
    }


def inspect_inbox(data: dict[str, Any]) -> dict[str, bool]:
    with io.StringIO(json.dumps(data) + "\n") as stream:
        result = host.get_fact(Command, command=component_command("status"), _stdin=stream, _get_pty=False)
    try:
        value = json.loads(result or "")
        if (
            not isinstance(value, dict)
            or set(value)
            != {
                "source_current",
                "directories_current",
                "resources_current",
                "install_resources_current",
                "runtime_stopped",
                "quiescent",
            }
            or any(type(item) is not bool for item in value.values())
        ):
            raise ValueError
    except (ValueError, TypeError):
        raise DeployError("Inbox component observation is unavailable") from None
    return value


@operation()
def upload_inbox_bundle(src: str, dest: str) -> Generator[FileUploadCommand | StringCommand, None, None]:
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
        raise DeployError("Inbox original connecting uid is unavailable")
    return int(value)


def _transfer_operation(data: dict[str, Any], *, cleanup: bool = False) -> OperationMeta:
    return secret_stdin(
        name="Clean private existing-identity Inbox source transfer"
        if cleanup
        else "Prepare private existing-identity Inbox source transfer",
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
                    logger.error("Inbox source temporary transport cleanup failed")

    host.state.add_callback_handler(Cleanup())


@deploy("Install original disabled-first Voice Memo Inbox components")
def install_daybook_inbox(
    cfg: DaybookInboxConfig,
    secrets: Mapping[str, str],
    source: SourceTree,
    bundle: Path,
    *,
    runtime: DaybookRuntimeConfig | None = None,
    installed: InstalledRuntime | None = None,
) -> None:
    """Installer substage; explicit activation/update sequencing belongs to callers.

    This function never activates, baselines, rotates credentials or calls an
    importer status command. Source/Python convergence includes original managed
    service-user import and CLI-help smoke, outside the status predicate.
    A current enabled keeper is left running; drift
    still requires the original runtime stop/update path before managed work.
    """
    if not cfg.daybook_voice_memo_inbox_enabled:
        return
    if host.get_fact(Os) != "Darwin":
        raise DeployError("Daybook Inbox supports Darwin targets only")
    uid_raw = host.get_fact(
        Command, command=shlex.join(["/usr/bin/id", "-u", cfg.daybook_voice_memo_inbox_service_user])
    )
    if not uid_raw or not uid_raw.isdecimal() or int(uid_raw) <= 0:
        raise DeployError("Inbox GUI account uid is unavailable")
    data = component_payload(cfg, secrets, source, bundle, uid=int(uid_raw), runtime=runtime, installed=installed)
    state = inspect_inbox(data)

    def managed(name: str, action: str) -> OperationMeta:
        return secret_stdin(
            name=name, command=component_command(action), content=SecretContent(json.dumps(data) + "\n")
        )

    current = all(state[key] for key in ("source_current", "directories_current", "resources_current"))
    if not current:
        if not state["runtime_stopped"]:
            raise DeployError("Inbox drift requires the original operations runtime stop/update path")
        if not state["quiescent"]:
            managed("Quiesce original disabled-first Inbox lanes", "quiesce")
        if not state["directories_current"]:
            managed("Prepare original Inbox directories and preserved logs", "directories")
        if not state["source_current"]:
            # Immutable controller bundle is already bound by source_payload.
            original_uid = _connecting_uid()
            temporary = "/private/var/tmp/ops-deploy-daybook-inbox-" + uuid.uuid4().hex
            data.update(
                transfer_dir=temporary,
                uploaded_bundle=temporary + "/source.bundle",
                transfer_uid=int(original_uid),
                bundle_sha256=hashlib.sha256(bundle.read_bytes()).hexdigest(),
            )
            prepared = _transfer_operation(data)
            uploaded = upload_inbox_bundle(
                name="Upload exact Inbox Main bundle", src=str(bundle), dest=data["uploaded_bundle"]
            )
            applied = managed("Converge original protected Inbox checkout", "source")
            transfer_cleanup(data, prepared, uploaded, applied)
            managed("Converge original pinned root Inbox Python", "python")
            managed("Run original managed Inbox service-user import and CLI smoke", "smoke")
        if not state["install_resources_current"]:
            managed("Converge original disabled-first Inbox resources", "resources")
    mark_read_only(
        managed("Verify Inbox code, Python and declared resources", "verify" if current else "verify-installed")
    )
