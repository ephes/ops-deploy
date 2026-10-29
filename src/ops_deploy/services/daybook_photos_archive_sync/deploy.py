"""Original direct-owner disabled archive installation and managed CLI smoke."""

from __future__ import annotations

import base64
import io
import json
import shlex
from importlib.resources import files
from pathlib import Path
from typing import Any

from pyinfra import host
from pyinfra.api import DeployError, deploy
from pyinfra.api.arguments import ConnectorArguments
from pyinfra.facts.server import Command, Os
from pyinfra.operations import files as file_ops

from ops_deploy.core.git_source import SourceTree
from ops_deploy.core.secrets import SecretContent
from ops_deploy.helpers import mark_read_only
from ops_deploy.ops import secret_stdin

from .config import PACKAGE, DaybookPhotosArchiveSyncConfig
from .payload import payload

DIRECT: ConnectorArguments = {
    "_sudo": False,
    "_sudo_user": "",
    "_su_user": "",
    "_doas": False,
    "_doas_user": "",
    "_dzdo": False,
    "_dzdo_user": "",
}


def command(action: str) -> str:
    if action not in {
        "status",
        "quiesce",
        "directories",
        "source",
        "environment",
        "smoke",
        "resources",
        "activate",
        "verify",
    }:
        raise ValueError("Unsupported archive component action")
    pieces = ["import base64,sys,types"]
    for name, package, resource in (
        ("ops_archive_filesystem", "ops_deploy.services.daybook_sessions", "files/resources_host.py"),
        ("ops_archive_controls", "ops_deploy.services.daybook_photos_offload", "files/photos_controls.py"),
    ):
        encoded = base64.b64encode(files(package).joinpath(resource).read_bytes()).decode()
        pieces.append(
            f"m=types.ModuleType('{name}');sys.modules[m.__name__]=m;"
            f"exec(compile(base64.b64decode('{encoded}'),'<{name}>','exec'),m.__dict__)"
        )
    encoded = base64.b64encode(files(PACKAGE).joinpath("files/archive_host.py").read_bytes()).decode()
    pieces.append(
        f"exec(compile(base64.b64decode('{encoded}'),'<archive-component>','exec'),{{'__name__':'__main__'}})"
    )
    return shlex.join(["/usr/bin/python3", "-I", "-B", "-c", ";".join(pieces), action])


def observe(data: dict[str, Any]) -> dict[str, bool]:
    with io.StringIO(json.dumps(data) + "\n") as stream:
        result = host.get_fact(Command, command=command("status"), _stdin=stream, _get_pty=False, **DIRECT)
    try:
        value = json.loads(result or "")
        if not isinstance(value, dict) or set(value) != {
            "quiescent",
            "directories",
            "bundle",
            "source",
            "environment",
            "resources",
        }:
            raise ValueError
        if any(type(item) is not bool for item in value.values()):
            raise ValueError
    except (ValueError, TypeError):
        raise DeployError("Archive synchronization observation is unavailable") from None
    return value


@deploy("Original single-writer Nikon archive components")
def install_daybook_photos_archive_sync(
    cfg: DaybookPhotosArchiveSyncConfig, source: SourceTree | None = None, bundle: Path | None = None
) -> None:
    if not cfg.daybook_photos_archive_sync_enabled:
        return
    if source is None or bundle is None:
        raise ValueError("Enabled archive synchronization requires controller-bound Main source")
    if host.get_fact(Os, **DIRECT) != "Darwin":
        raise DeployError("Archive synchronization requires its original macOS owner connection")
    name = host.get_fact(Command, command="/usr/bin/id -un", **DIRECT)
    uid = host.get_fact(Command, command="/usr/bin/id -u", **DIRECT)
    if name != cfg.daybook_photos_archive_sync_service_user or not uid or not uid.isdecimal() or int(uid) <= 0:
        raise DeployError("Archive synchronization must connect as its original service user without become")
    data = payload(cfg, source, bundle, int(uid))
    state = observe(data)

    def managed(name: str, action: str) -> Any:
        return secret_stdin(
            name=name, command=command(action), content=SecretContent(json.dumps(data) + "\n"), **DIRECT
        )

    if not state["quiescent"] or cfg.daybook_photos_archive_sync_launchd_enabled:
        managed("Quiesce only original archive synchronization label", "quiesce")
    if not state["directories"]:
        managed("Prepare original owner-private archive deployment directories", "directories")
    if not state["bundle"]:
        file_ops.put(
            name="Upload original exact Main archive bundle",
            src=str(bundle),
            dest=cfg.daybook_photos_archive_sync_repo_bundle_path,
            user=cfg.daybook_photos_archive_sync_service_user,
            group=cfg.daybook_photos_archive_sync_service_group,
            mode="0600",
            force=True,
            **DIRECT,
        )
    if not state["source"]:
        managed("Converge original clean archive Main checkout", "source")
    if not state["source"] or not state["environment"]:
        managed("Converge original pinned archive Python environment", "environment")
    # Original --help runs application code even with an unchanged environment.
    managed("Run original managed archive console-script smoke", "smoke")
    if not state["resources"]:
        managed("Publish original dormant archive launcher and plist", "resources")
    if cfg.daybook_photos_archive_sync_launchd_enabled:
        managed("Perform original explicit archive activation", "activate")
    mark_read_only(managed("Verify original archive source and selected launchd state", "verify"))
