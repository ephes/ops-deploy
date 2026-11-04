"""SQLite backups through the registered ``echoport-backup`` runner (``playbooks/{archive,chesslab}/backup.yml``).

Those plays have no role: they check that the Echoport runner is installed,
write a one-run JSON config with the target's environment into a private
``mktemp`` file and run the runner with it, as Echoport does for a scheduled
run. The runner uploads to the object store; nothing is kept on the host or
fetched. :func:`deploy_echoport_runner_backup` runs the same bash script, so
the run id, key prefix and timestamp are the play's (``<prefix>-<UTC
%Y-%m-%dT%H-%M-%S>``).
"""

from __future__ import annotations

import json
import shlex
from typing import Annotated

from pydantic import Field
from pyinfra.api import DeployError, deploy
from pyinfra.operations import server

from ops_deploy.base._common import AbsolutePath, RoleConfig
from ops_deploy.core.config import ServiceName
from ops_deploy.services._lifecycle import exists

RUNNER = "/usr/local/libexec/fastdeploy/echoport-backup/backup.py"
Prefix = Annotated[str, Field(pattern=r"^[A-Za-z0-9._-]+$")]
Bucket = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9.-]{1,62}$")]
Owner = Annotated[str, Field(pattern=r"^[a-z_][a-z0-9_-]{0,31}:[a-z_][a-z0-9_-]{0,31}$")]
Unit = Annotated[str, Field(pattern=r"^[A-Za-z0-9@._-]+\.service$")]
Label = Annotated[str, Field(pattern=r"^[A-Za-z][A-Za-z0-9 ._-]*$")]


class EchoportRunnerBackupConfig(RoleConfig):
    """The play's variables: ``target`` names the Echoport target and the key prefix."""

    target: ServiceName
    # Shown in the play's refusal ("<label> backups").
    label: Label
    prefix: Prefix = "manual"
    db_path: AbsolutePath
    # ``ECHOPORT_SERVICE_NAME`` and ``ECHOPORT_RESTORE_OWNER``: only the Chesslab play sets them.
    service_name: Unit | None = None
    restore_owner: Owner | None = None
    bucket: Bucket = "backups"
    runner: AbsolutePath = RUNNER


def _environment(cfg: EchoportRunnerBackupConfig) -> list[tuple[str, str]]:
    """The play's ``context.env`` in its order; ``${timestamp}`` is expanded by the host's shell."""

    values = [
        ("ECHOPORT_TARGET", json.dumps(cfg.target)),
        ("ECHOPORT_RUN_ID", f'"{cfg.prefix}-${{timestamp}}"'),
        ("ECHOPORT_DB_PATH", json.dumps(cfg.db_path)),
        ("ECHOPORT_BACKUP_FILES", '""'),
    ]
    if cfg.service_name is not None:
        values.append(("ECHOPORT_SERVICE_NAME", json.dumps(cfg.service_name)))
    if cfg.restore_owner is not None:
        values.append(("ECHOPORT_RESTORE_OWNER", json.dumps(cfg.restore_owner)))
    values += [
        ("ECHOPORT_BUCKET", json.dumps(cfg.bucket)),
        ("ECHOPORT_KEY_PREFIX", f'"{cfg.target}/{cfg.prefix}-${{timestamp}}"'),
        ("ECHOPORT_TIMESTAMP", '"${timestamp}"'),
    ]
    return values


def backup_script(cfg: EchoportRunnerBackupConfig) -> str:
    """The play's ``shell`` task (``set -euo pipefail``, private config, ``EXIT`` trap, runner)."""

    env = ",\n".join(f'      "{name}": {value}' for name, value in _environment(cfg))
    return (
        "set -euo pipefail\n"
        'timestamp="$(date -u +%Y-%m-%dT%H-%M-%S)"\n'
        f'config_path="$(mktemp /tmp/{cfg.target}-backup-XXXXXX.json)"\n'
        "cleanup() {\n"
        '  rm -f "$config_path"\n'
        "}\n"
        "trap cleanup EXIT\n"
        'cat > "$config_path" <<JSON\n'
        "{\n"
        '  "context": {\n'
        '    "env": {\n'
        f"{env}\n"
        "    }\n"
        "  }\n"
        "}\n"
        "JSON\n"
        f'python3 {shlex.quote(cfg.runner)} --config "$config_path"\n'
    )


def echoport_runner_backup(cfg: EchoportRunnerBackupConfig) -> None:
    """Refuse without the runner, then run one backup of ``cfg.target`` through it (call inside a deploy)."""

    if not exists(cfg.runner):
        raise DeployError(f"echoport-backup must be registered before {cfg.label} backups can run.")
    server.shell(
        name=f"Run {cfg.label} SQLite backup through echoport-backup",
        commands=[backup_script(cfg)],
        _shell_executable="bash",
    )


deploy_echoport_runner_backup = deploy("Echoport runner backup")(echoport_runner_backup)

__all__ = [
    "RUNNER",
    "EchoportRunnerBackupConfig",
    "backup_script",
    "deploy_echoport_runner_backup",
    "echoport_runner_backup",
]
