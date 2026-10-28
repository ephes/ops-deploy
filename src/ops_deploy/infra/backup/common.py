"""Original package/file/timer mechanics shared by the four explicit policies."""

from __future__ import annotations

import json
import re
import shlex
from collections.abc import Generator, Sequence
from io import StringIO
from pathlib import Path

from pydantic import SecretStr
from pyinfra import host
from pyinfra.api import DeployError, StringCommand, operation
from pyinfra.api.operation import OperationMeta
from pyinfra.operations import apt, files, systemd
from pyinfra.operations.util import any_changed

from ops_deploy.base._common import require_linux, require_systemd
from ops_deploy.helpers.probes import StdinLines, probe
from ops_deploy.helpers.systemd import service_rollout

from .config import BackupConfig
from .render import render

SECRET_SCRIPT = (Path(__file__).parents[1] / "files/backup_secret.py").read_text()
RESOURCE_FILES = Path(__file__).parents[1] / "files"


def prerequisites(cfg: BackupConfig) -> None:
    require_linux("scheduled backup configuration")
    require_systemd("scheduled backup configuration")
    apt.packages(name="Ensure original backup package prerequisites", packages=list(cfg.packages), update=False)


def key_input(content: SecretStr | None) -> SecretStr:
    if content is None or not content.get_secret_value() or content.get_secret_value() in {"CHANGE_ME", "CHANGEME"}:
        raise DeployError("Original managed backup key input is required; source value suppressed")
    return content


def mail_key_input(content: SecretStr | None) -> SecretStr:
    """Exact original mail-role/restore-client regex; MinIO remains raw.

    The original re.sub pattern also adds one LF to a value already ending in
    LF. Preserve that literal source transformation, not a new normalization.
    """
    value = key_input(content).get_secret_value()
    return SecretStr(re.sub(r"\n?$", "\n", value))


@operation()
def private_key(path: str, content: SecretStr, kind: str) -> Generator[StringCommand, None, None]:
    payload = json.dumps({"path": path, "content": content.get_secret_value(), "kind": kind})

    def command(action: str) -> str:
        return shlex.join(["python3", "-I", "-B", "-c", SECRET_SCRIPT, action])

    state = probe(command("check"), name="Declared backup key RAM equality/native admission", stdin=payload)
    if state == "current":
        host.noop("Original backup key content/ownership/mode are current")
    elif state == "pending":
        yield StringCommand(command("apply"), _stdin=StdinLines(payload), _get_pty=False, _shell_executable="sh")
    else:
        raise DeployError("Backup key state/validation unavailable; no key publication admitted")


def resource(cfg: BackupConfig, name: str, dest: str, mode: str = "0750") -> OperationMeta:
    return files.put(
        name="Original backup resource " + name,
        src=StringIO(render(cfg, name)),
        dest=dest,
        user="root",
        group="root",
        mode=mode,
    )


def original_file(name: str, dest: str, mode: str) -> OperationMeta:
    return files.put(
        name="Original backup program " + name,
        src=str(RESOURCE_FILES / name),
        dest=dest,
        user="root",
        group="root",
        mode=mode,
    )


def timer(cfg: BackupConfig, prefix: str, *, restart_when: Sequence[OperationMeta] = ()) -> None:
    service = resource(
        cfg, prefix + "-replication.service", "/etc/systemd/system/" + cfg.service_name + ".service", "0644"
    )
    failure = []
    if cfg.alert_enabled:
        failure.append(
            resource(
                cfg,
                prefix + "-replication-failure@.service",
                "/etc/systemd/system/" + cfg.service_name + "-failure@.service",
                "0644",
            )
        )
    schedule = resource(cfg, prefix + "-replication.timer", "/etc/systemd/system/" + cfg.timer_name + ".timer", "0644")
    systemd.daemon_reload(name="Reload changed backup units only", _if=any_changed(service, schedule, *failure))
    # Reload-only failure unit changes do not add a timer restart. Starting a
    # timer never directly executes its replication oneshot; Persistent keeps
    # its original scheduling semantics (including legitimate missed jobs).
    service_rollout(cfg.timer_name + ".timer", restart_when=[service, schedule, *restart_when])


KNOWN_HOSTS_SCRIPT = (Path(__file__).parents[1] / "files/backup_known_hosts.py").read_text()


@operation()
def known_host(path: str, peer: str, key_type: str) -> Generator[StringCommand, None, None]:
    payload = json.dumps({"path": path, "host": peer, "key_type": key_type})

    def command(action: str) -> str:
        return shlex.join(["python3", "-I", "-B", "-c", KNOWN_HOSTS_SCRIPT, action])

    result = probe(
        command("check"), name="Original fresh SSH peer keyscan and selected known_hosts equality", stdin=payload
    )
    if result == "current":
        host.noop("Fresh peer key and known_hosts metadata are current; unrelated bytes retained")
    elif result == "pending":
        yield StringCommand(command("apply"), _stdin=StdinLines(payload), _get_pty=False, _shell_executable="sh")
    else:
        raise DeployError("Fresh peer keyscan/known_hosts admission failed; no trust write admitted")
