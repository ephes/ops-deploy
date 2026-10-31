"""Install the standalone shared notifier without executing or sending through it."""

from __future__ import annotations

import base64
import io
import json
import os
import shlex
import stat
from importlib.resources import files
from pathlib import Path

from pyinfra import host
from pyinfra.api import DeployError, deploy
from pyinfra.facts.server import Command, Os

from ops_deploy.core.secrets import SecretContent
from ops_deploy.ops import secret_stdin

from .config import PACKAGE, DaybookVoiceMemoAttentionNotifierConfig, DaybookVoiceMemoAttentionNotifierPins


def component_command(action: str) -> str:
    if action not in {"status", "install"}:
        raise ValueError("Unsupported notifier action")
    filesystem = base64.b64encode(
        files("ops_deploy.services.daybook_sessions").joinpath("files/resources_host.py").read_bytes()
    ).decode()
    helper = base64.b64encode(files(PACKAGE).joinpath("files/notifier_host.py").read_bytes()).decode()
    code = (
        "import base64,sys,types;m=types.ModuleType('ops_notifier_filesystem');sys.modules[m.__name__]=m;"
        f"exec(compile(base64.b64decode('{filesystem}'),'<notifier-filesystem>','exec'),m.__dict__);"
        f"exec(compile(base64.b64decode('{helper}'),'<notifier-installation>','exec'),{{'__name__':'__main__'}})"
    )
    return shlex.join(["/usr/bin/python3", "-I", "-B", "-c", code, action])


def read_source(path: Path) -> bytes:
    """Freeze one bounded regular descriptor; reject replacement or growth."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_size > 131072:
                raise ValueError("Notifier source must be a bounded regular file")
            body = bytearray()
            while len(body) <= 131072:
                chunk = os.read(fd, min(65536, 131073 - len(body)))
                if not chunk:
                    break
                body.extend(chunk)

            def identity(info: os.stat_result) -> tuple[int, ...]:
                return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

            if (
                not body
                or len(body) > 131072
                or len(body) != before.st_size
                or identity(before) != identity(os.fstat(fd))
                or identity(before) != identity(path.lstat())
            ):
                raise ValueError("Notifier source changed during its bounded read")
            return bytes(body)
        finally:
            os.close(fd)
    except OSError:
        raise ValueError("Notifier source descriptor is unavailable") from None


def payload(cfg: DaybookVoiceMemoAttentionNotifierConfig, pins: DaybookVoiceMemoAttentionNotifierPins) -> str:
    body = read_source(Path(cfg.script_src))
    return (
        json.dumps(
            {
                "public_key": pins.public_key.get_secret_value(),
                "native_host": pins.native_host.get_secret_value(),
                "recipient": pins.recipient.get_secret_value(),
                "container": cfg.container,
                "script_base64": base64.b64encode(body).decode(),
            }
        )
        + "\n"
    )


@deploy("Original shared Daybook notifier endpoint")
def install_daybook_voice_memo_attention_notifier(
    cfg: DaybookVoiceMemoAttentionNotifierConfig,
    *,
    pins: DaybookVoiceMemoAttentionNotifierPins,
) -> None:
    if host.get_fact(Os) != "Linux":
        raise DeployError("Shared notifier installation requires Linux")
    data = payload(cfg, pins)
    with io.StringIO(data) as stream:
        result = host.get_fact(Command, command=component_command("status"), _stdin=stream, _get_pty=False)
    try:
        state = json.loads(result or "")
        if (
            not isinstance(state, dict)
            or set(state) != {"directories", "script", "config", "authorization"}
            or any(type(value) is not bool for value in state.values())
        ):
            raise ValueError
    except (TypeError, ValueError):
        raise DeployError("Shared notifier installation observation is unavailable") from None
    # Revalidate original ownership/authorization and compile the exact source on
    # every normal converge. This is genuine managed validation, including repeat.
    secret_stdin(
        name="Validate and install original shared notifier without sending",
        command=component_command("install"),
        content=SecretContent(data),
    )
