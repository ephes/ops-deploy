"""Original disabled wheel installer; importing application code is managed work."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import shlex
from importlib.resources import files as resources
from pathlib import Path
from typing import Any

from pyinfra import host
from pyinfra.api import DeployError, deploy
from pyinfra.facts.server import Command, Os
from pyinfra.operations import files

from ops_deploy.core.secrets import SecretContent
from ops_deploy.ops import secret_stdin

from .config import PACKAGE, DaybookVoiceMemoAttentionConfig
from .render import render_plist


def component_command(action: str) -> str:
    if action not in {"status", "quiesce", "directories", "environment", "resources", "verify-import"}:
        raise ValueError("Unsupported attention component action")
    pieces = ["import base64,sys,types"]
    filesystem = resources("ops_deploy.services.daybook_sessions").joinpath("files/resources_host.py").read_bytes()
    encoded = base64.b64encode(filesystem).decode()
    pieces.append(
        "m=types.ModuleType('ops_attention_filesystem');sys.modules[m.__name__]=m;"
        f"exec(compile(base64.b64decode('{encoded}'),'<attention-filesystem>','exec'),m.__dict__)"
    )
    encoded = base64.b64encode(resources(PACKAGE).joinpath("files/attention_host.py").read_bytes()).decode()
    pieces.append(
        f"exec(compile(base64.b64decode('{encoded}'),'<attention-component>','exec'),{{'__name__':'__main__'}})"
    )
    return shlex.join(["/usr/bin/python3", "-I", "-B", "-c", ";".join(pieces), action])


def payload(cfg: DaybookVoiceMemoAttentionConfig) -> dict[str, Any]:
    data = {
        key.removeprefix("daybook_voice_memo_attention_"): value for key, value in cfg.model_dump(mode="json").items()
    }
    wheel = Path(data["wheel_src"])
    if wheel.is_symlink() or not wheel.is_file():
        raise ValueError("Attention requires the prepared original regular wheel")
    data["wheel_name"] = wheel.name
    data["wheel_sha1"] = hashlib.sha1(wheel.read_bytes()).hexdigest()
    data["plist"] = render_plist(cfg)
    return data


def observe(data: dict[str, Any]) -> dict[str, bool]:
    with io.StringIO(json.dumps(data) + "\n") as stream:
        result = host.get_fact(Command, command=component_command("status"), _stdin=stream, _get_pty=False)
    try:
        state = json.loads(result or "")
        if not isinstance(state, dict) or set(state) != {
            "quiescent",
            "directories",
            "wheel",
            "environment",
            "resources",
        }:
            raise ValueError
        if any(type(value) is not bool for value in state.values()):
            raise ValueError
    except (TypeError, ValueError):
        raise DeployError("Attention installation observation is unavailable") from None
    return state


@deploy("Original disabled Daybook voice-memo attention wheel")
def install_daybook_voice_memo_attention(cfg: DaybookVoiceMemoAttentionConfig) -> None:
    if host.get_fact(Os) != "Darwin":
        raise DeployError("Attention installation requires macOS")
    data = payload(cfg)
    state = observe(data)

    def managed(name: str, action: str) -> None:
        secret_stdin(name=name, command=component_command(action), content=SecretContent(json.dumps(data) + "\n"))

    if not state["quiescent"]:
        managed("Disable and unload only original attention label", "quiesce")
    if not state["directories"]:
        managed("Create original attention installation directories", "directories")
    if not state["wheel"]:
        files.put(
            name="Copy prepared original attention wheel",
            src=cfg.daybook_voice_memo_attention_wheel_src,
            dest=cfg.daybook_voice_memo_attention_install_root + "/" + data["wheel_name"],
            user="root",
            group="wheel",
            mode="0644",
            # Fresh component observation already proved destination mismatch.
            # The SDK caches local digests by filename for the process lifetime;
            # do not let that stale cache suppress a recovery wheel transfer.
            force=True,
        )
    if not state["environment"] or not state["wheel"]:
        managed("Converge original attention Python and wheel installation", "environment")
    # The original task imports application code on every converge. This is an
    # explicit managed operation, never a fact or a zero-managed repeat claim.
    managed("Verify original attention isolated application import", "verify-import")
    if not state["resources"]:
        managed("Install original disabled attention configuration and plist", "resources")
