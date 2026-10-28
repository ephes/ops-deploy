"""Original update check with managed executor status, no stop or source writes."""

from __future__ import annotations

import base64
import json
import shlex
from importlib.resources import files

from pyinfra import host
from pyinfra.api import DeployError, deploy
from pyinfra.facts.server import Os

from ops_deploy.core.secrets import SecretContent
from ops_deploy.ops import secret_stdin

from .config import DaybookRuntimeConfig, RuntimeStopPolicy

PACKAGE = "ops_deploy.services.daybook_operations_runtime"


def preflight_command() -> str:
    parts = ["import base64,sys,types"]
    for module, resource in (
        ("ops_daybook_observer", "files/runtime_state.py"),
        ("ops_daybook_guards", "guards.py"),
        ("ops_daybook_stop", "files/runtime_stop.py"),
    ):
        encoded = base64.b64encode(files(PACKAGE).joinpath(resource).read_bytes()).decode()
        parts.append(
            f"m=types.ModuleType('{module}');sys.modules[m.__name__]=m;"
            f"exec(compile(base64.b64decode('{encoded}'),'<{module}>','exec'),m.__dict__)"
        )
    encoded = base64.b64encode(files(PACKAGE).joinpath("files/runtime_preflight.py").read_bytes()).decode()
    parts.append(f"exec(compile(base64.b64decode('{encoded}'),'<runtime-preflight>','exec'),{{'__name__':'__main__'}})")
    return shlex.join(["/usr/bin/python3", "-I", "-B", "-c", ";".join(parts)])


@deploy("Check original runtime update prerequisites with explicitly managed executor work")
def check_daybook_runtime_update(cfg: DaybookRuntimeConfig, *, policy: RuntimeStopPolicy) -> None:
    if cfg.mode != "host" or cfg.action != "stop" or not cfg.confirmed:
        raise ValueError("Original update check requires the original confirmed hosted stop declaration")
    if host.get_fact(Os) != "Darwin":
        raise DeployError("Protected Daybook runtime supports Darwin targets only")
    # Exact original preflight checks each source once. App status/expiry work
    # remains managed even when the keeper is already stopped. No signalling.
    secret_stdin(
        name="Check original runtime windows, capability, store and executor sources once without stopping",
        command=preflight_command(),
        content=SecretContent(
            json.dumps({"config": cfg.model_dump(mode="json"), "stop_policy": policy.model_dump(mode="json")}) + "\n"
        ),
    )
