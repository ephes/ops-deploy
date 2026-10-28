"""Guarded stop operation; original executor/Journal effects are managed work."""

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


def stop_command() -> str:
    parts = ["import base64,sys,types"]
    for module, resource in (
        ("ops_daybook_observer", "files/runtime_state.py"),
        ("ops_daybook_guards", "guards.py"),
    ):
        encoded = base64.b64encode(files(PACKAGE).joinpath(resource).read_bytes()).decode()
        parts.append(
            f"m=types.ModuleType('{module}');sys.modules[m.__name__]=m;"
            f"exec(compile(base64.b64decode('{encoded}'),'<{module}>','exec'),m.__dict__)"
        )
    script = base64.b64encode(files(PACKAGE).joinpath("files/runtime_stop.py").read_bytes()).decode()
    parts.append(f"exec(compile(base64.b64decode('{script}'),'<runtime-stop>','exec'))")
    return shlex.join(["/usr/bin/python3", "-I", "-B", "-c", ";".join(parts)])


@deploy("Stop hosted Daybook supervisor with original transition guards")
def stop_daybook_runtime(cfg: DaybookRuntimeConfig, *, policy: RuntimeStopPolicy) -> None:
    if cfg.action != "stop" or not cfg.confirmed or cfg.mode != "host" or cfg.poll_delay == 0:
        raise ValueError("stop requires the original confirmed hosted action and positive polling delay")
    if host.get_fact(Os) != "Darwin":
        raise DeployError("Protected Daybook runtime supports Darwin targets only")
    # This operation is deliberately not marked read-only: executor status can
    # expire binding authority and opens Journal state, even when already stopped.
    secret_stdin(
        name="Quiesce original runtime, stop keeper and gracefully TERM supervisor",
        command=stop_command(),
        content=SecretContent(
            json.dumps({"config": cfg.model_dump(mode="json"), "stop_policy": policy.model_dump(mode="json")}) + "\n"
        ),
    )
