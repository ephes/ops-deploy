"""Original attended runtime cutover/rollback; executor effects are managed."""

from __future__ import annotations

import base64
import json
import shlex
from collections.abc import Mapping
from importlib.resources import files

from pyinfra import host
from pyinfra.api import DeployError, deploy
from pyinfra.facts.server import Os

from ops_deploy.core.git_source import SourceTree
from ops_deploy.core.secrets import SecretContent
from ops_deploy.ops import secret_stdin

from .config import DaybookRuntimeConfig
from .inspect import observation_payload

PACKAGE = "ops_deploy.services.daybook_operations_runtime"


def transition_command() -> str:
    pieces = ["import base64,sys,types"]
    for module, package, resource in (
        ("ops_daybook_observer", PACKAGE, "files/runtime_state.py"),
        ("ops_daybook_guards", PACKAGE, "guards.py"),
        ("ops_daybook_stage", PACKAGE, "files/runtime_stage.py"),
        ("ops_transition_filesystem", "ops_deploy.services.daybook_sessions", "files/resources_host.py"),
    ):
        body = base64.b64encode(files(package).joinpath(resource).read_bytes()).decode()
        pieces.append(
            f"m=types.ModuleType('{module}');sys.modules[m.__name__]=m;"
            f"exec(compile(base64.b64decode('{body}'),'<{module}>','exec'),m.__dict__)"
        )
    body = base64.b64encode(files(PACKAGE).joinpath("files/runtime_transition.py").read_bytes()).decode()
    pieces.append(f"exec(compile(base64.b64decode('{body}'),'<runtime-transition>','exec'),{{'__name__':'__main__'}})")
    return shlex.join(["/usr/bin/python3", "-I", "-B", "-c", ";".join(pieces)])


@deploy("Transition Daybook runtime with original reconciliation and start guards")
def transition_daybook_runtime(cfg: DaybookRuntimeConfig, secrets: Mapping[str, str], source: SourceTree) -> None:
    if cfg.action not in {"cutover", "rollback"} or not cfg.confirmed:
        raise ValueError("Runtime transition needs its original confirmed cutover or rollback action")
    if host.get_fact(Os) != "Darwin":
        raise DeployError("Protected Daybook runtime supports Darwin targets only")
    # Explicit managed operation, including original executor status/idle and
    # constructor effects. Dry-run planning must not execute these as facts.
    secret_stdin(
        name="Converge original runtime transition and optional start",
        command=transition_command(),
        content=SecretContent(json.dumps(observation_payload(cfg, secrets, source)) + "\n"),
    )
