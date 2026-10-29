"""Original managed CLI health; monitor credentials do not prove executor rc."""

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


def health_command() -> str:
    parts = ["import base64,sys,types"]
    for module, resource in (
        ("ops_daybook_observer", "files/runtime_state.py"),
        ("ops_daybook_guards", "guards.py"),
        ("ops_daybook_stop", "files/runtime_stop.py"),
    ):
        body = base64.b64encode(files(PACKAGE).joinpath(resource).read_bytes()).decode()
        parts.append(
            f"m=types.ModuleType('{module}');sys.modules[m.__name__]=m;"
            f"exec(compile(base64.b64decode('{body}'),'<{module}>','exec'),m.__dict__)"
        )
    body = base64.b64encode(files(PACKAGE).joinpath("files/runtime_health.py").read_bytes()).decode()
    parts.append(f"exec(compile(base64.b64decode('{body}'),'<runtime-health>','exec'),{{'__name__':'__main__'}})")
    return shlex.join(["/usr/bin/python3", "-I", "-B", "-c", ";".join(parts)])


@deploy("Verify original Daybook CLI health with explicitly managed application work")
def verify_daybook_runtime_health(cfg: DaybookRuntimeConfig, secrets: Mapping[str, str], source: SourceTree) -> None:
    if host.get_fact(Os) != "Darwin":
        raise DeployError("Protected Daybook runtime supports Darwin targets only")
    # This runs on BOTH empty and nonempty stores. Pure monitor authorization
    # cannot establish the original executor credential/binding rc success.
    # Never tag the Journal/expiry-capable original CLI as a read-only fact.
    secret_stdin(
        name="Verify original CLI rc, local enabled profile and readable delivery status for every source",
        command=health_command(),
        content=SecretContent(json.dumps(observation_payload(cfg, secrets, source)) + "\n"),
    )
