"""Original always-run extra-package resolution, honestly managed execution.

UV check/dry-run may create locks and cache metadata, so it is not used as a
hidden planning predicate. Preserve the real original install and classify its
successful output only for deferred restart notification. The SDK managed row
remains an execution even when UV reports that no packages changed.

A dry run instead asks a read-only metadata probe (``files/extra_packages_observe.py``)
whether the installed packages already satisfy the specs, their dependencies and
the constraints; only then is the install planned as no change. Execution is
unchanged: it always runs the install.
"""

from __future__ import annotations

import base64
import json
import re
import shlex
from collections.abc import Generator
from importlib.resources import files
from pathlib import PurePosixPath

from pyinfra import state
from pyinfra.api import StringCommand, operation
from pyinfra.api.operation import OperationMeta

from ops_deploy.helpers.probes import probe
from ops_deploy.helpers.python import _as_user

from .planning import planned
from .runtime_config import HomeAssistantRuntimeConfig

_CHANGED = re.compile("Installed|Updated|Uninstalled|Prepared|Built")


def extra_packages_command(cfg: HomeAssistantRuntimeConfig) -> str:
    argv = [cfg.uv_path, "pip", "install", "--python", cfg.virtualenv_path]
    argv += list(cfg.python_security_constraint_argv)
    argv += list(cfg.extra_package_specs)
    return f"cd {shlex.quote(cfg.site_path)} && " + _as_user(cfg.user, PurePosixPath(cfg.home), {}, argv)


def _constraint_files(argv: tuple[str, ...]) -> list[str] | None:
    """Constraint paths of ``--constraint``/``-c`` argv; ``None`` for anything else."""
    paths: list[str] = []
    items = iter(argv)
    for item in items:
        if item in {"--constraint", "-c"}:
            path = next(items, None)
            if path is None:
                return None
            paths.append(path)
        elif item.startswith("--constraint="):
            paths.append(item.split("=", 1)[1])
        else:
            return None
    return paths


def observe_command(cfg: HomeAssistantRuntimeConfig) -> str:
    body = files("ops_deploy.services.homeassistant").joinpath("files/extra_packages_observe.py").read_bytes()
    launcher = (
        "import base64;exec(compile(base64.b64decode("
        + repr(base64.b64encode(body).decode())
        + "),'<ha-extra-packages>','exec'))"
    )
    # Same working directory as the install, so relative constraint paths agree.
    return f"cd {shlex.quote(cfg.site_path)} && " + _as_user(
        cfg.user,
        PurePosixPath(cfg.home),
        {"PYTHONDONTWRITEBYTECODE": "1"},
        [cfg.virtualenv_path + "/bin/python", "-I", "-B", "-c", launcher],
    )


def extra_packages_current(cfg: HomeAssistantRuntimeConfig) -> bool:
    """Planning only: True when the read-only probe finds every spec satisfied."""
    constraints = _constraint_files(tuple(cfg.python_security_constraint_argv))
    if constraints is None:
        return False
    answer = probe(
        observe_command(cfg),
        name="Home Assistant extra packages state",
        stdin=json.dumps({"specs": list(cfg.extra_package_specs), "constraints": constraints}),
    )
    try:
        report = json.loads(answer or "")
        return bool(report == {"success": True, "current": True})
    except ValueError:
        return False


@operation()
def _extra_packages(
    cfg: HomeAssistantRuntimeConfig, deferred: bool, predecessors: tuple[OperationMeta, ...]
) -> Generator[StringCommand, None, None]:
    if (
        not state.is_executing
        and not deferred
        and not any(item.will_change for item in predecessors)
        and extra_packages_current(cfg)
    ):
        return
    yield StringCommand(extra_packages_command(cfg))


def install_extra_packages(
    cfg: HomeAssistantRuntimeConfig,
    *,
    deferred: bool = False,
    predecessors: tuple[OperationMeta | None, ...] = (),
) -> OperationMeta | None:
    """One declared managed command when original extra specs are nonempty.

    No install command executes during planning. There is deliberately no
    application-specific timeout, matching the original command task; the
    qualification runner owns its separate finite deadline. Caller places this
    after main HA installation, constraints and environment ownership.

    Planning lists it as no change only when no prerequisite is ``deferred``,
    no ``predecessors`` (environment, application, constraints) are planned
    to change and the read-only probe finds the specs satisfied.
    """
    if not cfg.extra_package_specs:
        return None
    return _extra_packages(
        name="Resolve and install Home Assistant extra packages",
        cfg=cfg,
        deferred=deferred,
        predecessors=tuple(item for item in predecessors if item is not None),
        _get_pty=False,
    )


def extra_packages_changed(result: OperationMeta | None) -> bool:
    """Original changed_when predicate, evaluated after actual execution.

    Use this for the original deferred HA restart, not ``did_change``: the SDK
    correctly records the always-run command as managed even on a UV audit-only
    result. While planning it is the planned result (the probe's answer).
    """
    if result is None:
        return False
    if planned(result):
        return result.will_change
    return result.did_succeed() and bool(_CHANGED.search(result.stdout + result.stderr))
