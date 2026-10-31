"""Original UV-managed Python step, before any virtualenv observation.

Every query is fresh at operation execution. A patch installation can retarget
UV's minor-version symlink, making an existing virtualenv current without a
rebuild. Later environment operations must inspect it after this operation.
"""

from __future__ import annotations

import shlex
from collections.abc import Generator
from pathlib import PurePosixPath

from pyinfra import host, state
from pyinfra.api import FunctionCommand, Host, OperationError, StringCommand, operation
from pyinfra.api.operation import OperationMeta
from pyinfra.context import ctx_host

from ops_deploy.helpers.python import _as_user

from .runtime_config import HomeAssistantRuntimeConfig
from .transport import run_protected_command


def interpreter_command(cfg: HomeAssistantRuntimeConfig, action: str) -> str:
    # An unrelated controller project/virtualenv must not influence this target
    # account's requested interpreter. Original Ansible can use a module temp
    # cwd after become; an explicit home cwd is an intentional runtime correction,
    # not a claim that the original role declared chdir=home.
    command = (
        "cd " + shlex.quote(cfg.home) + " && exec " + shlex.join([cfg.uv_path, "python", action, cfg.python_version])
    )
    return _as_user(cfg.user, PurePosixPath(cfg.home), {}, ["/bin/sh", "-c", command])


def find_python(cfg: HomeAssistantRuntimeConfig) -> str | None:
    """Original find: a nonzero result requests installation; success trims stdout."""
    success, output = run_protected_command(host, StringCommand(interpreter_command(cfg, "find")), _timeout=60)
    return str(output.stdout).strip() if success else None


def _failed() -> None:
    # Callback failures complete the real SDK operation and mark the host;
    # raising while advancing a generator bypasses that accounting.
    raise OperationError("Home Assistant requested Python is still unavailable after UV installation")


def _retain_install_change() -> None:
    """Account for this invocation's earlier successful install, not a new write."""


@operation()
def _install(
    cfg: HomeAssistantRuntimeConfig, deferred: bool, installed: set[Host]
) -> Generator[StringCommand | FunctionCommand, None, None]:
    target = ctx_host.get()
    assert isinstance(target, Host)
    if not (deferred and not state.is_executing) and find_python(cfg) is not None:
        # The SDK keeps only the final retry's commands. Preserve this actual
        # invocation's successful install for deferred restart notifications.
        if state.is_executing and target in installed:
            yield FunctionCommand(_retain_install_change, (), {})
        return
    yield StringCommand(interpreter_command(cfg, "install"))
    if state.is_executing:
        installed.add(target)
    # A generator resumes here only after the command has executed successfully;
    # dry planning stops after the first yielded command. Do not reuse the
    # pre-install failure or a cached Command fact to determine the executable.
    if find_python(cfg) is None:
        yield FunctionCommand(_failed, (), {})


def install_python(cfg: HomeAssistantRuntimeConfig, *, deferred: bool = False) -> OperationMeta:
    """Return the actual managed change used by the original deferred restarts.

    ``deferred`` is only for a declared earlier user/UV creation prerequisite
    during a cold plan. Execution always performs the real find before writing.
    The caller owns HA and optional Matter restart notifications.
    """
    return _install(
        name="Install Home Assistant requested Python", cfg=cfg, deferred=deferred, installed=set(), _timeout=600
    )
