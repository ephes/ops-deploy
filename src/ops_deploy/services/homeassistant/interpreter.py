"""Original UV-managed Python step, before any virtualenv observation.

Every query is fresh at operation execution. A patch installation can retarget
UV's minor-version symlink, making an existing virtualenv current without a
rebuild. Later environment operations must inspect it after this operation.
"""

from __future__ import annotations

from collections.abc import Generator
from pathlib import PurePosixPath

from pyinfra import host, state
from pyinfra.api import OperationError, StringCommand, operation
from pyinfra.api.operation import OperationMeta

from ops_deploy.helpers.python import _as_user

from .runtime_config import HomeAssistantRuntimeConfig


def interpreter_command(cfg: HomeAssistantRuntimeConfig, action: str) -> str:
    return _as_user(cfg.user, PurePosixPath(cfg.home), {}, [cfg.uv_path, "python", action, cfg.python_version])


def find_python(cfg: HomeAssistantRuntimeConfig) -> str | None:
    """Original find: a nonzero result requests installation; success trims stdout."""
    success, output = host.run_shell_command(
        StringCommand(interpreter_command(cfg, "find")), print_output=False, print_input=False, _timeout=60
    )
    return str(output.stdout).strip() if success else None


@operation()
def _install(cfg: HomeAssistantRuntimeConfig, deferred: bool) -> Generator[StringCommand, None, None]:
    if not (deferred and not state.is_executing) and find_python(cfg) is not None:
        return
    yield StringCommand(interpreter_command(cfg, "install"))
    # A generator resumes here only after the command has executed successfully;
    # dry planning stops after the first yielded command. Do not reuse the
    # pre-install failure or a cached Command fact to determine the executable.
    if find_python(cfg) is None:
        raise OperationError("Home Assistant requested Python is still unavailable after UV installation")


def install_python(cfg: HomeAssistantRuntimeConfig, *, deferred: bool = False) -> OperationMeta:
    """Return the actual managed change used by the original deferred restarts.

    ``deferred`` is only for a declared earlier user/UV creation prerequisite
    during a cold plan. Execution always performs the real find before writing.
    The caller owns HA and optional Matter restart notifications.
    """
    return _install(name="Install Home Assistant requested Python", cfg=cfg, deferred=deferred, _timeout=600)
