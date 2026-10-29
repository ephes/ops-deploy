"""Original always-run extra-package resolution, honestly managed execution.

UV check/dry-run may create locks and cache metadata, so it is not used as a
hidden planning predicate. Preserve the real original install and classify its
successful output only for deferred restart notification. The SDK managed row
remains an execution even when UV reports that no packages changed.
"""

from __future__ import annotations

import re
import shlex
from pathlib import PurePosixPath

from pyinfra.api.operation import OperationMeta
from pyinfra.operations import server

from ops_deploy.helpers.python import _as_user

from .runtime_config import HomeAssistantRuntimeConfig

_CHANGED = re.compile("Installed|Updated|Uninstalled|Prepared|Built")


def extra_packages_command(cfg: HomeAssistantRuntimeConfig) -> str:
    argv = [cfg.uv_path, "pip", "install", "--python", cfg.virtualenv_path]
    if cfg.python_security_floor_enabled:
        argv += ["--constraint", cfg.python_security_constraints_path]
    argv += list(cfg.extra_package_specs)
    return f"cd {shlex.quote(cfg.site_path)} && " + _as_user(cfg.user, PurePosixPath(cfg.home), {}, argv)


def install_extra_packages(cfg: HomeAssistantRuntimeConfig) -> OperationMeta | None:
    """One declared managed command when original extra specs are nonempty.

    No install command executes during planning. There is deliberately no
    application-specific timeout, matching the original command task; the
    qualification runner owns its separate finite deadline. Caller places this
    after main HA installation, constraints and environment ownership.
    """
    if not cfg.extra_package_specs:
        return None
    return server.shell(
        name="Resolve and install Home Assistant extra packages",
        commands=[extra_packages_command(cfg)],
        _get_pty=False,
    )


def extra_packages_changed(result: OperationMeta | None) -> bool:
    """Original changed_when predicate, evaluated only after actual execution.

    Use this for the original deferred HA restart, not ``did_change``: the SDK
    correctly records the always-run command as managed even on a UV audit-only
    result. Before execution, OperationMeta refuses premature status access.
    """
    if result is None:
        return False
    return result.did_succeed() and bool(_CHANGED.search(result.stdout + result.stderr))
