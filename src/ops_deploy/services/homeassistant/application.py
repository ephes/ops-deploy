"""Prepared main application installs, after original environment prerequisites.

Extra-package resolution remains separate. An existing unpinned application is
not upgraded merely because a new release exists. Failed installation remains a
managed failure; this component does not restart services or invent rollback.
"""

from __future__ import annotations

import shlex
from collections.abc import Generator
from pathlib import PurePosixPath

from pyinfra import state
from pyinfra.api import DeployError, StringCommand, operation
from pyinfra.api.operation import OperationMeta

from ops_deploy.helpers.python import _as_user

from .python_observation import Kind, _observe
from .python_state import homeassistant_application_required, matter_application_required
from .runtime_config import HomeAssistantRuntimeConfig


def application_command(cfg: HomeAssistantRuntimeConfig, kind: Kind) -> str:
    venv = cfg.virtualenv_path if kind == "homeassistant" else cfg.matter_server_virtualenv_path
    spec = cfg.package_spec if kind == "homeassistant" else cfg.matter_server_package_spec
    # The original ansible.command cmd string splits the declared spec using
    # shell-style argv parsing, without a shell. Preserve quotes/options as argv.
    try:
        specs = shlex.split(spec)
    except ValueError:
        raise DeployError("Home Assistant application specification has invalid quoting") from None
    argv = [cfg.uv_path, "pip", "install", "--python", venv, *specs]
    if cfg.python_security_floor_enabled:
        argv += ["--constraint", cfg.python_security_constraints_path]
    return f"cd {shlex.quote(cfg.site_path)} && " + _as_user(cfg.user, PurePosixPath(cfg.home), {}, argv)


@operation()
def _application(
    cfg: HomeAssistantRuntimeConfig,
    kind: Kind,
    llama_cpp_rebuild: bool,
    environment: OperationMeta | None,
    deferred: bool,
) -> Generator[StringCommand, None, None]:
    pending = not state.is_executing and (deferred or (environment is not None and environment.will_change))
    if not pending:
        # Caller places this after replacement/ownership. Never retain old
        # application status observed before its environment was rebuilt.
        current = _observe(cfg, kind, "application")
        required = (
            homeassistant_application_required(cfg, current, llama_cpp_rebuild=llama_cpp_rebuild)
            if kind == "homeassistant"
            else matter_application_required(cfg, current)
        )
        if not required:
            return
    yield StringCommand(application_command(cfg, kind))


def install_application(
    cfg: HomeAssistantRuntimeConfig,
    *,
    matter: bool = False,
    llama_cpp_rebuild: bool = False,
    environment: OperationMeta | None = None,
    deferred: bool = False,
) -> OperationMeta:
    """Preserve original package/constraint argv and post-environment decisions.

    Pass the preceding prepare_environment result to defer old application
    imports in change-checking plans. ``deferred`` is only for another known
    preceding creation prerequisite; execution always probes real current state.
    The caller owns version records, ownership, security verification and
    original change-triggered service notifications.
    """
    kind: Kind = "matter" if matter else "homeassistant"
    application_command(cfg, kind)  # Reject malformed original-style argv before registering effects.
    return _application(
        name="Install Matter server application" if matter else "Install Home Assistant application",
        cfg=cfg,
        kind=kind,
        llama_cpp_rebuild=llama_cpp_rebuild,
        environment=environment,
        deferred=deferred,
    )
