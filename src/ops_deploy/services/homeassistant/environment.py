"""Original virtualenv replacement order, evaluated after interpreter installation.

This prepared component performs only replacement/creation. Version records,
links, recursive ownership, package installation and deferred service restarts
remain separate operations. Failed replacement can leave services stopped and
the environment absent/partial, exactly as the original sequence; no rollback
or successful no-change claim is invented.
"""

from __future__ import annotations

import shlex
from collections.abc import Generator
from pathlib import PurePosixPath

from pyinfra import host, state
from pyinfra.api import OperationError, StringCommand, operation
from pyinfra.api.operation import OperationMeta
from pyinfra.operations import systemd

from ops_deploy.helpers.python import _as_user

from .interpreter import find_python
from .python_observation import Kind, _observe
from .python_state import homeassistant_decision, matter_decision
from .runtime_config import HomeAssistantRuntimeConfig
from .security import _present


def create_command(cfg: HomeAssistantRuntimeConfig, kind: Kind, executable: str) -> str:
    argv = [cfg.uv_path, "venv", "--seed", "--python", executable]
    if kind == "matter":
        argv.append(cfg.matter_server_virtualenv_path)
    # The original HA command deliberately has no destination argument: UV
    # creates site/.venv. Preserve that distinction from Matter's explicit path.
    return f"cd {shlex.quote(cfg.site_path)} && " + _as_user(cfg.user, PurePosixPath(cfg.home), {}, argv)


@operation()
def _prepare_virtualenv(
    cfg: HomeAssistantRuntimeConfig,
    kind: Kind,
    llama_cpp_rebuild: bool,
    deferred: bool,
    python_install: OperationMeta | None,
) -> Generator[StringCommand, None, None]:
    if not state.is_executing and (deferred or (python_install is not None and python_install.will_change)):
        # Cold planning cannot inspect a user/interpreter that earlier declared
        # operations create. This is an explicit unresolved creation row, never
        # a false no-change result. Execution regenerates and resolves its path.
        yield StringCommand(create_command(cfg, kind, "<resolved-Python-at-execution>"))
        return
    executable = find_python(cfg)
    if not executable:
        raise OperationError("Home Assistant requested Python must be installed before virtualenv preparation")
    current = _observe(cfg, kind, "environment")
    try:
        if kind == "homeassistant":
            initial = homeassistant_decision(cfg, current, llama_cpp_rebuild=llama_cpp_rebuild)
        else:
            initial = matter_decision(cfg, current)
    except ValueError:
        raise OperationError("Home Assistant existing virtualenv version is invalid") from None
    if not initial.replace:
        return
    # Original unit existence checks and stop order apply only to an existing
    # Python environment; Matter stop is NOT gated by manage_matter_server.
    if current.python_exists:
        unit = cfg.systemd_unit_path if kind == "homeassistant" else cfg.matter_server_systemd_unit_path
        own_unit = _present(host, unit, cfg.security.system_python)
        if kind == "homeassistant":
            decision = homeassistant_decision(
                cfg,
                current,
                llama_cpp_rebuild=llama_cpp_rebuild,
                unit_exists=own_unit,
                matter_unit_exists=_present(host, cfg.matter_server_systemd_unit_path, cfg.security.system_python),
            )
        else:
            decision = matter_decision(cfg, current, unit_exists=own_unit)
        for service in decision.stop_services:
            yield from systemd.service._inner(service=service, running=False)
    path = cfg.virtualenv_path if kind == "homeassistant" else cfg.matter_server_virtualenv_path
    # Ansible state:absent removes a file, link or directory, without following
    # a root link. Do not substitute directory-only removal or recursive chown.
    if _present(host, path, cfg.security.system_python):
        yield StringCommand("rm -rf -- " + shlex.quote(path))
    yield StringCommand(create_command(cfg, kind, executable))


def prepare_environment(
    cfg: HomeAssistantRuntimeConfig,
    *,
    matter: bool = False,
    llama_cpp_rebuild: bool = False,
    deferred: bool = False,
    python_install: OperationMeta | None = None,
) -> OperationMeta:
    """Fresh execution decision; caller declares preceding account/UV/Python work.

    ``deferred`` is solely for a known pending creation prerequisite during
    planning. The real operation always resolves Python and re-observes the
    environment at execution, including after UV has retargeted a minor link.
    Pass the preceding ``install_python`` result as ``python_install`` so a
    pending requested interpreter (even with existing user/UV) defers the plan.
    """
    return _prepare_virtualenv(
        name="Prepare Matter virtualenv" if matter else "Prepare Home Assistant virtualenv",
        cfg=cfg,
        kind="matter" if matter else "homeassistant",
        llama_cpp_rebuild=llama_cpp_rebuild,
        deferred=deferred,
        python_install=python_install,
        _timeout=600,
    )
