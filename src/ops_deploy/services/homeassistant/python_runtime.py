"""Prepared original Python/venv/application sequence and deferred notifications.

The outer deployment still owns prerequisite validation/trust/account/UV,
constraints, configuration, final security checks and service flush ordering.
This component does not itself restart services or qualify an application.
"""

from __future__ import annotations

from dataclasses import dataclass
from io import StringIO
from pathlib import PurePosixPath

from pyinfra.api.operation import OperationMeta
from pyinfra.operations import files

from .application import install_application
from .environment import prepare_environment
from .extra_packages import extra_packages_changed, install_extra_packages
from .interpreter import install_python
from .ownership import environment_ownership
from .runtime_config import HomeAssistantRuntimeConfig


@dataclass(frozen=True)
class PythonRuntimeChanges:
    interpreter: OperationMeta
    homeassistant_environment: OperationMeta
    homeassistant_ownership: OperationMeta
    homeassistant_application: OperationMeta
    extras: OperationMeta | None
    matter_environment: OperationMeta | None = None
    matter_ownership: OperationMeta | None = None
    matter_application: OperationMeta | None = None

    def homeassistant_changed(self) -> bool:
        """Original notifications only; record/link changes do not notify."""
        return any(
            result.did_change()
            for result in (self.interpreter, self.homeassistant_ownership, self.homeassistant_application)
        ) or extra_packages_changed(self.extras)

    def matter_changed(self) -> bool:
        """A Python install notifies Matter only when its management is selected."""
        if self.matter_application is None:
            return False
        assert self.matter_ownership is not None
        return any(result.did_change() for result in (self.interpreter, self.matter_ownership, self.matter_application))


def _version_record(cfg: HomeAssistantRuntimeConfig, path: str, name: str) -> OperationMeta:
    return files.put(
        name=name,
        src=StringIO(cfg.python_version + "\n"),
        dest=path,
        user=cfg.user,
        group=cfg.group,
        mode="0644",
    )


def configure_python_runtime(
    cfg: HomeAssistantRuntimeConfig, *, llama_cpp_rebuild: bool = False, deferred: bool = False
) -> PythonRuntimeChanges:
    """Compose after account/UV/constraints; defer only known pending prerequisites.

    Returned callbacks are for the later original service-handler boundary.
    They inspect actual completed operation results, never planning guesses.
    Current extras remain declared managed resolution but notify only on the
    original successful changed-output predicate.
    """
    interpreter = install_python(cfg, deferred=deferred)
    ha_environment = prepare_environment(
        cfg, llama_cpp_rebuild=llama_cpp_rebuild, deferred=deferred, python_install=interpreter
    )
    files.link(
        name="Ensure Home Assistant convenience virtualenv link",
        path=cfg.virtualenv_link,
        target=cfg.virtualenv_path,
        user=cfg.user,
        group=cfg.group,
    )
    _version_record(cfg, cfg.virtualenv_version_file, "Record Home Assistant virtualenv Python version")
    ha_ownership = environment_ownership(cfg, deferred=deferred or ha_environment.will_change)
    ha_application = install_application(
        cfg, llama_cpp_rebuild=llama_cpp_rebuild, environment=ha_environment, deferred=deferred
    )
    extras = install_extra_packages(cfg)
    matter_environment = matter_ownership = matter_application = None
    if cfg.manage_matter_server:
        paths = [cfg.matter_server_storage_path]
        if cfg.matter_server_log_file:
            paths.append(str(PurePosixPath(cfg.matter_server_log_file).parent))
        paths.append(cfg.matter_server_chip_factory_dir)
        for path in paths:
            files.directory(
                name=f"Ensure Matter server directory {path}", path=path, user=cfg.user, group=cfg.group, mode="0755"
            )
        matter_environment = prepare_environment(cfg, matter=True, deferred=deferred, python_install=interpreter)
        _version_record(cfg, cfg.matter_server_virtualenv_version_file, "Record Matter virtualenv Python version")
        matter_ownership = environment_ownership(cfg, matter=True, deferred=deferred or matter_environment.will_change)
        matter_application = install_application(cfg, matter=True, environment=matter_environment, deferred=deferred)
    return PythonRuntimeChanges(
        interpreter,
        ha_environment,
        ha_ownership,
        ha_application,
        extras,
        matter_environment,
        matter_ownership,
        matter_application,
    )
