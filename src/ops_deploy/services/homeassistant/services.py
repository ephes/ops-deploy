"""Prepared original unit, desired-state and explicit handler-flush components.

The caller owns the original multiple flush boundaries and must supply only
notifications pending at that boundary. These helpers do not infer readiness
or silently convert an explicitly restarted/reloaded state to started.
"""

from __future__ import annotations

from collections.abc import Callable, Generator
from dataclasses import dataclass
from functools import partial
from io import StringIO
from typing import Any

from pyinfra import state
from pyinfra.api import operation
from pyinfra.api.operation import OperationMeta
from pyinfra.operations import files, systemd

from .configuration_deploy import TaskRenderer, protected_template, render_task
from .planning import changed, handler
from .render import render_unit
from .runtime_config import HomeAssistantRuntimeConfig, ServiceState


@dataclass(frozen=True)
class UnitChanges:
    homeassistant: OperationMeta
    matter: OperationMeta | None

    def homeassistant_changed(self) -> bool:
        return changed(self.homeassistant)

    def matter_changed(self) -> bool:
        return changed(self.matter)

    def reload_required(self) -> bool:
        return self.homeassistant_changed() or self.matter_changed()


def write_units(cfg: HomeAssistantRuntimeConfig, *, task_renderer: TaskRenderer | None = None) -> UnitChanges:
    """Render original bytes; leave reload and restart until the caller's flush."""
    if task_renderer is not None:
        homeassistant = protected_template(
            cfg,
            label="Write Home Assistant service unit",
            path=cfg.systemd_unit_path,
            content=partial(render_task, task_renderer, "homeassistant_unit"),
        )
        matter = None
        if cfg.manage_matter_server:
            matter = protected_template(
                cfg,
                label="Write Matter server service unit",
                path=cfg.matter_server_systemd_unit_path,
                content=partial(render_task, task_renderer, "matter_unit"),
            )
        return UnitChanges(homeassistant, matter)
    homeassistant = files.put(
        name="Write Home Assistant service unit",
        src=StringIO(render_unit(cfg, "homeassistant")),
        dest=cfg.systemd_unit_path,
        user="root",
        group="root",
        mode="0644",
    )
    matter = None
    if cfg.manage_matter_server:
        matter = files.put(
            name="Write Matter server service unit",
            src=StringIO(render_unit(cfg, "matter-server")),
            dest=cfg.matter_server_systemd_unit_path,
            user="root",
            group="root",
            mode="0644",
        )
    return UnitChanges(homeassistant, matter)


@operation()
def _service_state(service: str, desired: ServiceState, enabled: bool) -> Generator[Any, None, None]:
    yield from systemd.service._inner(
        service=service,
        running=desired != "stopped",
        restarted=desired == "restarted",
        reloaded=desired == "reloaded",
        enabled=enabled,
        # Original service.yml always requests daemon_reload, even when the
        # unit and desired state are current: execution keeps that managed
        # work. A dry run plans only the state change; a changed unit plans
        # the separate (conditional) reload handler instead.
        daemon_reload=bool(state.is_executing),
    )


def _desired_state(name: str, service: str, desired: ServiceState, enabled: bool) -> OperationMeta:
    return _service_state(name=name, service=service, desired=desired, enabled=enabled)


def ensure_service_states(cfg: HomeAssistantRuntimeConfig) -> tuple[OperationMeta, ...]:
    """Original HA then optional Matter state; not a zero-managed repeat claim."""
    results = [
        _desired_state("Ensure Home Assistant service state", cfg.service_name, cfg.service_state, cfg.service_enabled)
    ]
    if cfg.manage_matter_server:
        results.append(
            _desired_state(
                "Ensure Matter server service state",
                cfg.matter_server_service_name,
                cfg.matter_server_service_state,
                cfg.matter_server_service_enabled,
            )
        )
    return tuple(results)


def flush_service_handlers(
    cfg: HomeAssistantRuntimeConfig,
    *,
    reload_required: Callable[[], bool],
    homeassistant_required: Callable[[], bool],
    matter_required: Callable[[], bool],
    matter_selected: bool = False,
) -> None:
    """Original handler order and enabled=true, using completed dependencies.

    Caller supplies pending notifications at this one flush only. Reusing old
    true callbacks at another boundary would repeat a restart and is not valid
    composition. While planning, a notification reads only planned results
    (``planning.changed``); completed results decide while executing.
    """
    # Callbacks follow planning.changed: a dry run plans each handler only when
    # one of its triggers is planned to change (listed as conditional).
    handler(
        name="Reload Home Assistant systemd units",
        required=reload_required,
        operation=systemd.daemon_reload,
        arguments={},
        _if=reload_required,
    )
    if cfg.restart_on_change:
        handler(
            name="Restart Home Assistant after changes",
            required=homeassistant_required,
            operation=systemd.service,
            arguments={"service": cfg.service_name, "restarted": True, "enabled": True},
            _if=homeassistant_required,
        )
    if (cfg.manage_matter_server or matter_selected) and cfg.matter_server_restart_on_change:
        handler(
            name="Restart Matter server after changes",
            required=matter_required,
            operation=systemd.service,
            arguments={"service": cfg.matter_server_service_name, "restarted": True, "enabled": True},
            _if=matter_required,
        )
