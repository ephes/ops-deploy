"""Prepared original account/directories/udev component; not a deploy entry point."""

from __future__ import annotations

from collections.abc import Callable
from functools import partial
from importlib.resources import files as resources
from io import StringIO

from pyinfra.api.operation import OperationMeta
from pyinfra.operations import files, server

from .configuration_deploy import TaskRenderer, protected_template, render_task
from .planning import changed, handler
from .runtime_config import HomeAssistantRuntimeConfig


def directories(cfg: HomeAssistantRuntimeConfig) -> tuple[str, ...]:
    return (
        cfg.home,
        cfg.home + "/.local",
        cfg.home + "/.local/share",
        cfg.home + "/.local/share/uv",
        cfg.site_path,
        cfg.config_path,
        cfg.data_path,
        cfg.logs_path,
        cfg.bin_path,
    )


def configure_layout(
    cfg: HomeAssistantRuntimeConfig,
    *,
    task_renderer: TaskRenderer | None = None,
    prerequisites: list[OperationMeta] | None = None,
) -> OperationMeta | None:
    """Caller must complete original validation/trust/package prerequisites first.

    Return the changed-rule dependency for the original deferred udev handlers;
    this component never flushes it early or claims radio/device readiness.
    ``prerequisites`` collects the account and directory results: while one of
    them is planned to change, later steps cannot inspect the host yet.
    """
    collected = [] if prerequisites is None else prerequisites
    account = server.user(
        name="Ensure Home Assistant account",
        user=cfg.user,
        shell=cfg.shell,
        home=cfg.home,
        create_home=True,
        groups=["dialout"],
        append=True,
    )
    collected.append(account)
    for path in directories(cfg):
        collected.append(
            files.directory(
                name=f"Ensure Home Assistant directory {path}", path=path, user=cfg.user, group=cfg.group, mode="0755"
            )
        )
    if not cfg.enable_udev_rule:
        return None
    if task_renderer is not None:
        return protected_template(
            cfg,
            label="Write Home Assistant udev rule",
            path=cfg.udev_rule_path,
            content=partial(render_task, task_renderer, "udev"),
        )
    body = (
        resources("ops_deploy.services.homeassistant").joinpath("templates/99-homeassistant-zbt1.rules.j2").read_text()
    )
    return files.put(
        name="Write Home Assistant udev rule",
        src=StringIO(body),
        dest=cfg.udev_rule_path,
        user="root",
        group="root",
        mode="0644",
    )


def run_udev_handlers(
    rule: OperationMeta | None,
    *,
    reload_required: Callable[[], bool] | None = None,
    trigger_required: Callable[[], bool] | None = None,
) -> None:
    """Call only at the original handler-flush boundary, after configuration.

    Callbacks follow ``planning.changed``: a dry run lists a handler (as
    conditional) only when a trigger is planned to change.
    """
    if rule is not None or reload_required is not None:

        def reload() -> bool:
            return changed(rule) or (reload_required is not None and reload_required())

        handler(
            name="Reload Home Assistant udev rules",
            required=reload,
            operation=server.shell,
            arguments={"commands": ["udevadm control --reload-rules"]},
            _if=reload,
        )
    if rule is not None or trigger_required is not None:

        def trigger() -> bool:
            return changed(rule) or (trigger_required is not None and trigger_required())

        handler(
            name="Trigger Home Assistant tty udev",
            required=trigger,
            operation=server.shell,
            arguments={"commands": ["udevadm trigger --subsystem-match=tty"]},
            _if=trigger,
        )
