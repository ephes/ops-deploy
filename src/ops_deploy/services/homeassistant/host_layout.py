"""Prepared original account/directories/udev component; not a deploy entry point."""

from __future__ import annotations

from collections.abc import Callable
from importlib.resources import files as resources
from io import StringIO

from pyinfra.api.operation import OperationMeta
from pyinfra.operations import files, server

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


def configure_layout(cfg: HomeAssistantRuntimeConfig) -> OperationMeta | None:
    """Caller must complete original validation/trust/package prerequisites first.

    Return the changed-rule dependency for the original deferred udev handlers;
    this component never flushes it early or claims radio/device readiness.
    """
    server.user(
        name="Ensure Home Assistant account",
        user=cfg.user,
        shell=cfg.shell,
        home=cfg.home,
        create_home=True,
        groups=["dialout"],
        append=True,
    )
    for path in directories(cfg):
        files.directory(
            name=f"Ensure Home Assistant directory {path}", path=path, user=cfg.user, group=cfg.group, mode="0755"
        )
    if not cfg.enable_udev_rule:
        return None
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
    """Call only at the original handler-flush boundary, after configuration."""
    if rule is not None or reload_required is not None:
        server.shell(
            name="Reload Home Assistant udev rules",
            commands=["udevadm control --reload-rules"],
            _if=lambda: (rule is not None and rule.did_change()) or (reload_required is not None and reload_required()),
        )
    if rule is not None or trigger_required is not None:
        server.shell(
            name="Trigger Home Assistant tty udev",
            commands=["udevadm trigger --subsystem-match=tty"],
            _if=lambda: (
                (rule is not None and rule.did_change()) or (trigger_required is not None and trigger_required())
            ),
        )
