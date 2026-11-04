"""Removal of a route-only native app: its Traefik route and the deploy's state directory.

For ``ollama_proxy`` this is the ``ollama_proxy_remove`` role (it deletes the
route file and nothing else) plus the root-only ``/var/lib/ops-deploy/<service>``
state the pyinfra deploy wrote. The role's handler reloads Traefik and restarts
it when the reload fails (the unit has no ``ExecReload``); like the deploy, this
removal leaves Traefik running and relies on the file provider's watch.
Apps with runtime parts (unit, release, account) are refused: their removal is
a separate port (navidrome's is ``services.navidrome``).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import cast

from pyinfra.api import DeployError, deploy

from ops_deploy.base._common import RoleConfig
from ops_deploy.helpers.traefik import DYNAMIC_DIR
from ops_deploy.services._lifecycle import remove_path
from ops_deploy.services.native_app.config import NativeAppConfig


class NativeAppRemoveConfig(RoleConfig):
    """What :func:`remove_native_app` takes down; nothing happens without ``confirm``."""

    app: NativeAppConfig
    confirm: bool = False


def remove_native_app(cfg: NativeAppRemoveConfig) -> None:
    """Remove a route-only app's route and state directory; Traefik itself is not restarted."""

    named = cast(Callable[[NativeAppConfig, bool], None], deploy(f"Remove {cfg.app.service_name}")(_remove))
    named(cfg.app, cfg.confirm)


def _remove(cfg: NativeAppConfig, confirm: bool) -> None:
    if not confirm:
        raise DeployError(
            f"{cfg.service_name}: removal not confirmed; this removes its Traefik route and "
            "deploy state. Set confirm to proceed."
        )
    if cfg.unit is not None or cfg.route is None:
        raise DeployError(f"{cfg.service_name}: only route-only native apps have this removal")
    remove_path(str(DYNAMIC_DIR / f"{cfg.route.name or cfg.service_name.replace('_', '-')}.yml"))
    remove_path(str(cfg.state_dir))
