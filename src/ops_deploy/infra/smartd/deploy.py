from __future__ import annotations

from pyinfra.api import deploy

from ops_deploy.infra import _monitoring as common

from .config import SmartdConfig
from .render import render


@deploy("Configure SMART alerting policy")
def deploy_smartd(cfg: SmartdConfig) -> None:
    if not cfg.enabled:
        return
    common.prerequisites(cfg.packages)
    lines = []
    if cfg.opts:
        lines.append(
            {
                "path": "/etc/default/smartmontools",
                "mode": 0o644,
                "values": [{"regex": "^#?smartd_opts=", "value": f'smartd_opts="{cfg.opts}"'}],
            }
        )
    units = [cfg.service_name] if cfg.manage_service else []
    common.configure(
        name="Reconcile smartd config and change-gated daemon rollout",
        payload={
            "kind": "smartd",
            "files": [{"path": cfg.config_path, "content": render(cfg), "mode": 0o644}],
            "lines": lines,
            "units": units,
            # The role's config handler restarts even with manage_service=False;
            # that flag only skips unconditional enable/start enforcement.
            "restart_units": [cfg.service_name],
            "reload": False,
        },
    )
