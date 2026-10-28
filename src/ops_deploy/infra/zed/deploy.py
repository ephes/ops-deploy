from __future__ import annotations

from pathlib import PurePosixPath

from pyinfra import host
from pyinfra.api import DeployError, deploy
from pyinfra.facts.files import File
from pyinfra.operations import files

from ops_deploy.infra import _monitoring as common

from .config import ZedConfig
from .render import render


@deploy("Configure ZFS event alerting and scrub schedule")
def deploy_zed(cfg: ZedConfig) -> None:
    if not cfg.enabled:
        return
    if (
        cfg.manage_scrub_timer
        and cfg.scrub_spindown_enabled
        and not host.get_fact(File, path=cfg.scrub_spindown_script_path)
    ):
        raise DeployError("Existing scrub-spindown helper must be deployed separately")
    common.prerequisites(cfg.packages)
    files.directory(
        name="ZED configuration directory",
        path=str(PurePosixPath(cfg.rc_path).parent),
        user="root",
        group="root",
        mode="0755",
    )
    rows = []
    units = [cfg.service_name]
    if cfg.manage_scrub_timer and cfg.scrub_pools:
        rows = [
            {
                "path": "/etc/systemd/system/" + cfg.scrub_service_template,
                "content": render(cfg, "zpool-scrub@.service.j2"),
                "mode": 0o644,
                "restart": False,
            },
            {
                "path": "/etc/systemd/system/" + cfg.scrub_timer_template,
                "content": render(cfg, "zpool-scrub@.timer.j2"),
                "mode": 0o644,
                "restart": False,
            },
        ]
        units.extend("zpool-scrub@" + name + ".timer" for name in cfg.scrub_pools)
    common.configure(
        name="Reconcile ZED and enabled scrub timers, never run a scrub",
        payload={
            "kind": "zed",
            "files": rows,
            "lines": [
                {
                    "path": cfg.rc_path,
                    "mode": None,
                    "values": [
                        {"regex": "^ZED_EMAIL_ADDR=", "value": f'ZED_EMAIL_ADDR="{cfg.email_to}"'},
                        {"regex": "^ZED_EMAIL_PROG=", "value": f'ZED_EMAIL_PROG="{cfg.email_prog}"'},
                    ],
                }
            ],
            "units": units,
            "restart_units": [cfg.service_name],
            "reload": bool(rows),
        },
    )
