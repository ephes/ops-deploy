"""The existing endpoint removal; orchestration disables its Nyxmon row first."""

from __future__ import annotations

from pyinfra import host
from pyinfra.api.deploy import deploy
from pyinfra.facts.files import File
from pyinfra.operations import files, systemd

from ops_deploy.services.software_live.common import PRODUCTION, SHADOW
from ops_deploy.services.software_live.config import SoftwareLiveRemoveConfig


@deploy("Remove software live")
def remove_software_live(cfg: SoftwareLiveRemoveConfig) -> None:
    changes = []
    for name in (*PRODUCTION, *SHADOW):
        path = "/etc/systemd/system/" + name
        if host.get_fact(File, path=path) is not None:
            systemd.service(name=f"Stop and disable {name}", service=name, running=False, enabled=False)
        changes.append(files.file(name=f"Remove {name}", path=path, present=False))
    for name in ("software-live-endpoint.service.d", "software-live-collector.service.d"):
        changes.append(files.directory(name=f"Remove {name}", path="/etc/systemd/system/" + name, present=False))
    for directory in (cfg.config_dir, cfg.install_dir, cfg.data_dir / "shadow"):
        changes.append(files.directory(name=f"Remove {directory}", path=str(directory), present=False))
    if cfg.remove_data:
        changes.append(files.directory(name="Remove software observation state", path=str(cfg.data_dir), present=False))
    systemd.daemon_reload(name="Reload removed software-live units", _if=lambda: any(op.did_change() for op in changes))
