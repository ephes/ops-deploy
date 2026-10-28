"""Deploy the existing software observation units with change-gated collection."""

from __future__ import annotations

import ipaddress
import shlex
from collections.abc import Callable

from pyinfra.api import DeployError
from pyinfra.api.deploy import deploy
from pyinfra.operations import apt, files, server, systemd

from ops_deploy.core.secrets import SecretValues
from ops_deploy.helpers.checks import mark_read_only
from ops_deploy.helpers.probes import stdin_arguments
from ops_deploy.services.metrics_endpoint.common import account, bind_address, credentials, password
from ops_deploy.services.software_live import state, switch
from ops_deploy.services.software_live.common import PRODUCTION, RESOURCE, endpoint_json, nice_json, put, restart, unit
from ops_deploy.services.software_live.config import SoftwareLiveConfig

INVENTORY_CHECK = """import grp,os,stat,sys
from pathlib import Path
grp.getgrnam(sys.argv[1]);p=Path('/var/lib/software-estate-observations')
try:s=p.lstat()
except FileNotFoundError:sys.exit(0)
if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or stat.S_IMODE(s.st_mode) not in (0o750,0o700):
 sys.exit('software inventory export directory must be a root-owned real directory with mode0750/0700')
"""


def verify_endpoint(cfg: SoftwareLiveConfig, secret: str, bind: str, *, shadow: bool = False) -> None:
    args = (
        [
            "shadow",
            f"http://{bind}:9110/.well-known/software-live",
            f"http://127.0.0.1:{cfg.shadow_port}/.well-known/software-live",
        ]
        if shadow
        else ["verify", f"http://{bind}:9110/.well-known/software-live", cfg.host_id]
    )
    # The playbook's verification URLs deliberately retain literal port9110.
    # Password stays on masked stdin, never in a process argument or log.
    script = RESOURCE.joinpath("files/endpoint_check.py").read_text()
    mark_read_only(
        server.shell(
            name="Compare software-live shadow endpoint"
            if shadow
            else "Verify software-live endpoint identity and freshness",
            commands=[shlex.join(["/usr/bin/python3", "-I", "-c", script, *args])],
            **stdin_arguments(cfg.auth_user + "\n" + secret + "\n"),
        )
    )


@deploy("Deploy software live")
def deploy_software_live(
    cfg: SoftwareLiveConfig, secrets: SecretValues, on_endpoint: Callable[[str], None] | None = None
) -> None:
    secret = password(secrets)
    if len(secret) < 12:
        raise DeployError("software-live endpoint_password must contain at least12 characters")
    endpoint = cfg.endpoint()
    bind = bind_address(endpoint)
    address = ipaddress.IPv4Address(bind)
    if not (address.is_loopback or address in ipaddress.ip_network("100.64.0.0/10")):
        raise DeployError("software-live bind must be loopback or Tailscale IPv4")
    # Callback is only a candidate URL. Orchestration marks it verified only
    # after this complete deployment succeeds (check mode verifies no URL).
    if on_endpoint is not None:
        on_endpoint(f"http://{bind}:9110/.well-known/software-live")
    rust_inputs = switch.release_inputs(cfg) if cfg.impl == "rust" else None
    before = state.observation(cfg)
    live = switch.live_state(cfg)
    apt.packages(name="Install software observation dependencies", packages=list(cfg.packages))
    account(endpoint)
    files.directory(
        name="Ensure software observation state directory",
        path=str(cfg.data_dir),
        user="root",
        group=cfg.group,
        mode="0750",
    )
    files.directory(
        name="Ensure software observation program directory",
        path=str(cfg.install_dir),
        user="root",
        group="root",
        mode="0755",
    )
    programs = [
        put(str(cfg.install_dir / name), RESOURCE.joinpath("files", name).read_text(), mode="0755")
        for name in ("software_live.py", "nyxmon_checks.py")
    ]
    policy = put(str(cfg.config_dir / "policy.json"), nice_json(cfg.policy), group=cfg.group, mode="0640")
    if cfg.impl == "python":
        mark_read_only(
            server.shell(
                name="Validate software observation policy",
                commands=[
                    shlex.join(
                        [
                            "/usr/bin/python3",
                            str(cfg.install_dir / "software_live.py"),
                            "validate",
                            "--config",
                            str(cfg.config_dir / "policy.json"),
                        ]
                    )
                ],
            )
        )
    auth = credentials(endpoint, secret)
    endpoint_config = put(str(cfg.config_dir / "endpoint.json"), endpoint_json(cfg, bind), group=cfg.group, mode="0640")
    if cfg.inventory_export:
        mark_read_only(
            server.shell(
                name="Check existing software inventory export boundary",
                commands=[shlex.join(["/usr/bin/python3", "-I", "-", cfg.inventory_group])],
                **stdin_arguments(INVENTORY_CHECK),
            )
        )
        files.directory(
            name="Ensure software inventory projection directory",
            path="/var/lib/software-estate-observations",
            user="root",
            group=cfg.inventory_group,
            mode="0750",
        )
    selected = switch.select(cfg, live, rust_inputs)
    if selected.refused:
        return
    units = [
        unit(cfg, name, template)
        for name, template in zip(
            PRODUCTION, ("collector.service.j2", "collector.timer.j2", "endpoint.service.j2"), strict=True
        )
    ]
    changed_units = [*units, *selected.production]
    systemd.daemon_reload(
        name="Reload software-live production units", _if=lambda: any(op.did_change() for op in changed_units)
    )
    restart("software-live-endpoint.service", [*programs, *auth, endpoint_config, *changed_units])
    restart("software-live-collector.timer", changed_units)
    triggers = [*programs, policy, *auth, endpoint_config, *units, *selected.triggers]
    if selected.install is not None and not selected.install.validated:
        triggers.append(selected.install.op)
    state.collect(cfg, before, triggers)
    for name in ("software-live-collector.timer", "software-live-endpoint.service"):
        systemd.service(name=f"Enable and start {name}", service=name, running=True, enabled=True)
    if cfg.rust_shadow:
        for name in ("software-live-shadow-collector.timer", "software-live-shadow-endpoint.service"):
            systemd.service(name=f"Enable and start {name}", service=name, running=True, enabled=True)
    switch.verify_and_pin(cfg, selected)
    verify_endpoint(cfg, secret, bind)


@deploy("Compare software live shadow")
def compare_software_live_shadow(cfg: SoftwareLiveConfig, secrets: SecretValues) -> None:
    if cfg.rust_shadow:
        verify_endpoint(cfg, password(secrets), bind_address(cfg.endpoint()), shadow=True)
