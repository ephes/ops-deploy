"""Remove Traefik from a host (the ``traefik_remove`` role).

Every route on the host goes with it, so ``confirm`` must be set. The service,
unit, binary, static config, logs and log rotation are removed; the dynamic
configs and the ACME directory are kept unless ``preserve_*`` is turned off
or ``force_complete`` is set. Transaction-managed hosts are refused, as the
role refuses them. A second run finds nothing left and changes nothing.
"""

from __future__ import annotations

import shlex

from pyinfra import host
from pyinfra.api import DeployError, deploy
from pyinfra.facts.server import Which
from pyinfra.operations import files, server, systemd

from ops_deploy.base._common import AbsolutePath, RoleConfig, output, require_systemd
from ops_deploy.base._units import ACTIVE, ENABLED, unit_states
from ops_deploy.infra.traefik_deploy import Port, refuse_transaction_managed


class TraefikRemoveConfig(RoleConfig):
    confirm: bool = False
    preserve_certificates: bool = True
    preserve_dynamic_configs: bool = True
    # Overrides both ``preserve_*``.
    force_complete: bool = False
    binary_path: AbsolutePath = "/usr/local/bin/traefik"
    config_dir: AbsolutePath = "/etc/traefik"
    log_dir: AbsolutePath = "/var/log/traefik"
    remove_firewall_rules: bool = True
    http_port: Port = 80
    https_port: Port = 443
    dashboard_port: Port = 8090
    transaction_required: bool = False


def _present(path: str) -> bool:
    return output(f"test -e {shlex.quote(path)} && echo yes").strip() == "yes"


def _remove(path: str) -> None:
    if _present(path):
        server.shell(name=f"Remove {path}", commands=[f"rm -rf {shlex.quote(path)}"])


@deploy("Remove Traefik")
def deploy_traefik_remove(cfg: TraefikRemoveConfig) -> None:
    """Stop and remove Traefik; keep certificates and routes unless told otherwise."""

    refuse_transaction_managed(cfg.transaction_required, "traefik_remove")
    if not cfg.confirm:
        raise DeployError(
            "traefik_remove: removal not confirmed; every service routed through Traefik "
            "becomes unreachable. Set confirm to proceed."
        )
    require_systemd("traefik_remove")

    state = unit_states(["traefik.service"])["traefik.service"]
    # Like the role, a unit that cannot be stopped or disabled does not stop the removal.
    if state.get("ActiveState") in ACTIVE:
        server.shell(name="Stop Traefik", commands=["systemctl stop traefik.service || true"])
    if state.get("UnitFileState") in ENABLED:
        server.shell(name="Disable Traefik", commands=["systemctl disable traefik.service || true"])
    unit = "/etc/systemd/system/traefik.service"
    if _present(unit):
        files.file(name=f"Remove {unit}", path=unit, present=False)
        systemd.daemon_reload(name="Reload systemd")

    removing_all = cfg.force_complete
    to_remove = [cfg.binary_path, f"{cfg.config_dir}/traefik.toml"]
    if removing_all or not cfg.preserve_dynamic_configs:
        to_remove.append(f"{cfg.config_dir}/dynamic")
    if removing_all or not cfg.preserve_certificates:
        to_remove.append(f"{cfg.config_dir}/acme")
    entries = set(output(f"find {shlex.quote(cfg.config_dir)} -mindepth 1 -maxdepth 1").splitlines())
    for path in to_remove:
        _remove(path)
    # The role then removes the config directory if its ``find`` (which skips
    # hidden entries) finds nothing left in it.
    left = {path for path in entries - set(to_remove) if not path.rpartition("/")[2].startswith(".")}
    if cfg.config_dir != "/etc" and _present(cfg.config_dir) and not left:
        server.shell(name=f"Remove {cfg.config_dir}", commands=[f"rm -rf {shlex.quote(cfg.config_dir)}"])
    for path in (cfg.log_dir, "/etc/logrotate.d/traefik"):
        _remove(path)

    if cfg.remove_firewall_rules and host.get_fact(Which, command="ufw"):
        added = set(output("ufw show added").splitlines())
        for port in (cfg.http_port, cfg.https_port, cfg.dashboard_port):
            if f"ufw allow {port}/tcp" in added:
                server.shell(name=f"Remove the UFW rule for {port}/tcp", commands=[f"ufw delete allow {port}/tcp"])

    # The role deletes every non-hidden ``/tmp/traefik*`` entry.
    for path in output("find /tmp -mindepth 1 -maxdepth 1 -name 'traefik*' ! -name '.*'").splitlines():
        if path.startswith("/tmp/traefik"):
            server.shell(name=f"Remove {path}", commands=[f"rm -rf {shlex.quote(path)}"])
