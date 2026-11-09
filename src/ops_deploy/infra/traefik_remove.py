"""Remove Traefik from a host (the ``traefik_remove`` role).

Every route on the host goes with it, so ``confirm`` must be set. The service,
unit, binary, static config, logs and log rotation are removed; the dynamic
configs and the ACME directory are kept unless ``preserve_*`` is turned off
or ``force_complete`` is set. Transaction-managed hosts are refused, as the
role refuses them. A second run finds nothing left and changes nothing.
"""

from __future__ import annotations

import shlex
from pathlib import PurePosixPath
from typing import Annotated, Self

from pydantic import Field, field_validator, model_validator
from pyinfra import host
from pyinfra.api import DeployError, deploy
from pyinfra.facts.server import Which
from pyinfra.operations import files, server, systemd

from ops_deploy.base._common import AbsolutePath, RoleConfig, require_systemd
from ops_deploy.base._units import ACTIVE, ENABLED, unit_name, unit_states
from ops_deploy.helpers.probes import probe
from ops_deploy.infra.traefik_deploy import Port
from ops_deploy.infra.traefik_lifecycle_state import names_in, path_state, refuse_managed


class TraefikRemoveConfig(RoleConfig):
    confirm: bool = False
    preserve_certificates: bool = True
    preserve_dynamic_configs: bool = True
    # Overrides both ``preserve_*``.
    force_complete: bool = False
    service_name: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.@-]+$")] = "traefik"
    binary_path: AbsolutePath = "/usr/local/bin/traefik"
    config_dir: AbsolutePath = "/etc/traefik"
    static_config: AbsolutePath | None = None
    dynamic_dir: AbsolutePath | None = None
    acme_dir: AbsolutePath | None = None
    log_dir: AbsolutePath = "/var/log/traefik"
    remove_firewall_rules: bool = True
    http_port: Port = 80
    https_port: Port = 443
    dashboard_port: Port = 8090
    transaction_required: bool = False

    @field_validator("binary_path", "config_dir", "static_config", "dynamic_dir", "acme_dir", "log_dir")
    @classmethod
    def canonical_path(cls, value: str | None) -> str | None:
        return str(PurePosixPath(value)) if value is not None else None

    @model_validator(mode="after")
    def bounded_paths(self) -> Self:
        for name in ("binary_path", "config_dir", "static_config", "dynamic_dir", "acme_dir", "log_dir"):
            value = getattr(self, name)
            if value is not None:
                path = PurePosixPath(value)
                roots = {
                    "/",
                    "/usr",
                    "/var",
                    "/tmp",
                    "/var/log",
                    "/var/lib",
                    "/usr/local",
                    "/usr/local/bin",
                    "/usr/bin",
                    "/bin",
                    "/sbin",
                    "/usr/sbin",
                    "/etc/systemd",
                    "/etc/systemd/system",
                }
                if name != "config_dir":
                    roots.add("/etc")
                if ".." in path.parts or path.as_posix() in roots:
                    raise ValueError(f"{name} must identify the declared Traefik resource")
        return self


def _present(path: str) -> bool:
    return path_state(path) is not None


def _remove(path: str) -> None:
    if _present(path):
        server.shell(name=f"Remove {path}", commands=[f"rm -rf {shlex.quote(path)}"])


@deploy("Remove Traefik")
def deploy_traefik_remove(cfg: TraefikRemoveConfig) -> None:
    """Stop and remove Traefik; keep certificates and routes unless told otherwise."""

    refuse_managed(cfg.transaction_required, "traefik_remove")
    if not cfg.confirm:
        raise DeployError(
            "traefik_remove: removal not confirmed; every service routed through Traefik "
            "becomes unreachable. Set confirm to proceed."
        )
    require_systemd("traefik_remove")

    control_unit = unit_name(cfg.service_name)
    state = unit_states([control_unit])[control_unit]
    if not state.get("LoadState") or not state.get("ActiveState"):
        raise DeployError("Cannot establish Traefik service metadata before removal")
    # Like the role, a unit that cannot be stopped or disabled does not stop the removal.
    if state.get("ActiveState") in ACTIVE:
        server.shell(name="Stop Traefik", commands=[f"systemctl stop {shlex.quote(control_unit)} || true"])
    if state.get("UnitFileState") in ENABLED:
        server.shell(name="Disable Traefik", commands=[f"systemctl disable {shlex.quote(control_unit)} || true"])
    unit = f"/etc/systemd/system/{cfg.service_name}.service"
    if _present(unit):
        files.file(name=f"Remove {unit}", path=unit, present=False)
        systemd.daemon_reload(name="Reload systemd")

    removing_all = cfg.force_complete
    to_remove = [cfg.binary_path, cfg.static_config or f"{cfg.config_dir}/traefik.toml"]
    if removing_all or not cfg.preserve_dynamic_configs:
        to_remove.append(cfg.dynamic_dir or f"{cfg.config_dir}/dynamic")
    if removing_all or not cfg.preserve_certificates:
        to_remove.append(cfg.acme_dir or f"{cfg.config_dir}/acme")
    entries = {f"{cfg.config_dir}/{name}" for name in names_in(cfg.config_dir)} if _present(cfg.config_dir) else set()
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
        raw = probe("ufw show added", name="Traefik selected UFW removal rules")
        if raw is None:
            raise DeployError("Cannot establish the selected Traefik UFW rules")
        added = set(raw.splitlines())
        for port in (cfg.http_port, cfg.https_port, cfg.dashboard_port):
            if f"ufw allow {port}/tcp" in added:
                server.shell(
                    name=f"Remove the UFW rule for {port}/tcp",
                    commands=[f"ufw delete allow {port}/tcp || true"],
                )

    # The role deletes every non-hidden ``/tmp/traefik*`` entry.
    for name in names_in("/tmp"):
        if name.startswith("traefik"):
            path = "/tmp/" + name
            server.shell(name=f"Remove {path}", commands=[f"rm -rf {shlex.quote(path)}"])
