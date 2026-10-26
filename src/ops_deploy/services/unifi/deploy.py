"""Converge configuration of an existing controller, with read-only admission first."""

from __future__ import annotations

import json
import re
import shlex
from importlib.resources import files as resources
from io import StringIO

from pyinfra.api import DeployError, deploy
from pyinfra.operations import files, server, systemd

from ops_deploy.core.secrets import SecretContent, SecretValues
from ops_deploy.helpers import mark_read_only, service_rollout, systemd_unit
from ops_deploy.helpers.probes import probe, verify_probe
from ops_deploy.ops import secret_file
from ops_deploy.services._traefik_routes import route_put

from .config import UnifiConfig
from .render import render_template

PREFLIGHT = resources("ops_deploy.services.unifi").joinpath("files/preflight.py").read_text()
PREFLIGHT_COMMAND = shlex.join(["python3", "-I", "-c", PREFLIGHT])
RESTART = resources("ops_deploy.services.unifi").joinpath("files/restart_host.py").read_text()
FIREWALL_RULES = (
    (8080, "tcp", "UniFi device communication"),
    (8443, "tcp", "UniFi web admin"),
    (3478, "udp", "UniFi STUN"),
    (10001, "udp", "UniFi discovery"),
    (6789, "tcp", "UniFi speed test"),
)


def payload(cfg: UnifiConfig, secrets: SecretValues) -> str:
    """Secret stdin, never part of argv or pyinfra's rendered command."""

    keys = ("mongodb_password", "homeassistant_password") if cfg.create_homeassistant_user else ("mongodb_password",)
    secrets.require(keys)
    password = secrets["mongodb_password"]
    # The role's URI template does not percent-encode userinfo. Refuse ambiguous
    # URI/Java syntax rather than silently changing the role's credential semantics.
    if not re.fullmatch(r"[A-Za-z0-9._~-]+", password) or "CHANGEME" in password:
        raise ValueError("mongodb_password must be non-placeholder URI-unreserved text")
    if cfg.create_homeassistant_user and "CHANGEME" in secrets["homeassistant_password"]:
        raise ValueError("homeassistant_password must not be a placeholder")
    return json.dumps(
        {
            "installed_package_version": cfg.installed_package_version,
            "controller_bind_address": cfg.controller_bind_address,
            "mongodb_password": password,
            "create_homeassistant_user": cfg.create_homeassistant_user,
            "homeassistant_username": cfg.homeassistant_username,
            "homeassistant_password": secrets["homeassistant_password"] if cfg.create_homeassistant_user else "",
            "manage_firewall": cfg.manage_firewall,
            "routine": cfg.routine is not None,
            "selected_package_version": cfg.routine.package_version if cfg.routine else cfg.installed_package_version,
        }
    )


def _put(cfg: UnifiConfig, template: str, path: str, mode: str = "0644") -> None:
    files.put(
        name=f"Configure {path}",
        src=StringIO(render_template(cfg, template)),
        dest=path,
        user="root",
        group="root",
        mode=mode,
    )


def _firewall() -> None:
    # Preserve comments too: community.general.ufw writes these exact rules.
    current = probe("ufw show added", name="UniFi UFW rules")
    if current is None:
        raise DeployError("unifi: UFW probe failed")
    rules = set(current.splitlines())
    for port, protocol, comment in FIREWALL_RULES:
        command = f"ufw allow {port}/{protocol} comment {shlex.quote(comment)}"
        if command not in rules:
            server.shell(name=f"Allow UniFi {port}/{protocol}", commands=[command])


@deploy("Converge existing UniFi")
def deploy_unifi(cfg: UnifiConfig, secrets: SecretValues) -> None:
    """Preflight is read-only even in check mode; every refusal precedes operations.

    Optional routine selection enables package and authenticated Mongo/HA
    reconciliation. Traefik uses its watched dynamic directory.
    """

    stdin = payload(cfg, secrets)
    answer = probe(PREFLIGHT_COMMAND, name="existing UniFi admission", stdin=stdin)
    if answer is None or answer.strip() != "ready":
        raise DeployError(
            "unifi: existing-install preflight refused; inspect the reported host invariant before retrying"
        )
    if cfg.routine is not None:
        from .routine import prepare_routine

        needs_package, missing_controller = prepare_routine(cfg, stdin)
    else:
        needs_package = False
        missing_controller = False
    package = None
    restart_command = shlex.join(
        [
            "python3",
            "-I",
            "-c",
            RESTART,
            json.dumps(
                {
                    "unit": "unifi.service",
                    "paths": ["/etc/systemd/system/unifi.service", "/etc/unifi-secrets/mongodb.jvmargs"],
                }
            ),
        ]
    )
    restart = probe(restart_command, name="UniFi pending restart")
    if restart is None or restart.strip() not in {"inactive", "owed", "current"}:
        raise DeployError("unifi: pending restart probe failed")
    pending_reload = probe("systemctl show -p NeedDaemonReload --value unifi.service", name="UniFi pending unit reload")
    if pending_reload is None or pending_reload.strip() not in {"yes", "no"}:
        raise DeployError("unifi: pending unit reload probe failed")
    files.directory(
        name="Lock UniFi credentials directory",
        path="/etc/unifi-secrets",
        user="root",
        group="unifi",
        mode="0750",
    )
    args = secret_file(
        name="Configure UniFi MongoDB Java argument file",
        path="/etc/unifi-secrets/mongodb.jvmargs",
        content=SecretContent(render_template(cfg, "mongodb.jvmargs.j2", mongodb_password=secrets["mongodb_password"])),
        user="root",
        group="unifi",
        mode="0640",
    )
    unit = systemd_unit("unifi", render_template(cfg, "unifi.service.j2"))
    if cfg.routine is not None:
        from .routine import install_selected

        # Vendor postinst must see our unit and credential argfile even on the
        # first controller installation over an existing authenticated MongoDB.
        systemd.daemon_reload(name="Load UniFi unit before package installation", _if=lambda: needs_package)
        package = install_selected(cfg, needs_package, missing_controller, secrets)
    if cfg.mongodb_logrotate_enabled:
        _put(cfg, "mongodb-logrotate.j2", "/etc/logrotate.d/mongodb")
    if cfg.mongodb_monitor_script_enabled:
        _put(cfg, "mongodb-log-check.sh.j2", "/etc/cron.daily/mongodb-log-check", "0755")
    if cfg.traefik_enabled:
        files.directory(
            name="Ensure Traefik dynamic directory",
            path="/etc/traefik/dynamic",
            user="root",
            group="root",
            mode="0755",
        )
        route_put(
            name="Configure /etc/traefik/dynamic/unifi.yml",
            src=render_template(cfg, "unifi.traefik.yml.j2"),
            dest="/etc/traefik/dynamic/unifi.yml",
            mode="0644",
        )
    if cfg.manage_firewall:
        _firewall()
    # Recover an earlier write that failed before daemon-reload, even if the
    # file already matches now. The ordinary rollout handles a newly changed unit.
    systemd.daemon_reload(
        name="Recover pending UniFi unit reload",
        _if=lambda: pending_reload.strip() == "yes" and not unit.did_change(),
    )
    service_rollout(
        "unifi",
        units=(unit,),
        restart_when=(args,) if package is None else (args, package),
        always_restart=restart.strip() == "owed",
    )
    # The controller's own certificate is self-signed (the role uses
    # validate_certs:false). Never weaken verification for external downloads.
    command = (
        f"for i in $(seq 1 {cfg.healthcheck_timeout}); do "
        "code=$(curl -ksS -o /dev/null -w '%{http_code}' --max-time 5 https://127.0.0.1:8443/status); "
        '[ "$code" = 200 ] && exit 0; sleep 1; done; echo "UniFi status check failed" >&2; exit 1'
    )
    mark_read_only(server.shell(name="Verify UniFi status endpoint", commands=[command]))
    if cfg.routine is not None:
        from .routine import reconcile_ha

        reconcile_ha(name="Reconcile UniFi Home Assistant account and credential", cfg=cfg, secrets=secrets)
    verify_probe(
        PREFLIGHT_COMMAND,
        name="existing UniFi invariants",
        expect="ready",
        stdin=json.dumps(
            {
                **json.loads(stdin),
                "routine": False,
                "routine_verify": cfg.routine is not None,
                "installed_package_version": cfg.routine.package_version
                if cfg.routine
                else cfg.installed_package_version,
            }
        ),
    )
