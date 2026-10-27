"""Full ordinary DNS deployment; converged calls never trigger periodic jobs."""

from __future__ import annotations

import ipaddress
import json
import re
import shlex
from io import StringIO
from pathlib import Path, PurePosixPath
from typing import Any

from pyinfra import host
from pyinfra.api import DeployError, deploy
from pyinfra.facts.files import File, FileContents, Link
from pyinfra.operations import apt, files, server, systemd
from pyinfra.operations.util import any_changed

from ops_deploy.base._common import require_linux, require_systemd
from ops_deploy.core.secrets import SecretContent, SecretValues
from ops_deploy.helpers import mark_read_only
from ops_deploy.helpers.probes import probe, verify_probe
from ops_deploy.helpers.systemd import Rollout, service_rollout, systemd_unit
from ops_deploy.ops import secret_file
from ops_deploy.ops.secret_file import secret_stdin
from ops_deploy.services import _metrics_httpd as httpd
from ops_deploy.services.dns.config import DnsConfig
from ops_deploy.services.dns.render import configuration, render, role_vars
from ops_deploy.services.metrics_endpoint.common import account, credentials, password, port_preflight

ROOT = Path(__file__).parent
PACKAGES = ("unbound", "unbound-anchor", "dns-root-data", "dnsutils")


def target_inputs(cfg: DnsConfig) -> tuple[str, str, int]:
    if cfg.split_lan_ip is not None:
        lan = str(cfg.split_lan_ip)
    else:
        raw = probe("ip -json -4 route get 1.1.1.1", name="DNS target LAN source")
        if raw is None:
            raise DeployError("Cannot determine DNS LAN address")
        lan = str(ipaddress.IPv4Address(json.loads(raw)[0]["prefsrc"]))
    tailscale = (
        str(cfg.split_tailscale_ip)
        if cfg.split_tailscale_ip
        else probe("tailscale ip -4", name="DNS target Tailscale address")
    )
    if not tailscale:
        raise DeployError("DNS split view requires a Tailscale address")
    tailscale = str(ipaddress.IPv4Address(tailscale.strip()))
    cpus = cfg.processor_vcpus or int(probe("getconf _NPROCESSORS_ONLN", name="DNS target CPU count") or "0")
    if cpus < 1:
        raise DeployError("Cannot determine DNS target CPU count")
    return lan, tailscale, cpus


def validate_secrets(cfg: DnsConfig, secrets: SecretValues) -> None:
    if cfg.ddns_enabled:
        value = secrets.get("tsig_secret", "")
        if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", value) or len(value) % 4:
            raise DeployError("DNS requires valid RFC2136 key material")
    if cfg.endpoint:
        password(secrets)


def configuration_command() -> str:
    # Only public source in argv; config payload goes through real redacted stdin.
    source = (ROOT / "files/config_host.py").read_text()
    return shlex.join(["python3", "-I", "-B", "-c", source])


def apply_configuration(cfg: DnsConfig, variables: dict[str, Any], lan: str, tailscale: str) -> None:
    payload: dict[str, Any] = {
        "files": configuration(cfg, variables),
        "probe_name": "deploy." + cfg.local_domain_punycode,
        "probes": [[lan, lan], [tailscale, tailscale]],
    }
    command = configuration_command()
    current = probe(command, name="Compare owned DNS configuration", stdin=json.dumps(payload))
    if current not in ("changed=true", "changed=false"):
        raise DeployError("Cannot safely compare owned DNS configuration")
    if current == "changed=false":
        return
    payload["apply"] = True
    secret_stdin(
        name="Validate and install owned DNS configuration", command=command, content=SecretContent(json.dumps(payload))
    )


def wait_periodic_job(unit: str, rollout: Rollout) -> None:
    source = (ROOT / "files/wait_job.py").read_text()
    mark_read_only(
        server.shell(
            name=f"Wait for timer-triggered {unit}",
            commands=[shlex.join(["python3", "-I", "-B", "-c", source, unit])],
            _if=lambda: rollout.start.did_change() or rollout.restart.did_change(),
        )
    )


def legacy_admission() -> tuple[str, bool]:
    command = shlex.join(["python3", "-I", "-B", "-c", (ROOT / "files/legacy_host.py").read_text()])
    state = probe(command, name="Read exact obsolete DNS NAT rules", stdin="{}")
    if state not in ("changed=true", "changed=false"):
        raise DeployError("Cannot safely read legacy DNS rules; no firewall change admitted")
    return command, state == "changed=true"


def endpoint(cfg: DnsConfig, variables: dict[str, Any], tailscale: str, secrets: SecretValues) -> None:
    e = cfg.endpoint
    if e is None:
        if host.get_fact(File, path="/etc/systemd/system/ddns-status-endpoint.service"):
            systemd.service(
                name="Disable DDNS status endpoint", service="ddns-status-endpoint", running=False, enabled=False
            )
        return
    account(e)
    script = files.put(
        name="Install DDNS status server",
        src=str(ROOT / "files/ddns_status_httpd.py"),
        dest=str(e.server_path),
        user="root",
        group="root",
        mode="0755",
    )
    auth_file = host.get_fact(File, path=str(e.htpasswd_path))
    auth_before: dict[str, Any] = dict(auth_file) if auth_file else {}
    auth_metadata_changed = not (
        auth_before.get("user") == "root"
        and auth_before.get("group") == "ddns"
        and str(auth_before.get("mode", "")).lstrip("0") == "640"
    )
    auth = credentials(e, password(secrets))
    unit = systemd_unit(e.service_name, render("ddns-status-endpoint.service.j2", variables))
    spec = httpd.Endpoint(
        service_name=e.service_name,
        argv=(
            "json-file",
            "--bind",
            tailscale,
            "--port",
            str(e.port),
            "--path",
            e.path,
            "--json-path",
            "/var/lib/ddns/status.json",
            "--htpasswd-file",
            str(e.htpasswd_path),
            "--realm",
            "ddns-status",
            "--server-name",
            "ddns-status-httpd/0.1",
            "--missing-message",
            "Status file not found - updater may not have run yet",
            "--request-timeout",
            "10",
        ),
        user=e.user,
        group=e.group_name,
        sandbox=(
            "NoNewPrivileges=yes",
            "ProtectSystem=strict",
            "ProtectHome=yes",
            "PrivateTmp=yes",
            "ReadOnlyPaths=/var/lib/ddns",
        ),
        python_script=str(e.server_path),
        probe_bind=tailscale,
        probe_port=e.port,
        probe_path=e.path,
        probe_realm="ddns-status",
        ip_address_allow=("localhost", "100.64.0.0/10"),
    )
    selection = httpd.select(
        spec,
        e,
        check_when=lambda: any_changed(script, unit, *auth)() or auth_metadata_changed,
        transient_check_is_mutation=True,
    )
    service_rollout(e.service_name, units=[unit, selection.dropin], restart_when=[script, *auth])
    httpd.verify(selection)


def ddns(cfg: DnsConfig, variables: dict[str, Any], tailscale: str, secrets: SecretValues) -> None:
    if not cfg.ddns_enabled:
        return
    apt.packages(name="Install DDNS dependencies", packages=["python3", "bind9-dnsutils", "apache2-utils"])
    server.group(name="Ensure DDNS group", group="ddns", system=True)
    server.user(
        name="Ensure DDNS user",
        user="ddns",
        group="ddns",
        system=True,
        ensure_home=False,
        create_home=False,
        shell="/usr/sbin/nologin",
    )
    for path in ["/etc/ddns", "/var/lib/ddns", "/var/log/ddns"]:
        files.directory(name=f"Ensure {path}", path=path, user="ddns", group="ddns", mode="0755")
    script = files.put(
        name="Install DDNS updater",
        src=str(ROOT / "files/ddns_update.py"),
        dest="/usr/local/bin/ddns-update",
        user="root",
        group="root",
        mode="0755",
    )
    settings = files.put(
        name="Install DDNS settings",
        src=StringIO(render("ddns-config.json.j2", variables)),
        dest="/etc/ddns/config.json",
        user="root",
        group="ddns",
        mode="0644",
    )
    credential = secret_file(
        name="Install DDNS credentials",
        path=PurePosixPath("/etc/ddns/credentials.env"),
        content=SecretContent("DDNS_TSIG_SECRET=" + secrets["tsig_secret"] + "\n"),
        user="ddns",
        group="ddns",
        mode="0600",
    )
    for path in ["/etc/ddns/gandi.env", "/usr/local/bin/ddns-update.sh"]:
        files.file(name=f"Remove obsolete {path}", path=path, present=False)
    unit = systemd_unit("ddns-update", render("ddns-update.service.j2", variables))
    timer = systemd_unit("ddns-update.timer", render("ddns-update.timer.j2", variables))
    rollout = service_rollout("ddns-update.timer", units=[unit, timer])
    wait_periodic_job("ddns-update.service", rollout)
    # A converged deploy does not cause DNS UPDATE, status or logfile writes.
    systemd.service(
        name="Run changed DDNS updater",
        service="ddns-update.service",
        command="start",
        running=None,
        _if=lambda: (
            any_changed(script, settings, credential, unit)()
            and not (rollout.start.did_change() or rollout.restart.did_change())
        ),
    )
    endpoint(cfg, variables, tailscale, secrets)


@deploy("Deploy DNS resolver and DDNS")
def deploy_dns(cfg: DnsConfig, secrets: SecretValues) -> None:
    validate_secrets(cfg, secrets)
    require_linux("DNS")
    require_systemd("DNS")
    lan, tailscale, cpus = target_inputs(cfg)
    variables = role_vars(cfg, lan, tailscale, cpus)
    if cfg.endpoint:
        port_preflight(cfg.endpoint, tailscale)
    legacy_command, legacy_changed = legacy_admission()
    apt.packages(name="Install DNS packages", packages=list(PACKAGES))
    # Only existing distro units are stopped; an absent unit is not an error.
    for service in ["systemd-resolved", "pihole-FTL"]:
        exists = probe(
            shlex.join(["systemctl", "show", service, "-p", "LoadState", "--value"]), name=f"{service} presence"
        )
        if exists not in ("not-found", ""):
            systemd.service(name=f"Disable conflicting {service}", service=service, running=False, enabled=False)
    for key in ["RESOLVCONF", "USE_RESOLVCONF_FORWARDS"]:
        files.line(
            name=f"Disable distro {key}",
            path="/etc/default/unbound",
            line="^" + key + "=.*",
            replace=key + "=false",
            present=True,
        )
    systemd.service(
        name="Disable distro resolver helper",
        service="unbound-resolvconf.service",
        running=False,
        enabled=False,
    )
    files.link(
        name="Mask distro resolver helper", path="/etc/systemd/system/unbound-resolvconf.service", target="/dev/null"
    )
    for path in ["/etc/unbound/unbound.conf.d", "/var/lib/unbound"]:
        files.directory(name=f"Ensure {path}", path=path, user="unbound", group="unbound", mode="0755")
    missing_blocklist = host.get_fact(File, path="/var/lib/unbound/blocklist.conf") is None
    if missing_blocklist:
        files.put(
            name="Seed new blocklist",
            src=StringIO("# Blocklist will be populated by update script\n"),
            dest="/var/lib/unbound/blocklist.conf",
            user="unbound",
            group="unbound",
            mode="0644",
        )
    apply_configuration(cfg, variables, lan, tailscale)
    files.put(
        name="Install blocklist updater",
        src=StringIO(render("update-blocklists.sh.j2", variables)),
        dest="/usr/local/bin/update-blocklists.sh",
        user="root",
        group="root",
        mode="0755",
    )
    unit = systemd_unit("unbound-blocklist", render("unbound-blocklist.service.j2", variables))
    timer = systemd_unit("unbound-blocklist.timer", render("unbound-blocklist.timer.j2", variables))
    blocklist_rollout = service_rollout("unbound-blocklist.timer", units=[unit, timer])
    wait_periodic_job("unbound-blocklist.service", blocklist_rollout)
    if missing_blocklist:
        systemd.service(
            name="Populate initial blocklist",
            service="unbound-blocklist.service",
            running=None,
            command="start",
            _if=lambda: not (blocklist_rollout.start.did_change() or blocklist_rollout.restart.did_change()),
        )
    systemd.service(name="Ensure DNS running and enabled", service="unbound", running=True, enabled=True)
    if cfg.update_resolv_conf:
        wanted = render("resolv.conf.j2", variables)
        existing = host.get_fact(FileContents, path="/etc/resolv.conf")
        # A trailing blank line is not resolver drift. Never rewrite a converged resolver.
        link = host.get_fact(Link, path="/etc/resolv.conf")
        if link:
            files.link(name="Remove stale resolver symlink", path="/etc/resolv.conf", present=False)
        if link or existing is None or "\n".join(existing).strip() != wanted.strip():
            files.put(
                name="Install local resolver",
                src=StringIO(wanted),
                dest="/etc/resolv.conf",
                user="root",
                group="root",
                mode="0644",
                force=True,
            )
        else:
            files.file(name="Ensure resolver metadata", path="/etc/resolv.conf", user="root", group="root", mode="0644")
    ddns(cfg, variables, tailscale, secrets)
    # Keep old forwarding until the admitted replacement is validated and running.
    if legacy_changed:
        secret_stdin(
            name="Remove exact obsolete DNS NAT rules", command=legacy_command, content=SecretContent('{"apply": true}')
        )
    for address, expected in [(lan, lan), (tailscale, tailscale)]:
        command = shlex.join(
            ["dig", "@" + address, "deploy." + cfg.local_domain_punycode, "A", "+short", "+time=3", "+tries=1"]
        )
        verify_probe(command, expect=expected, name="Verify DNS split view")
