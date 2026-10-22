"""Pinned source-build OTBR deployment; Thread state is never provisioned."""

from __future__ import annotations

import json
import shlex
from io import StringIO
from typing import Literal

from pydantic import Field
from pyinfra import host
from pyinfra.api import DeployError, deploy
from pyinfra.facts.server import Command
from pyinfra.operations import apt, files, server, systemd

from ops_deploy.base._common import RoleConfig, require_linux, require_systemd


def output(command: str) -> str:
    """Read-only Bash probe, independent of the account's login shell."""
    return host.get_fact(Command, command=f"({command}) 2>/dev/null || true", _shell_executable="bash") or ""


class OtbrConfig(RoleConfig):
    # A full audited commit is mandatory; floating upstream refs are refused.
    repo_version: str = Field(pattern=r"^[0-9a-f]{40}$")
    rcp_device: str = Field(pattern=r"^/dev/serial/by-id/[A-Za-z0-9_.:+-]+$")
    infra_interface: str = Field(pattern=r"^[A-Za-z0-9_.:-]+$", min_length=1)
    wpan_interface: str = Field(default="wpan0", pattern=r"^[A-Za-z0-9_.:-]+$")
    backbone_interface: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_.:-]+$")
    rcp_baudrate: int = Field(default=460800, gt=0)
    rest_api_enabled: bool = True
    rest_listen_address: Literal["127.0.0.1", "::1"] = "127.0.0.1"
    rest_listen_port: int = Field(default=8081, ge=1, le=65535)
    web_enabled: bool = False
    mdns: Literal["openthread", "avahi", "mDNSResponder"] = "openthread"
    dhcp6_pd_client: Literal["none", "dhcpcd", "openthread"] = "none"
    backbone_router: bool = True
    border_routing: bool = True
    nat64: bool = True
    discovery_proxy: bool = True
    firewall: bool = True
    no_auto_attach: bool = False
    remove_bind: Literal[True] = True
    manage_packages: Literal[True] = True
    manage_udev: bool = True
    force_bootstrap: bool = False
    force_rebuild: bool = False
    restart_on_change: bool = True
    service_enabled: bool = True
    service_state: Literal["started", "stopped"] = "started"
    # An operator must explicitly authorize upstream root scripts/device effects.
    build_window_approved: bool = False
    # Fixed privileged paths; overriding paths/scripts is intentionally unsupported.
    install_dir: Literal["/opt/ot-br-posix"] = "/opt/ot-br-posix"
    agent_bin: Literal["/usr/sbin/otbr-agent"] = "/usr/sbin/otbr-agent"


def build_environment(cfg: OtbrConfig) -> dict[str, str]:
    return {
        "REST_API": str(int(cfg.rest_api_enabled)),
        "WEB_GUI": str(int(cfg.web_enabled)),
        "OTBR_MDNS": cfg.mdns,
        "OTBR_DHCP6_PD_CLIENT": cfg.dhcp6_pd_client,
        "BACKBONE_ROUTER": str(int(cfg.backbone_router)),
        "BORDER_ROUTING": str(int(cfg.border_routing)),
        "NAT64": str(int(cfg.nat64)),
        "DISCOVERY_PROXY": str(int(cfg.discovery_proxy)),
        "FIREWALL": str(int(cfg.firewall)),
        "INFRA_IF_NAME": cfg.infra_interface,
        "OTBR_OPTIONS": "",
    }


def render_defaults(cfg: OtbrConfig) -> str:
    opts = (
        f"-I {cfg.wpan_interface} -B {cfg.backbone_interface or cfg.infra_interface} "
        f"spinel+hdlc+uart://{cfg.rcp_device}?uart-baudrate={cfg.rcp_baudrate}"
    )
    if cfg.rest_api_enabled:
        opts += f" --rest-listen-address {cfg.rest_listen_address} --rest-listen-port {cfg.rest_listen_port}"
    return (
        f'# Managed by Ansible - OTBR agent defaults\nOTBR_AGENT_OPTS="{opts}"\n'
        f"OTBR_NO_AUTO_ATTACH={int(cfg.no_auto_attach)}\n"
    )


def render_udev() -> str:
    return "# Home Assistant Connect ZBT-2 (ESP32-S3 USB serial)\n" + "".join(
        f'SUBSYSTEM=="tty", ATTRS{{idVendor}}=="303a", ATTRS{{idProduct}}=="{pid}", GROUP="dialout", MODE="0660"\n'
        for pid in ("4001", "831a")
    )


# Read-only guards precede packages, checkout, configuration and all device effects.
# A pre-existing DNS listener (including a local resolver) needs its own approved
# collision plan, rather than assuming bootstrap's BIND installation is harmless.
DNS_GUARD = "command -v ss >/dev/null && ss -H -lntu 'sport = :53'"
SOURCE_GUARD = (
    'test "$(stat -c %u:%a /opt)" = 0:755 && '
    "(if test ! -e /opt/ot-br-posix && test ! -L /opt/ot-br-posix; then echo absent; else "
    "test ! -L /opt/ot-br-posix && test -d /opt/ot-br-posix/.git && "
    "test ! -L /opt/ot-br-posix/.git && "
    r"unsafe=$(find /opt/ot-br-posix -xdev \( ! -user root -o \( ! -type l -a -perm /022 \) \) "
    '-print -quit) && test -z "$unsafe" && '
    "dirty=$(git -C /opt/ot-br-posix status --porcelain --untracked-files=no) && "
    'test -z "$dirty" && echo safe; fi)'
)


@deploy("Deploy OpenThread Border Router")
def deploy_otbr(cfg: OtbrConfig) -> None:
    require_linux("OTBR")
    require_systemd("OTBR")
    if not cfg.build_window_approved:
        raise DeployError("OTBR needs an approved build/device window before planning mutations")
    # Commands fail closed through explicit sentinel output; output() hides exit status.
    source_state = output(SOURCE_GUARD).strip()
    if source_state not in {"absent", "safe"}:
        raise DeployError("OTBR source must be an unmodified root-owned safe checkout or absent")
    if output(f"{DNS_GUARD}; test $? = 0 && echo checked").strip() != "checked":
        raise DeployError("OTBR refuses existing DNS listeners or unavailable socket inspection")
    if output("dpkg-query -W -f='${db:Status-Status}' bind9 | grep -x installed").strip():
        raise DeployError("OTBR refuses a pre-existing BIND installation")
    dns_units = output(
        "systemctl show --property=LoadState --value named.service named-resolvconf.service bind9.service"
    ).split()
    if dns_units != ["not-found", "not-found", "not-found"]:
        raise DeployError("OTBR refuses existing BIND units or unavailable unit inspection")
    if output(f"test -c {shlex.quote(cfg.rcp_device)} && echo device").strip() != "device":
        raise DeployError("OTBR RCP path must resolve to a character device")
    if output(f"test -d /sys/class/net/{shlex.quote(cfg.infra_interface)} && echo interface").strip() != "interface":
        raise DeployError("OTBR infrastructure interface is absent")

    env = build_environment(cfg)
    assignments = " ".join(f"{key}={shlex.quote(value)}" for key, value in env.items())
    desired = json.dumps({"commit": cfg.repo_version, "environment": env}, sort_keys=True) + "\n"
    marker = f"{cfg.install_dir}/.ops-deploy-build-config"
    built = output(f"cat {marker}").strip() == desired.strip()
    revision = output("git -C /opt/ot-br-posix rev-parse HEAD").strip()
    rebuild = (
        cfg.force_rebuild
        or cfg.force_bootstrap
        or revision != cfg.repo_version
        or not built
        or output(f"test -x {shlex.quote(cfg.agent_bin)} && echo binary").strip() != "binary"
    )
    bootstrap = (
        cfg.force_bootstrap
        or revision != cfg.repo_version
        or output("cat /opt/ot-br-posix/.ops-deploy-bootstrap-config").strip() != desired.strip()
    )
    rebuild = rebuild or bootstrap
    applied_path = "/opt/ot-br-posix/.ops-deploy-agent-defaults"
    defaults_pending = output(f"cat {applied_path}").strip() != render_defaults(cfg).strip()
    if cfg.manage_packages:
        apt.packages(
            name="Install OTBR prerequisites",
            packages=["ca-certificates", "curl", "git", "lsb-release", "sudo"],
            update=True,
            cache_time=3600,
        )
    if rebuild:
        # A failed attempt may partially replace installed files. Never retain an
        # earlier success proof, including a forced attempt at the same SHA/env.
        files.file(name="Invalidate OTBR build proof before rebuilding", path=marker, present=False)
    if bootstrap:
        files.file(
            name="Invalidate OTBR bootstrap proof before bootstrapping",
            path="/opt/ot-br-posix/.ops-deploy-bootstrap-config",
            present=False,
        )
    if revision != cfg.repo_version:
        checkout = (
            f"git fetch https://github.com/openthread/ot-br-posix.git {cfg.repo_version}; "
            f"git checkout --detach {cfg.repo_version}"
        )
        if source_state == "absent":
            checkout = (
                "set -eu; stage=$(mktemp -d /opt/.otbr-source.XXXXXX); "
                'trap \'test -z "$stage" || rm -rf -- "$stage"\' EXIT; '
                'git clone --no-checkout https://github.com/openthread/ot-br-posix.git "$stage"; '
                'cd "$stage"; ' + checkout + "; git submodule update --init --recursive; "
                'chmod 0755 "$stage"; test ! -e /opt/ot-br-posix; test ! -L /opt/ot-br-posix; '
                'mv -T -- "$stage" /opt/ot-br-posix; stage='
            )
        else:
            checkout = "set -eu; cd /opt/ot-br-posix; " + checkout
        server.shell(name="Checkout immutable OTBR source", commands=[checkout], _shell_executable="bash")
    if rebuild:
        # Retry submodule initialization even when checkout itself already completed.
        server.shell(
            name="Ensure pinned OTBR submodules",
            commands=["cd /opt/ot-br-posix && git submodule update --init --recursive"],
            _shell_executable="bash",
        )
    if bootstrap:
        server.shell(
            name="Bootstrap pinned OTBR",
            _shell_executable="bash",
            commands=[f"cd /opt/ot-br-posix && env {assignments} ./script/bootstrap"],
        )
        files.put(
            name="Record successful pinned OTBR bootstrap",
            src=StringIO(desired),
            dest="/opt/ot-br-posix/.ops-deploy-bootstrap-config",
            user="root",
            group="root",
            mode="0644",
        )
    if rebuild:
        server.shell(
            name="Build pinned OTBR",
            _shell_executable="bash",
            commands=[f"cd /opt/ot-br-posix && env {assignments} ./script/setup"],
        )
    if cfg.remove_bind:
        # Bootstrap owns this transient installation; pre-existing BIND was refused above.
        server.shell(
            name="Stop bootstrap BIND units if installed",
            _shell_executable="bash",
            commands=[
                "set -eu; for unit in named.service named-resolvconf.service; do "
                'if systemctl cat "$unit" >/dev/null 2>&1; then systemctl stop "$unit"; '
                'systemctl disable "$unit"; fi; done; '
                "if dpkg-query -W -f='${db:Status-Status}' bind9 2>/dev/null | grep -qx installed; "
                "then DEBIAN_FRONTEND=noninteractive apt-get -y purge bind9; fi"
            ],
            _if=lambda: bootstrap or rebuild,
        )
    defaults = files.put(
        name="Configure OTBR agent",
        src=StringIO(render_defaults(cfg)),
        dest="/etc/default/otbr-agent",
        user="root",
        group="root",
        mode="0644",
    )
    if cfg.manage_udev:
        rule = files.put(
            name="Configure ZBT-2 permissions",
            src=StringIO(render_udev()),
            dest="/etc/udev/rules.d/99-otbr-zbt2.rules",
            user="root",
            group="root",
            mode="0644",
        )
        server.shell(
            name="Reload and trigger ZBT-2 udev rules",
            _shell_executable="bash",
            commands=["udevadm control --reload-rules && udevadm trigger --subsystem-match=tty"],
            _if=rule.did_change,
        )
    systemd.service(
        name="Ensure OTBR agent state",
        service="otbr-agent",
        enabled=cfg.service_enabled,
        running=cfg.service_state == "started",
        restarted=False,
        daemon_reload=rebuild,
    )
    if cfg.restart_on_change and cfg.service_state == "started":
        systemd.service(
            name="Restart OTBR agent after build or configuration changes",
            service="otbr-agent",
            restarted=True,
            _if=lambda: rebuild or defaults_pending or defaults.did_change(),
        )
    if cfg.web_enabled:
        systemd.service(
            name="Ensure OTBR web state",
            service="otbr-web",
            enabled=True,
            running=cfg.service_state == "started",
            restarted=cfg.restart_on_change and cfg.service_state == "started" and rebuild,
            daemon_reload=rebuild,
        )
    files.put(
        name="Record applied OTBR defaults",
        src=StringIO(render_defaults(cfg)),
        dest=applied_path,
        user="root",
        group="root",
        mode="0644",
    )
    if rebuild:
        files.put(
            name="Record successful OTBR build",
            src=StringIO(desired),
            dest=marker,
            user="root",
            group="root",
            mode="0644",
        )
