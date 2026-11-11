"""Close TCP connections stuck on a withdrawn global IPv6 address.

After a router reconnect with a new delegated IPv6 prefix, Linux keeps the old
address deprecated for two hours. Established TCP connections keep using it as
their source address and hang, unanswered, until ``tcp_retries2`` gives up
(about 16 minutes). tailscaled's control connection is one of them, so the node
reports itself offline for that time. The daemon installed here watches
``ip -6 monitor address`` and closes (``ss -K``) only connections whose local
global address is gone, or deprecated while a preferred address in another /64
exists. See ``docs/ipv6-stale-socket-reaper.md``.
"""

from __future__ import annotations

from io import StringIO
from pathlib import Path
from typing import Literal

from pyinfra.api import deploy
from pyinfra.operations import files, systemd

from ops_deploy.base._common import RoleConfig, require_linux, require_systemd
from ops_deploy.helpers.systemd import UNIT_DIR, service_rollout, systemd_unit

SERVICE = "ipv6-stale-socket-reaper.service"
SCRIPT_PATH = "/usr/local/sbin/ipv6-stale-socket-reaper"
UNIT_PATH = str(UNIT_DIR / SERVICE)
SCRIPT = (Path(__file__).parent / "files" / "ipv6_stale_socket_reaper.py").read_text()
HEADER = "# Managed by ops-deploy infra.ipv6_stale_socket_reaper; local changes are overwritten.\n"


class Ipv6StaleSocketReaperConfig(RoleConfig):
    state: Literal["present", "absent"] = "present"


def render_unit() -> str:
    return (
        f"{HEADER}"
        "[Unit]\n"
        "Description=Close TCP connections stuck on a withdrawn IPv6 address\n"
        "Documentation=https://github.com/ephes/ops-deploy/blob/main/docs/ipv6-stale-socket-reaper.md\n"
        "After=network.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        f"ExecStart=/usr/bin/python3 -I {SCRIPT_PATH}\n"
        "Restart=always\n"
        "RestartSec=5\n"
        # ss -K (SOCK_DESTROY) needs CAP_NET_ADMIN; nothing else is needed.
        "CapabilityBoundingSet=CAP_NET_ADMIN\n"
        "RestrictAddressFamilies=AF_NETLINK AF_UNIX\n"
        "NoNewPrivileges=true\n"
        "ProtectSystem=strict\n"
        "ProtectHome=true\n"
        "PrivateTmp=true\n"
        "PrivateDevices=true\n"
        "ProtectKernelTunables=true\n"
        "ProtectKernelModules=true\n"
        "ProtectControlGroups=true\n"
        "RestrictRealtime=true\n"
        "LockPersonality=true\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )


def render_script() -> str:
    return SCRIPT


@deploy("Configure the IPv6 stale socket reaper")
def deploy_ipv6_stale_socket_reaper(cfg: Ipv6StaleSocketReaperConfig) -> None:
    require_linux("ipv6-stale-socket-reaper")
    require_systemd("ipv6-stale-socket-reaper")
    if cfg.state == "absent":
        systemd.service(name=f"Stop and disable {SERVICE}", service=SERVICE, running=False, enabled=False)
        unit = files.file(name=f"Remove {UNIT_PATH}", path=UNIT_PATH, present=False)
        files.file(name=f"Remove {SCRIPT_PATH}", path=SCRIPT_PATH, present=False)
        systemd.daemon_reload(name=f"Reload systemd after removing {SERVICE}", _if=unit.did_change)
        return
    script = files.put(
        name=f"Install {SCRIPT_PATH}",
        src=StringIO(render_script()),
        dest=SCRIPT_PATH,
        user="root",
        group="root",
        mode="0755",
    )
    unit = systemd_unit(SERVICE, render_unit())
    # Starting or restarting closes nothing that is not already stuck.
    service_rollout(SERVICE, units=(unit,), restart_when=(script,))
