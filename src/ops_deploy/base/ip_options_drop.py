"""Drop IPv4 TCP packets that carry IP options, before conntrack (no ops-library role).

A temporary kernel-bug mitigation: some IPv4 TCP flaws are only reachable with
packets that carry IPv4 options (CVE-2026-98432, a use-after-free on the
handshake path triggered by SYNs with options, is one). Ordinary TCP traffic
carries no IPv4 options, so dropping those packets until a fixed kernel runs
costs nothing in practice.

``present`` installs:

- ``/etc/ops-deploy/ip-options-drop.nft``: one table ``ip ip_options_drop``
  with a ``prerouting`` filter chain at priority -300 (``raw``: after
  defragmentation, before conntrack) and the single rule
  ``meta l4proto tcp ip hdrlength gt 5 counter drop``. The file declares and
  deletes the table before it defines it, so ``nft -f`` replaces exactly this
  table in one transaction and never touches another table.
- ``ip-options-drop.service``: a oneshot that loads the file at boot (before
  ``network-pre.target``, after ``nftables.service``, whose
  ``flush ruleset`` would otherwise remove it), re-applies it on reload and
  deletes the table on stop. A restart or reload of ``nftables.service``
  re-applies it too (``PartOf=``, ``ReloadPropagatedFrom=``).

The deploy starts the unit when it is not active and reloads it when the file
or unit changed or the loaded table is missing or differs, so a host converges
again after something flushed the ruleset. ``absent`` disables and stops the
unit, removes both files and deletes a table still loaded.

While planning, the loaded table is read (never changed) and its counter is
logged, so ``--dry`` shows how many packets the rule dropped since it was
last loaded; for ``present``, ``nft -c`` also checks the file against the
running kernel before any change.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from io import StringIO
from typing import Literal

from pyinfra import host, logger
from pyinfra.api import DeployError, deploy
from pyinfra.api.operation import OperationMeta
from pyinfra.operations import files, server, systemd
from pyinfra.operations.util import any_changed

from ops_deploy.base._common import RoleConfig, output, require_linux, require_systemd
from ops_deploy.base._units import ACTIVE, ENABLED, unit_states
from ops_deploy.helpers import mark_read_only, systemd_unit
from ops_deploy.helpers.probes import probe

NFT = "/usr/sbin/nft"
TABLE = "ip_options_drop"
CHAIN = "prerouting"
CONFIG_DIR = "/etc/ops-deploy"
RULESET_PATH = f"{CONFIG_DIR}/ip-options-drop.nft"
SERVICE = "ip-options-drop.service"
UNIT_PATH = f"/etc/systemd/system/{SERVICE}"
HEADER = "Managed by ops-deploy (base.ip_options_drop). Do not edit."
RULE = "meta l4proto tcp ip hdrlength gt 5 counter drop"

# ``nft list table`` as nftables 1.0.6, 1.0.9 and 1.1.3 print the loaded table
# (``gt`` as ``>``, priority -300 as ``raw``), one entry per non-empty line.
_LISTING = (
    re.compile(rf"table ip {TABLE} \{{"),
    re.compile(rf"chain {CHAIN} \{{"),
    re.compile(r"type filter hook prerouting priority (raw|-300); policy accept;"),
    re.compile(r"meta l4proto tcp ip hdrlength > 5 counter packets (?P<packets>[0-9]+) bytes (?P<bytes>[0-9]+) drop"),
    re.compile(r"\}"),
    re.compile(r"\}"),
)


class IpOptionsDropConfig(RoleConfig):
    """``present`` installs and loads the drop rule; ``absent`` removes every trace of it."""

    state: Literal["present", "absent"] = "present"


def render_ruleset() -> str:
    """``/etc/ops-deploy/ip-options-drop.nft``; ``nft -f`` replaces only this table, atomically."""

    return (
        f"#!{NFT} -f\n"
        f"# {HEADER}\n"
        "# Drops IPv4 TCP packets that carry IP options (IHL > 5) before conntrack.\n"
        f"# Loaded by {SERVICE}; only this table is replaced, no other is touched.\n"
        f"table ip {TABLE}\n"
        f"delete table ip {TABLE}\n"
        f"table ip {TABLE} {{\n"
        f"\tchain {CHAIN} {{\n"
        "\t\ttype filter hook prerouting priority -300; policy accept;\n"
        f"\t\t{RULE}\n"
        "\t}\n"
        "}\n"
    )


def render_service() -> str:
    return (
        f"# {HEADER}\n"
        "[Unit]\n"
        "Description=Drop IPv4 TCP packets that carry IP options\n"
        "DefaultDependencies=no\n"
        "Wants=network-pre.target\n"
        "Before=network-pre.target\n"
        # nftables.service flushes the whole ruleset when it starts or reloads;
        # load after it, and again whenever it restarts or reloads.
        "After=nftables.service\n"
        "PartOf=nftables.service\n"
        "ReloadPropagatedFrom=nftables.service\n"
        f"ConditionPathExists={RULESET_PATH}\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        "RemainAfterExit=yes\n"
        "StandardInput=null\n"
        f"ExecStart={NFT} -f {RULESET_PATH}\n"
        f"ExecReload={NFT} -f {RULESET_PATH}\n"
        f"ExecStop=-{NFT} delete table ip {TABLE}\n"
        "\n"
        "[Install]\n"
        "WantedBy=sysinit.target\n"
    )


# Prints ``no-nft``, ``absent`` or ``loaded`` followed by the table; fails only
# when nft itself fails.
STATUS_COMMAND = (
    f"if [ ! -x {NFT} ]; then echo no-nft; exit 0; fi; "
    f"tables=$({NFT} list tables ip) || exit 1; "
    f"if printf '%s\\n' \"$tables\" | grep -qx 'table ip {TABLE}'; "
    f"then echo loaded; {NFT} list table ip {TABLE} || exit 1; else echo absent; fi"
)


@dataclass(frozen=True)
class TableStatus:
    """What :data:`STATUS_COMMAND` found: whether the table is loaded and is the expected one."""

    loaded: bool
    current: bool = False
    packets: int | None = None
    bytes: int | None = None
    nft_missing: bool = False

    def describe(self) -> str:
        if self.nft_missing:
            return f"{NFT} not found; table not loaded"
        if not self.loaded:
            return f"table ip {TABLE} not loaded"
        if not self.current:
            return f"table ip {TABLE} loaded but differs from the managed rule"
        return (
            f"table ip {TABLE} loaded; dropped {self.packets} packet(s), {self.bytes} byte(s) since it was last loaded"
        )


def parse_status(answer: str | None) -> TableStatus:
    """:data:`STATUS_COMMAND`'s answer; an unreadable one fails the deploy."""

    if answer is None:
        raise DeployError(f"ip_options_drop: could not read the nftables state (nft list table ip {TABLE})")
    lines = [line.strip() for line in answer.splitlines() if line.strip()]
    head, body = (lines[0], lines[1:]) if lines else ("", [])
    if head == "no-nft" and not body:
        return TableStatus(loaded=False, nft_missing=True)
    if head == "absent" and not body:
        return TableStatus(loaded=False)
    if head != "loaded":
        raise DeployError("ip_options_drop: unexpected answer from the nftables probe")
    if len(body) != len(_LISTING):
        return TableStatus(loaded=True)
    counter = None
    for line, pattern in zip(body, _LISTING, strict=True):
        match = pattern.fullmatch(line)
        if match is None:
            return TableStatus(loaded=True)
        if "packets" in pattern.groupindex:
            counter = match
    assert counter is not None
    return TableStatus(loaded=True, current=True, packets=int(counter["packets"]), bytes=int(counter["bytes"]))


def check_command(state: Literal["present", "absent"]) -> str:
    """Read-only check after the run: the managed table is loaded (or gone) and the unit agrees."""

    if state == "present":
        return (
            f"systemctl is-active --quiet {SERVICE} || {{ echo '{SERVICE} is not active' >&2; exit 1; }}; "
            f"{NFT} list chain ip {TABLE} {CHAIN} "
            "| grep -q 'meta l4proto tcp ip hdrlength > 5 counter packets [0-9]* bytes [0-9]* drop' "
            f"|| {{ echo 'table ip {TABLE} does not hold the drop rule' >&2; exit 1; }}"
        )
    return (
        f"if [ -e {UNIT_PATH} ] || [ -e {RULESET_PATH} ]; then echo 'ip_options_drop files remain' >&2; exit 1; fi; "
        f"if [ -x {NFT} ] && {NFT} list tables ip | grep -qx 'table ip {TABLE}'; "
        f"then echo 'table ip {TABLE} is still loaded' >&2; exit 1; fi"
    )


def _kind(path: str) -> str:
    kind = output(f"LC_ALL=C LANG=C stat -c %F {path} 2>/dev/null || echo missing")
    if not kind:
        raise DeployError(f"ip_options_drop: could not read the file type of {path}")
    return kind


@deploy("IPv4 options drop")
def deploy_ip_options_drop(cfg: IpOptionsDropConfig) -> None:
    require_linux("ip_options_drop")
    require_systemd("ip_options_drop")

    status = parse_status(probe(STATUS_COMMAND, name="ip_options_drop table"))
    logger.info(f"{host.print_prefix}ip_options_drop: {status.describe()}")
    # A symlink or directory in the way is refused before any change.
    present = []
    for path in (UNIT_PATH, RULESET_PATH):
        kind = _kind(path)
        if kind not in ("missing", "regular file", "regular empty file"):
            raise DeployError(f"ip_options_drop: {path} is a {kind}, not a regular file")
        if kind != "missing":
            present.append(path)
    unit = unit_states([SERVICE])[SERVICE]

    if cfg.state == "absent":
        _remove(status, unit, present)
        return

    if status.nft_missing:
        raise DeployError(f"ip_options_drop needs nftables ({NFT}); install the nftables package first")
    # Ask the running kernel whether it accepts the ruleset, before any change.
    if probe(f"{NFT} -c -f -", name="nft -c of the ip_options_drop ruleset", stdin=render_ruleset()) is None:
        raise DeployError("ip_options_drop: nft -c refused the ruleset on this host; nothing was changed")

    files.directory(name=f"Ensure {CONFIG_DIR}", path=CONFIG_DIR, user="root", group="root", mode="0755")
    ruleset = files.put(
        name=f"Write {RULESET_PATH}",
        src=StringIO(render_ruleset()),
        dest=RULESET_PATH,
        user="root",
        group="root",
        mode="0644",
    )
    installed = systemd_unit(SERVICE, render_service())
    systemd.daemon_reload(name=f"Reload systemd for {SERVICE}", _if=installed.did_change)
    # Only a persistent enablement survives a reboot (not ``enabled-runtime``,
    # which lives under /run).
    if unit.get("UnitFileState") != "enabled":
        server.shell(name=f"Enable {SERVICE}", commands=[f"systemctl enable {SERVICE}"])
    _load(status, unit, ruleset, installed)
    mark_read_only(server.shell(name="Check the ip_options_drop table", commands=[check_command("present")]))


def _load(status: TableStatus, unit: dict[str, str], ruleset: OperationMeta, installed: OperationMeta) -> None:
    """Start an inactive unit; reload an active one when anything it loads changed or drifted."""

    if unit.get("ActiveState") != "active":
        server.shell(name=f"Start {SERVICE}", commands=[f"systemctl start {SERVICE}"])
    elif not status.current:
        server.shell(name=f"Reload {SERVICE} (table missing or changed)", commands=[f"systemctl reload {SERVICE}"])
    else:
        server.shell(
            name=f"Reload {SERVICE}",
            commands=[f"systemctl reload {SERVICE}"],
            _if=any_changed(ruleset, installed),
        )


def _remove(status: TableStatus, unit: dict[str, str], present: list[str]) -> None:
    commands = []
    if unit.get("UnitFileState") in ENABLED:
        commands.append(f"systemctl disable {SERVICE}")
    if unit.get("ActiveState") in ACTIVE:
        # ExecStop deletes the table.
        commands.append(f"systemctl stop {SERVICE}")
    if commands:
        server.shell(name=f"Disable and stop {SERVICE}", commands=commands)
    removed = [files.file(name=f"Remove {path}", path=path, present=False) for path in present]
    if removed:
        systemd.daemon_reload(name=f"Reload systemd after removing {SERVICE}", _if=any_changed(*removed))
    if status.loaded:
        # Stopping the unit already deleted it, unless the unit was not active.
        server.shell(
            name=f"Delete table ip {TABLE}",
            commands=[f"if {NFT} list tables ip | grep -qx 'table ip {TABLE}'; then {NFT} delete table ip {TABLE}; fi"],
        )
    mark_read_only(server.shell(name="Check the ip_options_drop table is gone", commands=[check_command("absent")]))
