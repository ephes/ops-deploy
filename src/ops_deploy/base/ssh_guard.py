"""fail2ban for sshd and an sshd hardening drop-in (the ``ssh_guard_deploy`` role, extended).

With the role's fields only, the jail file and the drop-in are byte-identical
to the role's templates, header included, so switching a host between the tools
rewrites nothing. On top of the role the deploy

- writes ``/etc/fail2ban/filter.d/sshd.local`` while the packaged sshd filter
  still accepts ``on <token>`` after the host (CVE-2026-109786: a crafted user
  name makes fail2ban ban an address of the attacker's choice). The file holds
  the two lines of upstream fail2ban commit ddd879d and is removed again once
  the packaged ``sshd.conf`` no longer has the vulnerable pattern. A
  ``sshd.local`` the deploy did not write is refused.
- renders optional jail keys (``banaction``, ``journalmatch``, ``action``).
- installs ``python3-systemd`` for the systemd backend and ``nftables`` for an
  nftables ban action, after fail2ban has loaded the fixed filter.
- checks the running jail after every fail2ban change (the gate): no loaded
  failregex may contain ``on \\S+``, the ban actions must be firewall actions
  (the configured one among them) and, at the end, their binaries present. A
  failing gate stops fail2ban, which removes its firewall rules, and fails the
  deploy; sshd is never touched by it.
- renders more sshd per-source directives, refused while planning when the
  host's OpenSSH is too old for them, and checks a changed drop-in with
  ``sshd -t`` and its effective values with ``sshd -T`` before the reload.

fail2ban is restarted only when its filter, jail or packages changed and ssh is
reloaded only when the drop-in changed, so a converged host reports no change.
See the "ssh_guard" section of docs/base.md for the order and the differences
from the role.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from io import StringIO
from pathlib import PurePosixPath
from typing import Annotated, Literal

from pydantic import Field, StrictBool, StrictInt, model_validator
from pyinfra import host
from pyinfra.api import DeployError, deploy
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.deb import DebPackages
from pyinfra.facts.server import Which
from pyinfra.operations import apt, files, server, systemd
from pyinfra.operations.util import any_changed

from ops_deploy.base._common import AbsolutePath, RoleConfig, output, require_linux, require_systemd
from ops_deploy.base._units import ENABLED

# The role's header line, kept byte for byte.
HEADER = "# Managed by ops-library ssh_guard_deploy. Do not edit.\n"
JAIL_DIR = "/etc/fail2ban/jail.d"
JAIL_PATH = f"{JAIL_DIR}/ssh-guard.local"
FILTER_DIR = "/etc/fail2ban/filter.d"
STOCK_FILTER = f"{FILTER_DIR}/sshd.conf"
FILTER_OVERRIDE = f"{FILTER_DIR}/sshd.local"
# First line of the filter override; a sshd.local without it is not ours.
OVERRIDE_HEADER = "# Managed by ops-deploy ssh_guard. Do not edit.\n"
# The vulnerable packaged filter has this in ``__suff`` and ``__on_port_opt``;
# upstream's fix (and the override) has it nowhere.
VULNERABLE_MARKER = r"on \S+"
FILTER_OVERRIDE_CONTENT = (
    OVERRIDE_HEADER + "# CVE-2026-109786: the sshd filter must not accept an 'on <token>' suffix after\n"
    "# the host, because OpenSSH logs the offered user name verbatim. These are the\n"
    "# two lines of upstream fail2ban commit ddd879d (filter.d/sshd.conf); the deploy\n"
    "# removes this file once the packaged sshd.conf no longer has the old pattern.\n"
    "[Definition]\n"
    r"__on_port_opt = (?: port \d+)?" + "\n"
    r"__suff = %(__on_port_opt)s(?: \[preauth\])?\s*" + "\n"
)
# OpenSSH 10 logs pre-authentication failures from this process.
SSHD_SESSION = "/usr/lib/openssh/sshd-session"
# The role validates the main config, which includes every drop-in.
SSHD_CONFIG = "/etc/ssh/sshd_config"
# Seconds the gate waits for the jail after a fail2ban (re)start.
GATE_WAIT = 60

# A value rendered into one line of a config file: no line breaks or other control characters.
Line = Annotated[str, Field(pattern=r"^[^\x00-\x1f\x7f]*$")]
UnitName = Annotated[str, Field(pattern=r"^[A-Za-z0-9_.@:-]+$")]
Package = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9+.-]+$")]
# The jail name is the ``[section]`` header; brackets or ``=`` would change it.
JailName = Annotated[str, Field(pattern=r"^[A-Za-z0-9_.@-]+$")]
# Firewall ban actions only (no mail or whois actions), optionally with parameters.
BanAction = Annotated[str, Field(pattern=r"^((nftables|iptables)[a-z-]*(\[[a-z=,]*\])?)?$")]
_TOKEN = r"[^\s\x00-\x1f\x7f]+"
# journalctl-style matches, ``+`` between them (OR).
JournalMatch = Annotated[str, Field(pattern=rf"^([A-Z0-9_]+={_TOKEN}( \+ [A-Z0-9_]+={_TOKEN})*)?$")]
# Only the forms whose ``sshd -T`` line is the value itself.
MaxStartups = Annotated[str, Field(pattern=r"^([0-9]+:[0-9]+:[0-9]+)?$")]
NetBlockSize = Annotated[str, Field(pattern=r"^([0-9]+:[0-9]+)?$")]
ExemptList = Annotated[str, Field(pattern=r"^([0-9A-Fa-f.:/]+(,[0-9A-Fa-f.:/]+)*)?$")]

# OpenSSH release that first parses each gated directive.
DIRECTIVE_SINCE: dict[str, tuple[int, int]] = {
    "PerSourceMaxStartups": (8, 5),
    "PerSourceNetBlockSize": (8, 5),
    "PerSourcePenalties": (9, 8),
    "PerSourcePenaltyExemptList": (9, 8),
}
_OPENSSH = re.compile(r"OpenSSH_([0-9]+)\.([0-9]+)")
# OpenSSH's time format: ``90``, ``5m``, ``1h30m``.
_TIME = re.compile(r"(?:[0-9]+[sSmMhHdDwW]?)+")
_TIME_PART = re.compile(r"([0-9]+)([sSmMhHdDwW]?)")
_TIME_UNIT = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
_PENALTY_TIMES = ("crash", "authfail", "noauth", "grace-exceeded", "refuseconnection", "max", "min")
_PENALTY_COUNTS = ("max-sources4", "max-sources6")
_PENALTY_MODES = ("overflow", "overflow6")
_PORT_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_-]*")
_SECTION = re.compile(r"\[([^\]]+)\]")
_INLINE_COMMENT = re.compile(r"\s[#;].*$")


def convtime(value: str) -> int | None:
    """Seconds of an OpenSSH time value (what ``sshd -T`` prints), or None."""

    if not _TIME.fullmatch(value):
        return None
    return sum(int(number) * _TIME_UNIT[unit.lower()] for number, unit in _TIME_PART.findall(value))


def penalty_tokens(value: str) -> list[str]:
    """``PerSourcePenalties`` parts as ``sshd -T`` prints them (``authfail:5m`` is ``authfail:300``).

    ``no`` stands alone. Raises ValueError for anything but known
    ``key:value`` pairs, each key at most once.
    """

    if value == "no":
        return ["no"]
    tokens: list[str] = []
    seen: set[str] = set()
    for part in value.split():
        key, sep, raw = part.partition(":")
        if not sep or key in seen:
            raise ValueError(f"per_source_penalties: {part!r} is not a single key:value pair")
        seen.add(key)
        if key in _PENALTY_TIMES:
            seconds = convtime(raw)
            if seconds is None:
                raise ValueError(f"per_source_penalties: {part!r} needs an OpenSSH time value")
            tokens.append(f"{key}:{seconds}")
        elif key in _PENALTY_COUNTS and raw.isdigit():
            tokens.append(f"{key}:{int(raw)}")
        elif key in _PENALTY_MODES and raw in ("deny-all", "permissive"):
            tokens.append(part)
        else:
            raise ValueError(f"per_source_penalties: {part!r} is not a known PerSourcePenalties setting")
    if not tokens:
        raise ValueError("per_source_penalties: no setting given")
    return tokens


class SshGuardConfig(RoleConfig):
    fail2ban_enabled: bool = True
    fail2ban_package: Package = "fail2ban"
    fail2ban_service_name: UnitName = "fail2ban"
    fail2ban_jail_name: JailName = "sshd"
    fail2ban_backend: Line = "systemd"
    fail2ban_filter: Line = "sshd"
    fail2ban_port: Line = "ssh"
    # Strict: the role renders the value as given, so ``True``, ``"03"`` or
    # ``3.0`` would be written differently from a coerced int; they are refused.
    fail2ban_maxretry: StrictInt = 5
    fail2ban_findtime: Line = "10m"
    fail2ban_bantime: Line = "1h"
    # Empty: no ``ignoreip`` line.
    fail2ban_ignoreip: Line = "127.0.0.1/8 ::1 100.64.0.0/10"
    # Not in the role. ``auto``: manage /etc/fail2ban/filter.d/sshd.local (the
    # CVE-2026-109786 override) as the packaged filter needs it; ``off``: never
    # touch that file (the gate still refuses a vulnerable loaded filter).
    fail2ban_sshd_filter_fix: Literal["auto", "off"] = "auto"
    # Not in the role; empty leaves the line out (the packaged default applies).
    fail2ban_banaction: BanAction = ""
    fail2ban_journalmatch: JournalMatch = ""
    # ``action = %(action_)s``: ban only, no mail or whois actions.
    fail2ban_ban_only: StrictBool = False
    # apt without Recommends (no whois or mail tools pulled in by fail2ban).
    fail2ban_no_recommends: StrictBool = False

    sshd_dropin_enabled: bool = True
    sshd_dropin_path: AbsolutePath = "/etc/ssh/sshd_config.d/99-ssh-guard.conf"
    sshd_service_name: UnitName = "ssh"
    # Empty string: the directive is left out. None is refused (as in the role).
    per_source_max_startups: Line | None = "5"
    max_auth_tries: Line = ""
    login_grace_time: Line = ""
    # Not in the role; empty leaves the directive out.
    max_startups: MaxStartups = ""
    per_source_net_block_size: NetBlockSize = ""
    per_source_penalties: Line = ""
    per_source_penalty_exempt_list: ExemptList = ""

    @model_validator(mode="after")
    def _role_asserts(self) -> SshGuardConfig:
        # The role's two ``assert`` tasks, each only for the enabled part.
        if self.fail2ban_enabled and self.fail2ban_maxretry <= 0:
            raise ValueError("fail2ban_maxretry must be > 0")
        if self.sshd_dropin_enabled and self.per_source_max_startups is None:
            raise ValueError("use an empty string to omit PerSourceMaxStartups (None is invalid)")
        path = PurePosixPath(self.sshd_dropin_path)
        if self.sshd_dropin_enabled and (path.name in ("", ".", "..") or str(path.parent) == "/"):
            raise ValueError("sshd_dropin_path must be a file below a directory, not in /")
        return self

    @model_validator(mode="after")
    def _extensions_are_valid(self) -> SshGuardConfig:
        if self.per_source_net_block_size:
            ipv4, ipv6 = (int(part) for part in self.per_source_net_block_size.split(":"))
            if ipv4 > 32 or ipv6 > 128:
                raise ValueError("per_source_net_block_size must be <ipv4 0-32>:<ipv6 0-128>")
        if self.per_source_penalties:
            penalty_tokens(self.per_source_penalties)
        return self

    @property
    def dropin_dir(self) -> str:
        return str(PurePosixPath(self.sshd_dropin_path).parent)

    @property
    def banaction_name(self) -> str:
        """The action name fail2ban reports for ``fail2ban_banaction`` (parameters dropped)."""

        return self.fail2ban_banaction.partition("[")[0]


def render_jail(cfg: SshGuardConfig) -> str:
    """``fail2ban-sshd.local.j2`` from the role, byte for byte, then the extra jail keys."""

    ignore = f"ignoreip = {cfg.fail2ban_ignoreip}\n" if cfg.fail2ban_ignoreip else ""
    extra = "".join(
        line
        for line, wanted in (
            (f"banaction = {cfg.fail2ban_banaction}\n", cfg.fail2ban_banaction),
            (f"journalmatch = {cfg.fail2ban_journalmatch}\n", cfg.fail2ban_journalmatch),
            ("action = %(action_)s\n", cfg.fail2ban_ban_only),
        )
        if wanted
    )
    return (
        f"{HEADER}[{cfg.fail2ban_jail_name}]\nenabled = true\n"
        f"backend = {cfg.fail2ban_backend}\nfilter = {cfg.fail2ban_filter}\nport = {cfg.fail2ban_port}\n"
        f"maxretry = {cfg.fail2ban_maxretry}\nfindtime = {cfg.fail2ban_findtime}\nbantime = {cfg.fail2ban_bantime}\n"
        f"{ignore}{extra}"
    )


def dropin_directives(cfg: SshGuardConfig) -> list[tuple[str, str]]:
    """``(directive, value)`` in file order; the role's three first, empty values left out."""

    directives = (
        ("PerSourceMaxStartups", cfg.per_source_max_startups or ""),
        ("MaxAuthTries", cfg.max_auth_tries),
        ("LoginGraceTime", cfg.login_grace_time),
        ("MaxStartups", cfg.max_startups),
        ("PerSourceNetBlockSize", cfg.per_source_net_block_size),
        ("PerSourcePenalties", cfg.per_source_penalties),
        ("PerSourcePenaltyExemptList", cfg.per_source_penalty_exempt_list),
    )
    return [(key, value) for key, value in directives if value]


def render_dropin(cfg: SshGuardConfig) -> str:
    """``sshd-guard.conf.j2`` from the role, byte for byte, then the extra directives."""

    return HEADER + "".join(f"{key} {value}\n" for key, value in dropin_directives(cfg))


def _numbers(value: str) -> str:
    """``a:b:c`` of decimal numbers as sshd prints them (no leading zeros)."""

    return ":".join(str(int(part)) for part in value.split(":"))


def effective_lines(cfg: SshGuardConfig) -> list[str]:
    """``sshd -T`` lines (lowercase) the drop-in must produce.

    Numbers as sshd prints them (``05`` is ``5``, ``LoginGraceTime 1m`` is
    ``60``). A role field whose printed form cannot be derived here (free text
    that ``sshd -t`` may still accept) gets no line; ``sshd -t`` checks it.
    PerSourcePenalties other than ``no`` is matched by part
    (``penalty_tokens``).
    """

    lines = []
    for key, value in dropin_directives(cfg):
        printed: str | None = value.lower()
        if key == "LoginGraceTime":
            seconds = convtime(value)
            printed = None if seconds is None else str(seconds)
        elif key in ("PerSourceMaxStartups", "MaxAuthTries"):
            if value.isdigit():
                printed = str(int(value))
            elif value.lower() != "none":
                printed = None
        elif key in ("MaxStartups", "PerSourceNetBlockSize"):
            printed = _numbers(value)
        elif key == "PerSourcePenalties":
            printed = "no" if value == "no" else None
        if printed is not None:
            lines.append(f"{key.lower()} {printed}")
    return lines


def validate_command(cfg: SshGuardConfig) -> str:
    """``sshd -t``, then the effective values from ``sshd -T``; on any failure remove the drop-in and fail.

    The role's ``rescue`` covers ``sshd -t``. sshd takes the first value it
    reads, so an earlier drop-in that sets the same directive wins over this
    one: the ``sshd -T`` check catches that before the reload.
    """

    path = shlex.quote(cfg.sshd_dropin_path)
    removed = f"removed {cfg.sshd_dropin_path}."

    def fail(message: str) -> str:
        return f"{{ rm -f -- {path}; echo {message} >&2; exit 1; }}"

    command = f"sshd -t -f {SSHD_CONFIG} || " + fail(shlex.quote(f"Invalid sshd config; {removed}"))
    lines = effective_lines(cfg)
    penalties = penalty_tokens(cfg.per_source_penalties) if cfg.per_source_penalties not in ("", "no") else []
    if not lines and not penalties:
        return command
    command += f"; eff=$(sshd -T -f {SSHD_CONFIG}) || " + fail(shlex.quote(f"sshd -T failed; {removed}"))
    if lines:
        wanted = " ".join(shlex.quote(line) for line in lines)
        command += (
            f'; for want in {wanted}; do printf "%s\\n" "$eff" | grep -qixF -- "$want" || '
            + fail(f'"sshd -T does not show: $want; {removed}"')
            + "; done"
        )
    if penalties:
        # Part by part: a word must match exactly, a number by value (OpenSSH
        # 10.3 prints the times as 300.000000, earlier releases as 300).
        command += (
            '; pen=$(printf "%s\\n" "$eff" | grep -i \'^persourcepenalties \' | tr " " "\\n")'
            f"; for want in {' '.join(penalties)}; do key=${{want%%:*}}; val=${{want#*:}}"
            '; got=$(printf "%s\\n" "$pen" | sed -n "s/^$key://p" | head -n 1)'
            '; case "$val" in *[!0-9]*) [ "$got" = "$val" ];; '
            '*) [ -n "$got" ] && awk -v a="$got" -v b="$val" "BEGIN { exit !(a + 0 == b + 0) }";; esac || '
            + fail(f'"sshd -T persourcepenalties lacks $want; {removed}"')
            + "; done"
        )
    return command


def reload_command(service: str) -> str:
    """The role handler's ``state: reloaded``: reload a running unit, start a stopped one."""

    unit = shlex.quote(service)
    return f"if systemctl is-active --quiet {unit}; then systemctl reload {unit}; else systemctl start {unit}; fi"


def restart_command(cfg: SshGuardConfig) -> str:
    return f"systemctl restart {shlex.quote(cfg.fail2ban_service_name)}"


def gate_command(cfg: SshGuardConfig, *, final: bool) -> str:
    """Check the running jail; stop fail2ban and fail when it is vulnerable or not what was configured.

    Always: the jail is up (waits up to ``GATE_WAIT`` seconds after a
    restart), it loaded failregexes and none contains ``on \\S+``, it has ban
    actions and all are firewall actions, the configured ``banaction`` among
    them (the only one with ``ban_only``). ``final`` (after the package
    installs) adds: the actions' binaries exist and, on an OpenSSH that logs
    from ``sshd-session``, the loaded prefix regex accepts that name. An
    enabled ``nftables.service`` (its ``flush ruleset`` would drop fail2ban's
    rules, and Tailscale's and Docker's) fails the deploy without stopping
    fail2ban.
    """

    unit = shlex.quote(cfg.fail2ban_service_name)
    jail = shlex.quote(cfg.fail2ban_jail_name)
    parts = [
        f'stop() {{ echo "ssh_guard gate: $1; stopping {cfg.fail2ban_service_name}" >&2; systemctl stop {unit}; '
        "exit 1; }",
        f"i=0; until fail2ban-client status {jail} >/dev/null 2>&1; do i=$((i+1)); "
        f'[ "$i" -lt {GATE_WAIT} ] || stop "jail {cfg.fail2ban_jail_name} is not up after {GATE_WAIT} s"; '
        "sleep 1; done",
        f'regex=$(fail2ban-client get {jail} failregex) || stop "cannot read the loaded failregex"',
        'case "$regex" in *"[0]: "*) ;; *) stop "the jail loaded no failregex";; esac',
        "case \"$regex\" in *'on \\S+'*) stop \"the loaded sshd filter accepts 'on <token>' (CVE-2026-109786)\";; esac",
        f'out=$(fail2ban-client get {jail} actions) || stop "cannot read the ban actions"',
        'actions=$(printf "%s\\n" "$out" | sed 1d | tr "," " ")',
        '[ -n "$(echo $actions)" ] || stop "the jail has no ban action"',
        'for a in $actions; do case "$a" in nftables*|iptables*) ;; '
        '*) stop "ban action $a is not a firewall action";; esac; done',
    ]
    if cfg.fail2ban_banaction:
        name = cfg.banaction_name
        parts.append(f'case " $(echo $actions) " in *" {name} "*) ;; *) stop "ban action {name} is not loaded";; esac')
    if cfg.fail2ban_ban_only:
        parts.append('[ "$(echo $actions | wc -w)" -eq 1 ] || stop "more than one ban action with ban_only"')
    if final:
        parts += [
            'for a in $actions; do case "$a" in '
            'nftables*) command -v nft >/dev/null || stop "nft is missing for $a";; '
            "iptables*) { command -v iptables && command -v ip6tables; } >/dev/null || "
            'stop "iptables or ip6tables is missing for $a";; esac; done',
            f"if [ -e {SSHD_SESSION} ]; then pref=$(fail2ban-client get {jail} prefregex) && "
            'case "$pref" in *-session*) ;; *) false;; esac || '
            'stop "OpenSSH logs from sshd-session but the loaded filter does not accept it"; fi',
            'case "$(systemctl is-enabled nftables.service 2>/dev/null)" in enabled*|linked*) '
            'echo "ssh_guard gate: nftables.service is enabled; its flush ruleset would drop the bans" >&2; '
            "exit 1;; esac",
        ]
    return "; ".join(parts)


def probe_command(cfg: SshGuardConfig) -> str:
    """One read-only probe for everything the plan depends on (``key=value`` lines).

    With fail2ban running it also reads what the jail has loaded, so a host
    whose files are right but whose fail2ban still runs older ones (an
    interrupted run) gets the restart and the gate again.
    """

    unit = shlex.quote(cfg.fail2ban_service_name)
    jail = shlex.quote(cfg.fail2ban_jail_name)
    ports = "".join(
        f"; echo \"port_{name}=$(getent services {shlex.quote(name)}/tcp | awk '{{print $2}}' | cut -d/ -f1)\""
        for name in sorted(set(_PORT_NAME.findall(cfg.fail2ban_port)))
    )
    return (
        ": ssh_guard probe; LC_ALL=C; export LC_ALL"
        '; echo "ssh_version=$(ssh -V 2>&1 | head -n 1)"'
        f"; if [ -e {SSHD_SESSION} ]; then echo sshd_session=yes; else echo sshd_session=no; fi"
        f'; echo "stock_kind=$(stat -c %F {STOCK_FILTER} 2>/dev/null || echo missing)"'
        f"; echo \"stock_marker=$(grep -cF '{VULNERABLE_MARKER}' {STOCK_FILTER} 2>/dev/null)\""
        f"; echo \"stock_daemon=$(grep -E '^_daemon[[:space:]]*=' {STOCK_FILTER} 2>/dev/null | head -n 1)\""
        f'; echo "override_kind=$(stat -c %F {FILTER_OVERRIDE} 2>/dev/null || echo missing)"'
        f'; echo "override_head=$(head -n 1 {FILTER_OVERRIDE} 2>/dev/null)"'
        '; echo "nftables_service=$(systemctl is-enabled nftables.service 2>/dev/null)"'
        f"; if systemctl is-active --quiet {unit}; then"
        f" if regex=$(fail2ban-client get {jail} failregex 2>/dev/null); then"
        f" echo \"loaded_marker=$(printf '%s\\n' \"$regex\" | grep -cF '{VULNERABLE_MARKER}')\"; fi"
        f'; echo "loaded_actions=$(fail2ban-client get {jail} actions 2>/dev/null | sed 1d)"; fi'
        # The ban action lines of fail2ban's jail configuration in its read
        # order, without this deploy's jail file: what a jail without its own
        # banaction inherits.
        "; for f in /etc/fail2ban/jail.conf /etc/fail2ban/jail.d/*.conf /etc/fail2ban/jail.local"
        f' /etc/fail2ban/jail.d/*.local; do [ -f "$f" ] && [ "$f" != {JAIL_PATH} ] || continue'
        "; grep -E '^[[:space:]]*([[][^]]*[]]|banaction[[:space:]]*=)' \"$f\" | sed 's/^/jailconf=/'; done"
        f"{ports}"
    )


@dataclass(frozen=True)
class HostState:
    """What ``probe_command`` found."""

    openssh: tuple[int, int] | None = None
    sshd_session: bool = False
    stock_kind: str = "missing"
    # Lines of the packaged filter with the vulnerable pattern; None when unreadable.
    stock_marker: int | None = None
    stock_daemon: str = ""
    override_kind: str = "missing"
    override_head: str = ""
    nftables_service: str = ""
    # Port number per service name in ``fail2ban_port`` ("" when it does not resolve).
    ports: dict[str, str] = field(default_factory=dict)
    # A running fail2ban's loaded failregexes with the vulnerable pattern and
    # its ban actions; None/empty when fail2ban or the jail is not running.
    loaded_marker: int | None = None
    loaded_actions: tuple[str, ...] = ()
    # Section headers and ``banaction`` lines of fail2ban's jail configuration
    # without this deploy's jail file, in read order.
    jail_config: tuple[str, ...] = ()

    @classmethod
    def parse(cls, text: str) -> HostState:
        values: dict[str, str] = {}
        jail_config = []
        for line in text.splitlines():
            key, sep, value = line.partition("=")
            if key == "jailconf":
                jail_config.append(value.strip())
            elif sep:
                values.setdefault(key.strip(), value.strip())
        version = _OPENSSH.search(values.get("ssh_version", ""))
        marker = values.get("stock_marker", "")
        loaded = values.get("loaded_marker", "")
        return cls(
            openssh=(int(version.group(1)), int(version.group(2))) if version else None,
            sshd_session=values.get("sshd_session") == "yes",
            stock_kind=values.get("stock_kind") or "missing",
            stock_marker=int(marker) if marker.isdigit() else None,
            stock_daemon=values.get("stock_daemon", ""),
            override_kind=values.get("override_kind") or "missing",
            override_head=values.get("override_head", ""),
            nftables_service=values.get("nftables_service", ""),
            ports={key.removeprefix("port_"): value for key, value in values.items() if key.startswith("port_")},
            loaded_marker=int(loaded) if loaded.isdigit() else None,
            loaded_actions=tuple(values.get("loaded_actions", "").replace(",", " ").split()),
            jail_config=tuple(jail_config),
        )

    def inherited_banaction(self, jail: str) -> str | None:
        """The ban action a jail without its own ``banaction`` gets from the other files.

        fail2ban's rule: the jail's section wins over ``[DEFAULT]``, a later
        file over an earlier one. None when nothing sets it or the value
        interpolates (``%(...)s``), which is not resolved here.
        """

        section, values = "", {}
        for line in self.jail_config:
            # Inline comments after whitespace, as fail2ban's parser allows.
            stripped = _INLINE_COMMENT.sub("", line).strip()
            header = _SECTION.match(stripped)
            if header:
                section = header.group(1).strip()
            elif section in ("DEFAULT", jail):
                values[section] = stripped.partition("=")[2].strip()
        value = values.get(jail, values.get("DEFAULT"))
        if not value or "%(" in value:
            return None
        return value.partition("[")[0].strip()

    def stale(self, cfg: SshGuardConfig) -> bool:
        """Whether the running jail lacks the fix or the configured ban action."""

        if self.loaded_marker is None:
            return False
        return self.loaded_marker > 0 or bool(cfg.fail2ban_banaction and cfg.banaction_name not in self.loaded_actions)


def _check_openssh(cfg: SshGuardConfig, state: HostState) -> None:
    for key, _ in dropin_directives(cfg):
        since = DIRECTIVE_SINCE.get(key)
        if since is None:
            continue
        if state.openssh is None:
            raise DeployError(f"ssh_guard: cannot read the OpenSSH version (ssh -V), needed for {key}")
        if state.openssh < since:
            have = ".".join(map(str, state.openssh))
            raise DeployError(f"ssh_guard: {key} needs OpenSSH {since[0]}.{since[1]} or later; the host has {have}")


def _check_fail2ban(cfg: SshGuardConfig, state: HostState) -> None:
    if cfg.fail2ban_sshd_filter_fix == "auto":
        if state.override_kind not in ("missing", "regular file", "regular empty file"):
            raise DeployError(f"ssh_guard: {FILTER_OVERRIDE} is a {state.override_kind}, not a regular file")
        if state.override_kind != "missing" and state.override_head != OVERRIDE_HEADER.rstrip("\n"):
            raise DeployError(
                f"ssh_guard: {FILTER_OVERRIDE} was not written by this deploy; move it away or set "
                "fail2ban_sshd_filter_fix to off"
            )
    if state.stock_kind not in ("missing", "regular file") or (
        state.stock_kind == "regular file" and state.stock_marker is None
    ):
        raise DeployError(f"ssh_guard: cannot read {STOCK_FILTER} ({state.stock_kind})")
    if state.sshd_session and state.stock_kind == "regular file" and "-session" not in state.stock_daemon:
        raise DeployError(
            f"ssh_guard: OpenSSH logs from sshd-session but the _daemon of {STOCK_FILTER} does not "
            "accept it; fail2ban would miss every failure"
        )
    if state.nftables_service in ENABLED:
        raise DeployError(
            "ssh_guard: nftables.service is enabled; its 'flush ruleset' would drop fail2ban's bans "
            "(and Tailscale's and Docker's rules). Disable it first."
        )
    for name, port in sorted(state.ports.items()):
        if not port.isdigit():
            raise DeployError(f"ssh_guard: the port name {name!r} does not resolve (getent services; netbase?)")


@deploy("SSH guard")
def deploy_ssh_guard(cfg: SshGuardConfig) -> None:
    require_linux("ssh_guard")
    require_systemd("ssh_guard")
    if cfg.fail2ban_enabled and not host.get_fact(Which, command="apt-get"):
        raise DeployError("ssh_guard installs fail2ban with apt; a Debian-family host is required")
    if not (cfg.fail2ban_enabled or cfg.sshd_dropin_enabled):
        return

    state = HostState.parse(output(probe_command(cfg)))
    if cfg.sshd_dropin_enabled:
        _check_openssh(cfg, state)
    if cfg.fail2ban_enabled:
        _check_fail2ban(cfg, state)

    if cfg.sshd_dropin_enabled:
        files.directory(name=f"Ensure {cfg.dropin_dir}", path=cfg.dropin_dir, user="root", group="root", mode="0755")

    if cfg.fail2ban_enabled:
        installed = cfg.fail2ban_package in (host.get_fact(DebPackages) or {})
        _deploy_fail2ban(cfg, state, installed=installed)

    if cfg.sshd_dropin_enabled:
        dropin = files.put(
            name=f"Write {cfg.sshd_dropin_path}",
            src=StringIO(render_dropin(cfg)),
            dest=cfg.sshd_dropin_path,
            user="root",
            group="root",
            mode="0644",
        )
        server.shell(
            name="Validate the sshd configuration",
            commands=[validate_command(cfg)],
            _if=dropin.did_change,
        )
        server.shell(
            name=f"Reload {cfg.sshd_service_name} for the new drop-in",
            commands=[reload_command(cfg.sshd_service_name)],
            _if=dropin.did_change,
        )


def _deploy_fail2ban(cfg: SshGuardConfig, state: HostState, *, installed: bool) -> None:
    service = cfg.fail2ban_service_name
    for directory in (JAIL_DIR, FILTER_DIR):
        files.directory(name=f"Ensure {directory}", path=directory, user="root", group="root", mode="0755")

    # As the role's ``package`` task: no apt cache refresh. The systemd
    # backend's module first (it arms nothing, and a fail2ban installed without
    # Recommends could not load a systemd jail without it); fail2ban and
    # nftables only after the fixed filter and the jail are in place.
    def install(name: str) -> OperationMeta:
        return apt.packages(name=f"Install {name}", packages=[name], no_recommends=cfg.fail2ban_no_recommends)

    packages = [install("python3-systemd")] if cfg.fail2ban_backend.startswith("systemd") else []

    # The filter override and the jail come next: an installed fail2ban is
    # restarted onto them before a package (nftables) can arm a ban action, and
    # a fresh package's postinst starts fail2ban with them already in place.
    config: list[OperationMeta] = []
    if cfg.fail2ban_sshd_filter_fix == "auto":
        if state.stock_kind == "missing" or state.stock_marker:
            config.append(
                files.put(
                    name=f"Write {FILTER_OVERRIDE} (CVE-2026-109786)",
                    src=StringIO(FILTER_OVERRIDE_CONTENT),
                    dest=FILTER_OVERRIDE,
                    user="root",
                    group="root",
                    mode="0644",
                )
            )
        elif state.override_kind != "missing":
            config.append(
                server.shell(
                    name=f"Remove {FILTER_OVERRIDE} (the packaged filter is fixed)",
                    commands=[f"rm -f -- {FILTER_OVERRIDE}"],
                )
            )
    config.append(
        files.put(
            name=f"Write {JAIL_PATH}",
            src=StringIO(render_jail(cfg)),
            dest=JAIL_PATH,
            user="root",
            group="root",
            mode="0644",
        )
    )
    # The running jail lacks the fix or the ban action although the files may
    # be right (a run interrupted before its restart): restart and check anyway.
    stale = installed and state.stale(cfg)
    config_changed = any_changed(*config)
    if installed:
        # A shell step, not ``systemd.service(restarted=True)``: that restarts
        # only a unit running while planning. ``systemctl restart`` also
        # starts a stopped unit, as the role's handler does.
        server.shell(
            name=f"Restart {service} for the new filter or jail",
            commands=[restart_command(cfg)],
            _if=lambda: stale or config_changed(),
        )
        server.shell(
            name="Check the jail before the package installs",
            commands=[gate_command(cfg, final=False)],
            _if=lambda: stale or config_changed(),
        )

    # nftables last, for a configured nftables action or, without one, the one
    # the jail inherits from fail2ban's other files (e.g. Debian 13's default).
    packages.append(install(cfg.fail2ban_package))
    action = cfg.banaction_name or state.inherited_banaction(cfg.fail2ban_jail_name) or ""
    if action.startswith("nftables"):
        packages.append(install("nftables"))
    server.shell(
        name=f"Restart {service} for the new packages",
        commands=[restart_command(cfg)],
        _if=any_changed(*packages),
    )
    ensure = systemd.service(name=f"Ensure {service}", service=service, running=True, enabled=True)
    anything_changed = any_changed(*config, *packages, ensure)
    server.shell(
        name="Check the jail",
        commands=[gate_command(cfg, final=True)],
        _if=lambda: stale or anything_changed(),
    )
