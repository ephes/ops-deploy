"""``deploy_ssh_guard`` against the fake connector, and its files against the role's templates."""

import re
from pathlib import Path
from typing import Any

import jinja2
import pytest
from pydantic import ValidationError

from ops_deploy.base import SshGuardConfig, deploy_ssh_guard
from ops_deploy.base.ssh_guard import (
    FILTER_OVERRIDE,
    FILTER_OVERRIDE_CONTENT,
    HEADER,
    JAIL_PATH,
    OVERRIDE_HEADER,
    HostState,
    convtime,
    effective_lines,
    gate_command,
    penalty_tokens,
    probe_command,
    render_dropin,
    render_jail,
    validate_command,
)
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests import fakehost
from tests.fakehost import LINUX

VENDORED = Path(__file__).parent / "parity" / "ansible"
DROPIN = "/etc/ssh/sshd_config.d/99-ssh-guard.conf"
DEFAULT = SshGuardConfig()
# A Debian 13 host: nftables bans, explicit journal match, ban only, /64 grouping.
NFT_HOST = SshGuardConfig(
    fail2ban_banaction="nftables",
    fail2ban_journalmatch="_SYSTEMD_UNIT=ssh.service + _COMM=sshd + _COMM=sshd-session",
    fail2ban_ban_only=True,
    fail2ban_no_recommends=True,
    fail2ban_ignoreip="127.0.0.1/8 ::1",
    per_source_net_block_size="32:64",
)
# A Debian 12 host: iptables bans kept, OpenSSH 9.2 without sshd-session.
IPTABLES_HOST = SshGuardConfig(
    fail2ban_banaction="iptables-multiport",
    fail2ban_journalmatch="_SYSTEMD_UNIT=ssh.service + _COMM=sshd",
    fail2ban_ban_only=True,
    fail2ban_ignoreip="127.0.0.1/8 ::1",
)

INSTALL = "SSH guard | Install fail2ban"
INSTALL_SYSTEMD = "SSH guard | Install python3-systemd"
INSTALL_NFT = "SSH guard | Install nftables"
ENSURE = "SSH guard | Ensure fail2ban"
DIRS = ("SSH guard | Ensure /etc/fail2ban/jail.d", "SSH guard | Ensure /etc/fail2ban/filter.d")
WRITE_FILTER = f"SSH guard | Write {FILTER_OVERRIDE} (CVE-2026-109786)"
REMOVE_FILTER = f"SSH guard | Remove {FILTER_OVERRIDE} (the packaged filter is fixed)"
WRITE_JAIL = f"SSH guard | Write {JAIL_PATH}"
RESTART = "SSH guard | Restart fail2ban for the new filter or jail"
GATE_EARLY = "SSH guard | Check the jail before the package installs"
RESTART_PACKAGES = "SSH guard | Restart fail2ban for the new packages"
GATE = "SSH guard | Check the jail"
WRITE_DROPIN = f"SSH guard | Write {DROPIN}"
VALIDATE = "SSH guard | Validate the sshd configuration"
RELOAD = "SSH guard | Reload ssh for the new drop-in"
RESTART_CMD = "systemctl restart fail2ban"
RELOAD_CMD = "if systemctl is-active --quiet ssh; then systemctl reload ssh; else systemctl start ssh; fi"
OPENSSH_10 = "OpenSSH_10.0p2 Debian-7+deb13u4, OpenSSL 3.5.7 9 Jun 2026"
OPENSSH_92 = "OpenSSH_9.2p1 Debian-2+deb12u10, OpenSSL 3.0.22 25 Aug 2026"
SESSION_DAEMON = "_daemon = sshd(?:-session)?"


def render_ansible(template: str, cfg: SshGuardConfig) -> str:
    # ansible.builtin.template defaults: trim_blocks on, lstrip_blocks off.
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(VENDORED),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
    )
    variables = {f"ssh_guard_{key}": value for key, value in cfg.model_dump().items()}
    return env.get_template(f"ssh_guard_deploy__{template}").render(**variables)


PARITY = {
    "defaults": DEFAULT,
    "no ignoreip, every sshd directive": SshGuardConfig(
        fail2ban_ignoreip="",
        fail2ban_jail_name="sshd-ddos",
        fail2ban_maxretry=3,
        per_source_max_startups="10:30:60",
        max_auth_tries="3",
        login_grace_time="30s",
    ),
    "no sshd directive": SshGuardConfig(per_source_max_startups=""),
    "other backend and port": SshGuardConfig(fail2ban_backend="auto", fail2ban_port="2222,ssh", fail2ban_bantime="-1"),
    # The deploy's own fields change the host, not the role's two files.
    "filter fix off": SshGuardConfig(fail2ban_sshd_filter_fix="off"),
}


@pytest.mark.parametrize("cfg", PARITY.values(), ids=PARITY.keys())
def test_files_match_the_role(cfg: SshGuardConfig) -> None:
    assert render_jail(cfg) == render_ansible("fail2ban-sshd.local.j2", cfg)
    assert render_dropin(cfg) == render_ansible("sshd-guard.conf.j2", cfg)


def test_default_files() -> None:
    assert render_jail(DEFAULT) == (
        HEADER + "[sshd]\nenabled = true\nbackend = systemd\nfilter = sshd\nport = ssh\n"
        "maxretry = 5\nfindtime = 10m\nbantime = 1h\nignoreip = 127.0.0.1/8 ::1 100.64.0.0/10\n"
    )
    assert render_dropin(DEFAULT) == HEADER + "PerSourceMaxStartups 5\n"
    assert render_dropin(SshGuardConfig(per_source_max_startups="")) == HEADER


def test_extra_jail_keys_and_directives_follow_the_role_lines() -> None:
    assert render_jail(NFT_HOST) == (
        HEADER + "[sshd]\nenabled = true\nbackend = systemd\nfilter = sshd\nport = ssh\n"
        "maxretry = 5\nfindtime = 10m\nbantime = 1h\nignoreip = 127.0.0.1/8 ::1\n"
        "banaction = nftables\njournalmatch = _SYSTEMD_UNIT=ssh.service + _COMM=sshd + _COMM=sshd-session\n"
        "action = %(action_)s\n"
    )
    cfg = SshGuardConfig(
        max_auth_tries="4",
        login_grace_time="1m",
        max_startups="10:30:100",
        per_source_net_block_size="32:64",
        per_source_penalties="authfail:5m max:600",
        per_source_penalty_exempt_list="192.0.2.0/24,2001:db8::/32",
    )
    assert render_dropin(cfg) == HEADER + (
        "PerSourceMaxStartups 5\nMaxAuthTries 4\nLoginGraceTime 1m\nMaxStartups 10:30:100\n"
        "PerSourceNetBlockSize 32:64\nPerSourcePenalties authfail:5m max:600\n"
        "PerSourcePenaltyExemptList 192.0.2.0/24,2001:db8::/32\n"
    )


def test_the_override_is_upstreams_two_lines() -> None:
    # fail2ban ddd879d, config/filter.d/sshd.conf.
    lines = FILTER_OVERRIDE_CONTENT.splitlines()
    assert lines[0] == OVERRIDE_HEADER.rstrip("\n")
    assert lines[-3:] == [
        "[Definition]",
        r"__on_port_opt = (?: port \d+)?",
        r"__suff = %(__on_port_opt)s(?: \[preauth\])?\s*",
    ]
    assert "on \\S+" not in FILTER_OVERRIDE_CONTENT
    assert all(line.startswith("#") for line in lines[:-3])


def probe(
    *,
    openssh: str = OPENSSH_10,
    sshd_session: bool = True,
    stock: str = "vulnerable",
    override: str = "missing",
    nftables_service: str = "not-found",
    ports: dict[str, str] | None = None,
    loaded_marker: int | None = 0,
    loaded_actions: str = "nftables",
    jail_config: tuple[str, ...] = (),
) -> dict[str, Any]:
    """The ``probe_command`` answer of a host."""

    stock_kind, marker, daemon = {
        "vulnerable": ("regular file", "2", SESSION_DAEMON if sshd_session else "_daemon = sshd"),
        "fixed": ("regular file", "0", SESSION_DAEMON if sshd_session else "_daemon = sshd"),
        "no session": ("regular file", "2", "_daemon = sshd"),
        "missing": ("missing", "", ""),
    }[stock]
    override_kind, head = {
        "missing": ("missing", ""),
        "ours": ("regular file", OVERRIDE_HEADER.rstrip("\n")),
        "foreign": ("regular file", "[Definition]"),
        "symlink": ("symbolic link", OVERRIDE_HEADER.rstrip("\n")),
    }[override]
    lines = [
        f"ssh_version={openssh}",
        f"sshd_session={'yes' if sshd_session else 'no'}",
        f"stock_kind={stock_kind}",
        f"stock_marker={marker}",
        f"stock_daemon={daemon}",
        f"override_kind={override_kind}",
        f"override_head={head}",
        f"nftables_service={nftables_service}",
    ]
    if loaded_marker is not None:
        lines += [f"loaded_marker={loaded_marker}", f"loaded_actions={loaded_actions}"]
    lines += [f"jailconf={line}" for line in jail_config]
    lines += [f"port_{name}={port}" for name, port in (ports if ports is not None else {"ssh": "22"}).items()]
    return {": ssh_guard probe": lines}


def converged(cfg: SshGuardConfig = DEFAULT, **probe_args: Any) -> dict[str, Any]:
    # Without a configured ban action the jail runs the packaged default (nftables here).
    probe_args.setdefault("loaded_actions", cfg.banaction_name or "nftables")
    action = cfg.banaction_name or probe_args["loaded_actions"]
    packages = ["fail2ban", "python3-systemd"] + (["nftables"] if action.startswith("nft") else [])
    fixed = probe_args.get("stock") == "fixed"
    override = {} if fixed else fakehost.file(FILTER_OVERRIDE, FILTER_OVERRIDE_CONTENT)
    probe_args.setdefault("override", "missing" if fixed else "ours")
    return {
        **probe(**probe_args),
        **fakehost.UBUNTU,
        **fakehost.directory("/etc/ssh/sshd_config.d"),
        **fakehost.directory("/etc/fail2ban/jail.d"),
        **fakehost.directory("/etc/fail2ban/filter.d"),
        **fakehost.deb_installed(*packages),
        **fakehost.service("fail2ban.service"),
        **override,
        **fakehost.file(JAIL_PATH, render_jail(cfg)),
        **fakehost.file(cfg.sshd_dropin_path, render_dropin(cfg)),
    }


def run(responses: dict[str, Any], cfg: SshGuardConfig = DEFAULT, *, ok: bool = True) -> FakeRun:
    result = run_deploy_fake(deploy_ssh_guard, cfg, responses=responses)
    assert result.succeeded is ok, result.error
    return result


@pytest.mark.parametrize("cfg", [DEFAULT, NFT_HOST, IPTABLES_HOST], ids=["defaults", "nftables host", "iptables host"])
def test_converged_host_changes_nothing(cfg: SshGuardConfig) -> None:
    result = run(converged(cfg, sshd_session=cfg is not IPTABLES_HOST), cfg)

    assert result.changed_ops == []
    assert result.executed_commands == []
    assert result.uploaded_paths == []


def test_fixed_package_filter_without_override_changes_nothing() -> None:
    result = run(converged(stock="fixed"))

    assert result.changed_ops == []
    assert result.executed_commands == []


# Debian 13: jail.conf's default, overridden by jail.d/defaults-debian.conf.
DEBIAN_13_JAILS = ("[DEFAULT]", "banaction = iptables-multiport", "[DEFAULT]", "banaction = nftables", "[sshd]")


def test_an_inherited_nftables_action_gets_nftables() -> None:
    # No ban action configured: the jail runs the packaged default (Debian 13's nftables).
    responses = exposed_host()
    responses.update(probe(override="missing", loaded_marker=18, jail_config=DEBIAN_13_JAILS))

    result = run(responses)

    assert INSTALL_NFT in result.mutating_changed_ops
    assert result.mutating_changed_ops.index(GATE_EARLY) < result.mutating_changed_ops.index(INSTALL_NFT)


def test_dropping_an_explicit_ban_action_resolves_the_inherited_one() -> None:
    # The jail on the host still says iptables-multiport (and fail2ban runs it);
    # without it the packaged nftables default applies, so nftables is needed.
    responses = exposed_host()
    responses.update(fakehost.file(JAIL_PATH, render_jail(IPTABLES_HOST)))
    responses.update(
        probe(
            override="missing",
            loaded_marker=18,
            loaded_actions="iptables-multiport",
            jail_config=DEBIAN_13_JAILS,
        )
    )

    result = run(responses)

    assert INSTALL_NFT in result.mutating_changed_ops


def test_the_configured_ban_action_wins_over_the_inherited_one() -> None:
    responses = {**converged(IPTABLES_HOST, sshd_session=False), **probe(sshd_session=False, override="ours")}
    responses.update(
        probe(sshd_session=False, override="ours", loaded_actions="iptables-multiport", jail_config=DEBIAN_13_JAILS)
    )

    result = run(responses, IPTABLES_HOST)

    assert result.changed_ops == []


@pytest.mark.parametrize(
    ("lines", "action"),
    [
        (DEBIAN_13_JAILS, "nftables"),
        (("[DEFAULT]", "banaction = iptables-multiport", "[sshd]"), "iptables-multiport"),
        (("[DEFAULT]", "banaction = nftables", "[sshd]", "banaction = iptables-allports"), "iptables-allports"),
        (("[sshd]", "banaction = iptables-allports", "[DEFAULT]", "banaction = nftables"), "iptables-allports"),
        (("[DEFAULT]", "banaction = nftables[type=multiport]"), "nftables"),
        (("[DEFAULT]", "banaction = %(other)s"), None),
        (
            ("[DEFAULT]", "banaction = iptables-multiport", "[sshd] # local SSH policy", "banaction = nftables"),
            "nftables",
        ),
        (("[DEFAULT] ; defaults", "banaction = nftables ; comment"), "nftables"),
        (("[recidive]", "banaction = nftables"), None),
        ((), None),
    ],
)
def test_inherited_ban_action(lines: tuple[str, ...], action: str | None) -> None:
    state = HostState(jail_config=lines)

    assert state.inherited_banaction("sshd") == action


def test_fresh_host_writes_the_filter_and_jail_before_the_packages() -> None:
    result = run({**probe(stock="missing", loaded_marker=None), **fakehost.UBUNTU})

    assert result.mutating_changed_ops == [
        "SSH guard | Ensure /etc/ssh/sshd_config.d",
        *DIRS,
        INSTALL_SYSTEMD,
        WRITE_FILTER,
        WRITE_JAIL,
        INSTALL,
        RESTART_PACKAGES,
        ENSURE,
        GATE,
        WRITE_DROPIN,
        VALIDATE,
        RELOAD,
    ]
    commands = result.executed_commands
    installs = [c for c in commands if "apt-get" in c and "install" in c]
    assert [c.split()[-1] for c in installs] == ["python3-systemd", "fail2ban"]
    # As the role: with Recommends, no cache refresh.
    assert not any("--no-install-recommends" in c for c in installs)
    assert not any("apt-get update" in c for c in commands)
    # Nothing restarts fail2ban before the package exists; the postinst starts it with our files.
    assert commands.index(RESTART_CMD) > commands.index(installs[-1])
    assert "systemctl start fail2ban.service" in commands
    assert "systemctl enable fail2ban.service" in commands
    assert gate_command(DEFAULT, final=True) in commands
    assert validate_command(DEFAULT) in commands
    assert commands[-1] == RELOAD_CMD
    assert result.upload(FILTER_OVERRIDE).decode() == FILTER_OVERRIDE_CONTENT
    assert result.upload(JAIL_PATH).decode() == render_jail(DEFAULT)
    assert result.upload(DROPIN).decode() == render_dropin(DEFAULT)
    assert result.uploaded_paths.index(FILTER_OVERRIDE) < result.uploaded_paths.index(JAIL_PATH)
    assert any("chmod 644" in c and FILTER_OVERRIDE in c for c in commands)
    assert any("chown root:root" in c and DROPIN in c for c in commands)


def exposed_host() -> dict[str, Any]:
    """A host exposed to the CVE: the vulnerable filter loaded, Debian's nftables default, no nft."""

    responses = converged(DEFAULT, override="missing", loaded_marker=18)
    del responses[f"sha1sum {FILTER_OVERRIDE} "], responses[f"cat {FILTER_OVERRIDE}"]
    del responses[f"test -e {FILTER_OVERRIDE} ||"], responses[f"sha256sum {FILTER_OVERRIDE} "]
    responses.update(fakehost.deb_installed("fail2ban", "python3-systemd"))
    return responses


def test_nftables_host_loads_the_fix_before_installing_nftables() -> None:
    result = run(exposed_host(), NFT_HOST)

    assert result.mutating_changed_ops == [
        WRITE_FILTER,
        WRITE_JAIL,
        RESTART,
        GATE_EARLY,
        INSTALL_NFT,
        RESTART_PACKAGES,
        GATE,
        WRITE_DROPIN,
        VALIDATE,
        RELOAD,
    ]
    commands = result.executed_commands
    install = next(c for c in commands if "apt-get" in c and "install" in c)
    assert install.endswith("install --no-install-recommends nftables")
    # The fixed filter is loaded and checked before nft exists.
    assert commands.index(RESTART_CMD) < commands.index(gate_command(NFT_HOST, final=False)) < commands.index(install)
    assert commands.count(RESTART_CMD) == 2
    assert commands.index(gate_command(NFT_HOST, final=True)) > commands.index(install)
    assert commands.index(validate_command(NFT_HOST)) < commands.index(RELOAD_CMD)
    assert result.upload(JAIL_PATH).decode() == render_jail(NFT_HOST)
    assert result.upload(DROPIN).decode() == HEADER + "PerSourceMaxStartups 5\nPerSourceNetBlockSize 32:64\n"
    assert not any("nftables.service" in c and ("enable" in c or "start" in c) for c in commands if "is-" not in c)


def test_the_systemd_module_comes_before_the_first_restart() -> None:
    # fail2ban installed without Recommends: a systemd jail needs python3-systemd
    # before fail2ban is restarted onto it, or the early gate stops fail2ban.
    responses = exposed_host()
    responses.update(fakehost.deb_installed("fail2ban"))

    result = run(responses, NFT_HOST)

    ops = result.mutating_changed_ops
    assert ops[:4] == [INSTALL_SYSTEMD, WRITE_FILTER, WRITE_JAIL, RESTART]
    assert ops.index(GATE_EARLY) < ops.index(INSTALL_NFT)
    assert RESTART_PACKAGES in ops


def test_iptables_host_changes_only_the_filter_and_jail() -> None:
    responses = converged(
        DEFAULT,
        sshd_session=False,
        override="missing",
        openssh=OPENSSH_92,
        loaded_marker=18,
        loaded_actions="iptables-multiport",
    )
    for key in ("sha1sum", "sha256sum"):
        del responses[f"{key} {FILTER_OVERRIDE} "]
    del responses[f"cat {FILTER_OVERRIDE}"], responses[f"test -e {FILTER_OVERRIDE} ||"]

    result = run(responses, IPTABLES_HOST)

    assert result.mutating_changed_ops == [WRITE_FILTER, WRITE_JAIL, RESTART, GATE_EARLY, GATE]
    commands = result.executed_commands
    assert not any("apt-get" in c for c in commands)
    assert not any("sshd" in c and "fail2ban" not in c for c in commands)
    gate = gate_command(IPTABLES_HOST, final=True)
    assert gate in commands
    assert "iptables-multiport" in gate
    assert "command -v ip6tables" in gate


def test_fixed_package_filter_removes_our_override_and_restarts() -> None:
    responses = {**converged(stock="fixed"), **probe(stock="fixed", override="ours")}

    result = run(responses)

    assert result.mutating_changed_ops == [REMOVE_FILTER, RESTART, GATE_EARLY, GATE]
    assert f"rm -f -- {FILTER_OVERRIDE}" in result.executed_commands
    assert FILTER_OVERRIDE not in result.uploaded_paths


def test_override_drift_rewrites_it_and_restarts_fail2ban_only() -> None:
    responses = converged()
    responses.update(fakehost.file(FILTER_OVERRIDE, OVERRIDE_HEADER + "[Definition]\n"))

    result = run(responses)

    assert result.mutating_changed_ops == [WRITE_FILTER, RESTART, GATE_EARLY, GATE]
    assert result.upload(FILTER_OVERRIDE).decode() == FILTER_OVERRIDE_CONTENT
    assert not any("sshd -t" in c or "reload" in c for c in result.executed_commands)


def test_jail_drift_restarts_and_checks_fail2ban_only() -> None:
    responses = converged()
    responses.update(fakehost.file(JAIL_PATH, HEADER + "[sshd]\nenabled = false\n"))

    result = run(responses)

    assert result.mutating_changed_ops == [WRITE_JAIL, RESTART, GATE_EARLY, GATE]
    assert RESTART_CMD in result.executed_commands
    assert not any("sshd -t" in c or "reload" in c for c in result.executed_commands)


def test_a_stopped_fail2ban_is_started_and_checked() -> None:
    responses = converged()
    responses.update(fakehost.service("fail2ban.service", running=False, enabled=False))

    result = run(responses)

    assert result.mutating_changed_ops == [ENSURE, GATE]
    assert "systemctl start fail2ban.service" in result.executed_commands
    assert result.executed_commands[-1] == gate_command(DEFAULT, final=True)


@pytest.mark.parametrize(
    ("cfg", "loaded"),
    [(DEFAULT, {"loaded_marker": 18}), (NFT_HOST, {"loaded_actions": "iptables-multiport"})],
    ids=["vulnerable filter loaded", "other ban action loaded"],
)
def test_converged_files_with_a_stale_running_jail_restart_and_check(cfg: SshGuardConfig, loaded: Any) -> None:
    # A run interrupted between writing the files and restarting fail2ban.
    result = run({**converged(cfg), **probe(override="ours", **loaded)}, cfg)

    assert result.mutating_changed_ops == [RESTART, GATE_EARLY, GATE]
    assert result.uploaded_paths == []


def test_a_stopped_fail2ban_reads_as_not_stale() -> None:
    state = HostState.parse("loaded_actions=\nstock_marker=2")

    assert state.loaded_marker is None
    assert not state.stale(NFT_HOST)
    assert HostState.parse("loaded_marker=0\nloaded_actions=nftables, sendmail").loaded_actions == (
        "nftables",
        "sendmail",
    )


@pytest.mark.parametrize("override", ["foreign", "symlink"])
def test_an_unmanaged_override_is_refused_before_any_change(override: str) -> None:
    responses = {**converged(), **probe(override=override)}

    result = run(responses, ok=False)

    assert FILTER_OVERRIDE in str(result.error)
    assert result.executed_commands == []


def test_filter_fix_off_never_touches_the_override_but_keeps_the_gate() -> None:
    cfg = SshGuardConfig(fail2ban_sshd_filter_fix="off")
    responses = {**converged(cfg), **probe(override="foreign")}
    responses.update(fakehost.file(JAIL_PATH, "# old\n"))

    result = run(responses, cfg)

    assert result.mutating_changed_ops == [WRITE_JAIL, RESTART, GATE_EARLY, GATE]
    assert FILTER_OVERRIDE not in result.uploaded_paths
    assert not any(FILTER_OVERRIDE in c for c in result.executed_commands)
    assert gate_command(cfg, final=True) in result.executed_commands


def test_a_session_daemon_the_filter_ignores_is_refused() -> None:
    result = run({**converged(), **probe(stock="no session")}, ok=False)

    assert "sshd-session" in str(result.error)
    assert result.executed_commands == []


def test_an_enabled_nftables_service_is_refused() -> None:
    result = run({**converged(NFT_HOST), **probe(nftables_service="enabled")}, NFT_HOST, ok=False)

    assert "nftables.service" in str(result.error)
    assert result.executed_commands == []


def test_an_unresolvable_port_name_is_refused() -> None:
    cfg = SshGuardConfig(fail2ban_port="2222,ssh")
    result = run({**converged(cfg), **probe(ports={"ssh": ""})}, cfg, ok=False)

    assert "'ssh' does not resolve" in str(result.error)


def test_numeric_ports_need_no_lookup() -> None:
    cfg = SshGuardConfig(fail2ban_port="2222")

    assert "getent" not in probe_command(cfg)
    assert "getent services ssh/tcp" in probe_command(DEFAULT)
    run({**converged(cfg), **probe(ports={})}, cfg)


@pytest.mark.parametrize(
    ("openssh", "cfg", "message"),
    [
        ("OpenSSH_8.4p1 Debian-5", DEFAULT, "PerSourceMaxStartups needs OpenSSH 8.5"),
        ("OpenSSH_9.6p1 Ubuntu-3ubuntu13.20", SshGuardConfig(per_source_penalties="authfail:5"), "9.8"),
        ("OpenSSH_9.6p1 Ubuntu", SshGuardConfig(per_source_penalty_exempt_list="192.0.2.0/24"), "9.8"),
        ("garbage", DEFAULT, "cannot read the OpenSSH version"),
    ],
)
def test_directives_the_host_cannot_parse_are_refused(openssh: str, cfg: SshGuardConfig, message: str) -> None:
    result = run({**converged(cfg), **probe(openssh=openssh)}, cfg, ok=False)

    assert message in str(result.error)
    assert result.executed_commands == []


def test_ungated_directives_need_no_version() -> None:
    cfg = SshGuardConfig(per_source_max_startups="", max_auth_tries="3", fail2ban_enabled=False)
    responses = {**probe(openssh=""), **fakehost.UBUNTU, **fakehost.directory("/etc/ssh/sshd_config.d")}

    result = run(responses, cfg)

    assert result.mutating_changed_ops == [WRITE_DROPIN, VALIDATE, RELOAD]


def test_new_directives_on_a_recent_openssh_are_checked_with_sshd_capital_t() -> None:
    cfg = SshGuardConfig(
        per_source_net_block_size="32:64",
        max_startups="10:30:100",
        login_grace_time="1m30s",
        max_auth_tries="4",
        per_source_penalties="authfail:5m max:600 overflow:permissive",
        per_source_penalty_exempt_list="192.0.2.0/24",
    )
    responses = converged(cfg)
    responses.update(fakehost.file(DROPIN, HEADER + "PerSourceMaxStartups 5\n"))

    result = run(responses, cfg)

    assert result.mutating_changed_ops == [WRITE_DROPIN, VALIDATE, RELOAD]
    command = validate_command(cfg)
    assert command in result.executed_commands
    for line in (
        "'persourcemaxstartups 5'",
        "'maxauthtries 4'",
        "'logingracetime 90'",
        "'maxstartups 10:30:100'",
        "'persourcenetblocksize 32:64'",
        "'persourcepenaltyexemptlist 192.0.2.0/24'",
    ):
        assert line in command
    assert "for want in authfail:300 max:600 overflow:permissive" in command


def test_dropin_drift_validates_and_reloads_only() -> None:
    responses = converged()
    responses.update(fakehost.file(DROPIN, HEADER + "PerSourceMaxStartups 50\n"))

    result = run(responses)

    assert result.mutating_changed_ops == [WRITE_DROPIN, VALIDATE, RELOAD]
    commands = result.executed_commands
    assert commands.index(validate_command(DEFAULT)) < commands.index(RELOAD_CMD)
    assert RESTART_CMD not in commands


def test_dropin_mode_drift_counts_as_a_change() -> None:
    responses = converged()
    responses.update(fakehost.stat(DROPIN, mode="-rw-rw-rw-"))

    result = run(responses)

    assert result.mutating_changed_ops == [WRITE_DROPIN, VALIDATE, RELOAD]
    assert "chmod 644 /etc/ssh/sshd_config.d/99-ssh-guard.conf" in result.executed_commands


def test_invalid_or_ineffective_sshd_config_removes_the_dropin_and_fails_before_the_reload() -> None:
    responses = {"sshd -t -f /etc/ssh/sshd_config": {"success": False, "stderr": ["bad option"]}}
    responses.update(converged())
    responses.update(fakehost.file(DROPIN, "# apt default\n"))

    result = run(responses, ok=False)

    assert result.op(VALIDATE).succeeded is False
    # The reload never ran: the op after the failed validation is not executed.
    assert RELOAD_CMD not in result.executed_commands
    assert RESTART_CMD not in result.executed_commands
    command = validate_command(DEFAULT)
    assert command in result.executed_commands
    assert command == (
        "sshd -t -f /etc/ssh/sshd_config || { rm -f -- /etc/ssh/sshd_config.d/99-ssh-guard.conf; "
        "echo 'Invalid sshd config; removed /etc/ssh/sshd_config.d/99-ssh-guard.conf.' >&2; exit 1; }; "
        "eff=$(sshd -T -f /etc/ssh/sshd_config) || { rm -f -- /etc/ssh/sshd_config.d/99-ssh-guard.conf; "
        "echo 'sshd -T failed; removed /etc/ssh/sshd_config.d/99-ssh-guard.conf.' >&2; exit 1; }; "
        'for want in \'persourcemaxstartups 5\'; do printf "%s\\n" "$eff" | grep -qixF -- "$want" || '
        '{ rm -f -- /etc/ssh/sshd_config.d/99-ssh-guard.conf; echo "sshd -T does not show: $want; '
        'removed /etc/ssh/sshd_config.d/99-ssh-guard.conf." >&2; exit 1; }; done'
    )


def test_a_jail_change_is_applied_before_an_invalid_dropin_fails() -> None:
    # The role's handlers never run once the drop-in fails, leaving a written
    # but unloaded jail that later runs do not restart; here the restart comes first.
    responses = {"sshd -t -f /etc/ssh/sshd_config": {"success": False}}
    responses.update(converged())
    responses.update(fakehost.file(JAIL_PATH, "# old\n"))
    responses.update(fakehost.file(DROPIN, "# old\n"))

    result = run(responses, ok=False)

    commands = result.executed_commands
    assert RESTART_CMD in commands
    assert commands.index(RESTART_CMD) < commands.index(validate_command(DEFAULT))
    assert RELOAD_CMD not in commands


def test_a_failing_gate_stops_the_deploy_before_the_packages() -> None:
    responses = {gate_command(NFT_HOST, final=False): {"success": False, "stderr": ["ssh_guard gate: ..."]}}
    responses.update(exposed_host())

    result = run(responses, NFT_HOST, ok=False)

    assert result.op(GATE_EARLY).succeeded is False
    assert not any("apt-get" in c for c in result.executed_commands)
    assert not any("sshd -t" in c for c in result.executed_commands)


def test_the_gate_stops_fail2ban_on_every_finding() -> None:
    early, final = gate_command(NFT_HOST, final=False), gate_command(NFT_HOST, final=True)

    assert final.startswith(early)
    assert "systemctl stop fail2ban" in early
    assert "*'on \\S+'*) stop" in early
    assert 'case " $(echo $actions) " in *" nftables "*)' in early
    assert "-eq 1 ] || stop" in early
    assert "command -v nft" in final
    assert "command -v nft" not in early
    assert "prefregex" in final
    assert "nftables.service" in final
    # Without a configured ban action only "firewall actions" is required.
    assert "is not loaded" not in gate_command(DEFAULT, final=True)
    assert "nftables*|iptables*) ;;" in gate_command(DEFAULT, final=True)
    assert 'case " $(echo $actions) " in *" nftables "*)' in gate_command(
        SshGuardConfig(fail2ban_banaction="nftables[type=allports]"), final=False
    )


def test_disabled_fail2ban_touches_only_sshd() -> None:
    cfg = SshGuardConfig(fail2ban_enabled=False, fail2ban_maxretry=0)

    result = run({**probe(), **fakehost.UBUNTU}, cfg)

    assert result.mutating_changed_ops == ["SSH guard | Ensure /etc/ssh/sshd_config.d", WRITE_DROPIN, VALIDATE, RELOAD]
    assert not any("fail2ban" in c for c in result.executed_commands)


def test_disabled_dropin_touches_only_fail2ban() -> None:
    cfg = SshGuardConfig(sshd_dropin_enabled=False, per_source_max_startups=None)

    result = run({**probe(openssh="", stock="missing", loaded_marker=None), **fakehost.UBUNTU}, cfg)

    assert result.mutating_changed_ops == [
        *DIRS,
        INSTALL_SYSTEMD,
        WRITE_FILTER,
        WRITE_JAIL,
        INSTALL,
        RESTART_PACKAGES,
        ENSURE,
        GATE,
    ]
    assert not any("sshd" in c and "fail2ban" not in c for c in result.executed_commands)


def test_both_disabled_does_nothing() -> None:
    cfg = SshGuardConfig(fail2ban_enabled=False, sshd_dropin_enabled=False)

    result = run({**fakehost.UBUNTU}, cfg)

    assert result.executed_commands == []
    assert not any("ssh_guard probe" in c for c in result.fact_commands)


def test_custom_dropin_path_and_service_names() -> None:
    cfg = SshGuardConfig(
        sshd_dropin_path="/etc/ssh/guard.d/10-guard.conf", sshd_service_name="sshd", fail2ban_service_name="f2b"
    )

    result = run({**probe(stock="missing", loaded_marker=None), **fakehost.UBUNTU}, cfg)

    commands = result.executed_commands
    assert "mkdir -p /etc/ssh/guard.d" in commands
    assert "systemctl restart f2b" in commands
    assert "systemctl stop f2b" in gate_command(cfg, final=True)
    assert "if systemctl is-active --quiet sshd; then systemctl reload sshd; else systemctl start sshd; fi" in commands
    assert result.upload("/etc/ssh/guard.d/10-guard.conf").decode() == render_dropin(cfg)


def test_the_probe_is_read_only() -> None:
    command = probe_command(NFT_HOST)

    words = set(re.findall(r"[A-Za-z_-]+", command))
    writes = {"rm", "mv", "cp", "tee", "mkdir", "touch", "chmod", "chown", "apt-get", "dpkg"}
    assert not words & (writes | {"start", "stop", "restart", "reload", "enable", "disable", "mask", "set"})
    # fail2ban-client only reads.
    assert re.findall(r"fail2ban-client (\w+)", command) == ["get", "get"]
    # The only redirections discard output or merge stderr into stdout.
    assert ">" not in re.sub(r"2?>(/dev/null|&1)", "", command)


def test_probe_parsing() -> None:
    lines = probe(openssh=OPENSSH_92, sshd_session=False)
    state = HostState.parse("\n".join(lines[": ssh_guard probe"]))

    assert state.openssh == (9, 2)
    assert not state.sshd_session
    assert state.stock_marker == 2
    assert state.ports == {"ssh": "22"}
    assert HostState.parse("") == HostState()


# --- refusals and validation -----------------------------------------------------


def test_refuses_macos() -> None:
    result = run({"uname -s": ["Darwin"]}, ok=False)

    assert "Linux hosts only" in str(result.error)
    assert result.executed_commands == []


def test_refuses_a_host_without_systemd() -> None:
    result = run({**LINUX, "cat /proc/1/comm": ["init"]}, ok=False)

    assert "systemd" in str(result.error)


def test_refuses_a_host_without_apt() -> None:
    result = run({**LINUX, "cat /proc/1/comm": ["systemd"]}, ok=False)

    assert "apt" in str(result.error)
    assert result.executed_commands == []


@pytest.mark.parametrize("maxretry", [0, -1])
def test_maxretry_must_be_positive_when_fail2ban_is_enabled(maxretry: int) -> None:
    with pytest.raises(ValidationError, match="maxretry"):
        SshGuardConfig(fail2ban_maxretry=maxretry)
    SshGuardConfig(fail2ban_enabled=False, fail2ban_maxretry=maxretry)


@pytest.mark.parametrize("maxretry", [True, "3", "03", " 3", 3.0])
def test_maxretry_is_not_coerced(maxretry: object) -> None:
    # The role renders these as given ("True", "03", "3.0"); a coerced int
    # would write a different jail file, so they are refused instead.
    with pytest.raises(ValidationError, match="fail2ban_maxretry"):
        SshGuardConfig(fail2ban_maxretry=maxretry)
    assert "maxretry = 3\n" in render_jail(SshGuardConfig(fail2ban_maxretry=3))


def test_per_source_max_startups_none_is_refused_when_the_dropin_is_enabled() -> None:
    with pytest.raises(ValidationError, match="PerSourceMaxStartups"):
        SshGuardConfig(per_source_max_startups=None)
    SshGuardConfig(sshd_dropin_enabled=False, per_source_max_startups=None)


@pytest.mark.parametrize(
    "field",
    [
        "fail2ban_backend",
        "fail2ban_filter",
        "fail2ban_port",
        "fail2ban_findtime",
        "fail2ban_bantime",
        "fail2ban_ignoreip",
        "fail2ban_banaction",
        "fail2ban_journalmatch",
        "per_source_max_startups",
        "max_auth_tries",
        "login_grace_time",
        "max_startups",
        "per_source_net_block_size",
        "per_source_penalties",
        "per_source_penalty_exempt_list",
    ],
)
@pytest.mark.parametrize("bad", ["5\nPermitRootLogin yes", "5\r", "5\x00", "a\tb", "x\x7f"])
def test_rendered_values_refuse_control_characters(field: str, bad: str) -> None:
    with pytest.raises(ValidationError):
        SshGuardConfig.model_validate({field: bad})


@pytest.mark.parametrize(
    ("field", "bad"),
    [
        ("fail2ban_jail_name", "sshd]\n[recidive"),
        ("fail2ban_jail_name", "a b"),
        ("fail2ban_jail_name", ""),
        ("fail2ban_service_name", "fail2ban; reboot"),
        ("sshd_service_name", "ssh service"),
        ("fail2ban_package", "fail2ban=1.0"),
        ("sshd_dropin_path", "relative.conf"),
        ("sshd_dropin_path", "/guard.conf"),
        ("sshd_dropin_path", "/etc/ssh/x y.conf"),
        ("fail2ban_maxretry", "five"),
        ("unknown_option", "x"),
        ("fail2ban_sshd_filter_fix", "on"),
        ("fail2ban_banaction", "sendmail-whois"),
        ("fail2ban_banaction", "%(action_mwl)s"),
        ("fail2ban_banaction", "nftables; reboot"),
        ("fail2ban_banaction", "iptables-ipset-proto6"),
        ("fail2ban_journalmatch", "_SYSTEMD_UNIT=ssh.service _COMM=sshd"),
        ("fail2ban_journalmatch", "lower=case"),
        ("fail2ban_ban_only", "yes"),
        ("fail2ban_ban_only", 1),
        ("fail2ban_no_recommends", "true"),
        ("max_startups", "10"),
        ("max_startups", "10:30"),
        ("per_source_net_block_size", "24"),
        ("per_source_net_block_size", "33:64"),
        ("per_source_net_block_size", "32:129"),
        ("per_source_penalties", "authfail"),
        ("per_source_penalties", "authfail:5x"),
        ("per_source_penalties", "authfail:5 authfail:6"),
        ("per_source_penalties", "unknown:5"),
        ("per_source_penalties", "overflow:drop"),
        ("per_source_penalties", "no max:5"),
        ("per_source_penalty_exempt_list", "host.example"),
        ("per_source_penalty_exempt_list", "192.0.2.0/24 2001:db8::/32"),
    ],
)
def test_rejects_invalid_values(field: str, bad: object) -> None:
    with pytest.raises(ValidationError):
        SshGuardConfig.model_validate({field: bad})


@pytest.mark.parametrize(
    "banaction",
    ["nftables", "nftables-multiport", "nftables-allports", "nftables[type=allports]", "iptables-multiport", ""],
)
def test_firewall_ban_actions_are_accepted(banaction: str) -> None:
    assert SshGuardConfig(fail2ban_banaction=banaction).fail2ban_banaction == banaction


def test_ban_action_name_drops_parameters() -> None:
    assert SshGuardConfig(fail2ban_banaction="nftables[type=allports]").banaction_name == "nftables"


@pytest.mark.parametrize(
    ("value", "seconds"),
    [("90", 90), ("90s", 90), ("2m", 120), ("1h30m", 5400), ("1W", 604800), ("", None), ("1.5m", None), ("m", None)],
)
def test_convtime(value: str, seconds: int | None) -> None:
    assert convtime(value) == seconds


def test_penalty_tokens_are_normalised_like_sshd() -> None:
    assert penalty_tokens("authfail:5m max:600 max-sources4:65536 overflow6:deny-all") == [
        "authfail:300",
        "max:600",
        "max-sources4:65536",
        "overflow6:deny-all",
    ]
    assert penalty_tokens("no") == ["no"]


def test_effective_lines_skip_values_sshd_prints_differently() -> None:
    cfg = SshGuardConfig(per_source_max_startups="10:30:60", max_auth_tries="three", login_grace_time="1.5m")

    assert effective_lines(cfg) == []
    assert effective_lines(SshGuardConfig(per_source_max_startups="None", per_source_penalties="no")) == [
        "persourcemaxstartups none",
        "persourcepenalties no",
    ]


def test_config_is_frozen() -> None:
    with pytest.raises(ValidationError):
        DEFAULT.fail2ban_maxretry = 1  # type: ignore[misc]
