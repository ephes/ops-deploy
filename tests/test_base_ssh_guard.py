"""``deploy_ssh_guard`` against the fake connector, and its files against the role's templates."""

from pathlib import Path
from typing import Any

import jinja2
import pytest
from pydantic import ValidationError

from ops_deploy.base import SshGuardConfig, deploy_ssh_guard
from ops_deploy.base.ssh_guard import HEADER, JAIL_PATH, render_dropin, render_jail, validate_command
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests import fakehost
from tests.fakehost import LINUX

VENDORED = Path(__file__).parent / "parity" / "ansible"
DROPIN = "/etc/ssh/sshd_config.d/99-ssh-guard.conf"
DEFAULT = SshGuardConfig()

INSTALL = "SSH guard | Install fail2ban"
ENSURE = "SSH guard | Ensure fail2ban"
WRITE_JAIL = f"SSH guard | Write {JAIL_PATH}"
RESTART = "SSH guard | Restart fail2ban for the new jail"
WRITE_DROPIN = f"SSH guard | Write {DROPIN}"
VALIDATE = "SSH guard | Validate the sshd configuration"
RELOAD = "SSH guard | Reload ssh for the new drop-in"
RESTART_CMD = "systemctl restart fail2ban"
RELOAD_CMD = "if systemctl is-active --quiet ssh; then systemctl reload ssh; else systemctl start ssh; fi"


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


def converged(cfg: SshGuardConfig = DEFAULT) -> dict[str, Any]:
    return {
        **fakehost.UBUNTU,
        **fakehost.directory("/etc/ssh/sshd_config.d"),
        **fakehost.directory("/etc/fail2ban/jail.d"),
        **fakehost.deb_installed("fail2ban"),
        **fakehost.service("fail2ban.service"),
        **fakehost.file(JAIL_PATH, render_jail(cfg)),
        **fakehost.file(cfg.sshd_dropin_path, render_dropin(cfg)),
    }


def run(responses: dict[str, Any], cfg: SshGuardConfig = DEFAULT, *, ok: bool = True) -> FakeRun:
    result = run_deploy_fake(deploy_ssh_guard, cfg, responses=responses)
    assert result.succeeded is ok, result.error
    return result


def test_converged_host_changes_nothing() -> None:
    result = run(converged())

    assert result.changed_ops == []
    assert result.executed_commands == []


def test_fresh_host_installs_writes_restarts_validates_and_reloads() -> None:
    result = run({**fakehost.UBUNTU})

    assert result.mutating_changed_ops == [
        "SSH guard | Ensure /etc/ssh/sshd_config.d",
        INSTALL,
        ENSURE,
        WRITE_JAIL,
        RESTART,
        WRITE_DROPIN,
        VALIDATE,
        RELOAD,
    ]
    commands = result.executed_commands
    assert any("apt-get" in c and "install" in c and "fail2ban" in c for c in commands)
    # No cache refresh, as the role's package task.
    assert not any("apt-get update" in c for c in commands)
    assert "systemctl start fail2ban.service" in commands
    assert "systemctl enable fail2ban.service" in commands
    assert RESTART_CMD in commands
    assert validate_command(DEFAULT) in commands
    assert commands[-1] == RELOAD_CMD
    assert result.upload(JAIL_PATH).decode() == render_jail(DEFAULT)
    assert result.upload(DROPIN).decode() == render_dropin(DEFAULT)
    assert any("chmod 644" in c and JAIL_PATH in c for c in commands)
    assert any("chown root:root" in c and DROPIN in c for c in commands)


def test_jail_drift_restarts_fail2ban_only() -> None:
    responses = converged()
    responses.update(fakehost.file(JAIL_PATH, HEADER + "[sshd]\nenabled = false\n"))

    result = run(responses)

    assert result.mutating_changed_ops == [WRITE_JAIL, RESTART]
    assert RESTART_CMD in result.executed_commands
    assert not any("sshd -t" in c or "reload" in c for c in result.executed_commands)


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


def test_invalid_sshd_config_removes_the_dropin_and_fails_before_the_reload() -> None:
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
        "echo 'Invalid sshd config; removed /etc/ssh/sshd_config.d/99-ssh-guard.conf.' >&2; exit 1; }"
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


def test_disabled_fail2ban_touches_only_sshd() -> None:
    cfg = SshGuardConfig(fail2ban_enabled=False, fail2ban_maxretry=0)

    result = run({**fakehost.UBUNTU}, cfg)

    assert result.mutating_changed_ops == ["SSH guard | Ensure /etc/ssh/sshd_config.d", WRITE_DROPIN, VALIDATE, RELOAD]
    assert not any("fail2ban" in c for c in result.executed_commands)


def test_disabled_dropin_touches_only_fail2ban() -> None:
    cfg = SshGuardConfig(sshd_dropin_enabled=False, per_source_max_startups=None)

    result = run({**fakehost.UBUNTU}, cfg)

    assert result.mutating_changed_ops == [INSTALL, ENSURE, WRITE_JAIL, RESTART]
    assert not any("sshd" in c and "fail2ban" not in c for c in result.executed_commands)


def test_both_disabled_does_nothing() -> None:
    cfg = SshGuardConfig(fail2ban_enabled=False, sshd_dropin_enabled=False)

    assert run({**fakehost.UBUNTU}, cfg).executed_commands == []


def test_custom_dropin_path_and_service_names() -> None:
    cfg = SshGuardConfig(
        sshd_dropin_path="/etc/ssh/guard.d/10-guard.conf", sshd_service_name="sshd", fail2ban_service_name="f2b"
    )

    result = run({**fakehost.UBUNTU}, cfg)

    commands = result.executed_commands
    assert "mkdir -p /etc/ssh/guard.d" in commands
    assert "systemctl restart f2b" in commands
    assert "if systemctl is-active --quiet sshd; then systemctl reload sshd; else systemctl start sshd; fi" in commands
    assert result.upload("/etc/ssh/guard.d/10-guard.conf").decode() == render_dropin(cfg)


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
        "per_source_max_startups",
        "max_auth_tries",
        "login_grace_time",
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
    ],
)
def test_rejects_invalid_values(field: str, bad: str) -> None:
    with pytest.raises(ValidationError):
        SshGuardConfig.model_validate({field: bad})


def test_config_is_frozen() -> None:
    with pytest.raises(ValidationError):
        DEFAULT.fail2ban_maxretry = 1  # type: ignore[misc]
