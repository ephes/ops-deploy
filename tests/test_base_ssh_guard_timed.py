"""``deploy_ssh_guard`` with ``timed_revert_seconds`` (fake connector), and its parity with the plain deploy.

The host program itself is tested in ``test_base_ssh_guard_tx.py`` (stubs) and
``test_base_ssh_guard_docker.py`` (real systemd).
"""

from __future__ import annotations

import base64
import json
import re
from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.base import SshGuardConfig, deploy_ssh_guard
from ops_deploy.base.ssh_guard import (
    FILTER_OVERRIDE,
    JAIL_PATH,
    TX_PROGRAM,
    TX_PROGRAM_PATH,
    HostState,
    gate_command,
    reload_command,
    render_dropin,
    render_jail,
    transaction_bundle,
    validate_command,
)
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests import fakehost
from tests.test_base_ssh_guard import (
    DEFAULT,
    IPTABLES_HOST,
    NFT_HOST,
    converged,
    exposed_host,
    probe,
)

TIMED = DEFAULT.model_copy(update={"timed_revert_seconds": 900})
PLAN = "/usr/bin/python3 -I - plan --bundle-b64 "
APPLY_PREFIX = "SSH guard | Apply under a 900 s timed revert: "


def run_timed(
    responses: dict[str, Any], cfg: SshGuardConfig = TIMED, *, plan: dict[str, Any] | None = None, ok: bool = True
) -> FakeRun:
    answer = plan if plan is not None else {"pending": False, "steps": []}
    result = run_deploy_fake(deploy_ssh_guard, cfg, responses={PLAN: [json.dumps(answer)], **responses})
    assert result.succeeded is ok, result.error
    return result


def plan_bundle(result: FakeRun) -> dict[str, Any]:
    """The bundle the deploy sent to the read-only plan (and would send to ``run``)."""

    commands = [command for command in result.fact_commands if PLAN in command]
    assert len(commands) == 1
    encoded = commands[0].split(PLAN, 1)[1].split()[0]
    bundle: dict[str, Any] = json.loads(base64.b64decode(encoded))
    return bundle


def with_tx(responses: dict[str, Any], line: str) -> dict[str, Any]:
    """A probe answer with the timed-revert state line ``line``."""

    answer = dict(responses)
    answer[": ssh_guard probe"] = [*responses[": ssh_guard probe"], f"tx_state={line}"]
    return answer


# --- configuration ---------------------------------------------------------------


@pytest.mark.parametrize("seconds", [0, 60, 900, 3600])
def test_timed_revert_seconds_accepts_off_or_a_window(seconds: int) -> None:
    assert SshGuardConfig(timed_revert_seconds=seconds).timed_revert_seconds == seconds


@pytest.mark.parametrize("seconds", [1, 59, 3601, -1, True, "900", 900.0])
def test_timed_revert_seconds_refuses_other_values(seconds: object) -> None:
    with pytest.raises(ValidationError):
        SshGuardConfig(timed_revert_seconds=seconds)


def test_off_by_default() -> None:
    assert SshGuardConfig().timed_revert_seconds == 0


# --- the plain deploy is unchanged --------------------------------------------------


@pytest.mark.parametrize("cfg", [DEFAULT, NFT_HOST, IPTABLES_HOST], ids=["defaults", "nftables", "iptables"])
def test_without_a_transaction_the_plain_deploy_never_touches_the_program(cfg: SshGuardConfig) -> None:
    result = run_deploy_fake(deploy_ssh_guard, cfg, responses=exposed_host())

    assert not any(PLAN in command for command in result.fact_commands)
    assert TX_PROGRAM_PATH not in result.all_text()
    assert not any("Apply under" in op.name for op in result.ops)


@pytest.mark.parametrize("status", ["staged", "applying", "armed", "reverting"])
@pytest.mark.parametrize("cfg", [DEFAULT, TIMED], ids=["plain", "timed"])
def test_an_open_transaction_refuses_every_deploy(cfg: SshGuardConfig, status: str) -> None:
    responses = with_tx(converged(), f"{status} 3 0123456789abcdef0123456789abcdef")

    result = run_deploy_fake(deploy_ssh_guard, cfg, responses=responses)

    assert not result.succeeded
    assert f"generation 3 is {status}" in str(result.error)
    assert "confirm --generation 3" in str(result.error)
    assert result.executed_commands == []
    assert result.uploaded_paths == []


@pytest.mark.parametrize("line", ["armed", "armed x y", "unknown 1 abc", "armed -1 abc", "armed 1 a b"])
def test_an_unreadable_transaction_state_refuses(line: str) -> None:
    result = run_deploy_fake(deploy_ssh_guard, DEFAULT, responses=with_tx(converged(), line))

    assert not result.succeeded
    assert "unreadable" in str(result.error)


@pytest.mark.parametrize("status", ["unchanged", "aborted", "confirmed", "reverted", "revert-failed", "superseded"])
def test_a_finished_transaction_lets_the_plain_deploy_run(status: str) -> None:
    result = run_deploy_fake(deploy_ssh_guard, DEFAULT, responses=with_tx(converged(), f"{status} 2 ab"))

    assert result.succeeded, result.error
    assert result.changed_ops == []


# --- the timed deploy -------------------------------------------------------------------


def test_a_converged_host_gets_no_operation() -> None:
    result = run_timed(converged(TIMED))

    assert result.ops == []
    assert result.executed_commands == []
    assert result.uploaded_paths == []
    # The plan ran read-only, the program on stdin.
    assert [text for _, text in result.stdin] == [TX_PROGRAM]


def test_a_failed_plan_refuses() -> None:
    result = run_deploy_fake(
        deploy_ssh_guard, TIMED, responses={PLAN: ["", "ops-deploy-probe-failed"], **exposed_host()}
    )

    assert not result.succeeded
    assert "transaction plan failed" in str(result.error)
    assert result.executed_commands == []


def test_pending_changes_install_the_program_and_apply_in_one_operation() -> None:
    steps = ["Write /etc/fail2ban/filter.d/sshd.local (CVE-2026-109786)", "Write /etc/fail2ban/jail.d/ssh-guard.local"]
    result = run_timed(exposed_host(), plan={"pending": True, "steps": steps})

    assert result.mutating_changed_ops == [
        "SSH guard | Ensure /usr/local/libexec/ops-deploy",
        f"SSH guard | Install {TX_PROGRAM_PATH}",
        APPLY_PREFIX + "; ".join(steps),
    ]
    assert result.upload(TX_PROGRAM_PATH).decode() == TX_PROGRAM
    [command] = [c for c in result.executed_commands if "ssh-guard-tx run" in c]
    [planned] = [c for c in result.fact_commands if PLAN in c]
    encoded = planned.split(PLAN, 1)[1].split()[0]
    # The same bundle as planned; the caller's SSH connection expands on the host.
    assert f"{TX_PROGRAM_PATH} run --bundle-b64 {encoded} " in command
    assert '--caller "${SSH_CONNECTION:-}"' in command
    # Nothing outside the program writes an sshd or fail2ban file.
    assert set(result.uploaded_paths) == {TX_PROGRAM_PATH}
    assert not any(re.search(r"systemctl (restart|reload|start|stop)", c) for c in result.executed_commands)


def test_the_bundle_binds_the_generation_and_the_window() -> None:
    responses = with_tx(exposed_host(), "confirmed 7 ab")
    result = run_timed(responses, TIMED.model_copy(update={"timed_revert_seconds": 600}))

    bundle = plan_bundle(result)
    assert bundle["expect_generation"] == 7
    assert bundle["revert_after"] == 600
    assert bundle["schema"] == 1


def test_the_bundle_manages_exactly_the_three_files() -> None:
    bundle = plan_bundle(run_timed(exposed_host(), NFT_HOST.model_copy(update={"timed_revert_seconds": 900})))

    assert [entry["path"] for entry in bundle["files"]] == [
        JAIL_PATH,
        FILTER_OVERRIDE,
        "/etc/ssh/sshd_config.d/99-ssh-guard.conf",
    ]
    assert all((entry["uid"], entry["gid"], entry["mode"]) == (0, 0, 0o644) for entry in bundle["files"])
    assert bundle["services"] == [
        {"role": "fail2ban", "unit": "fail2ban", "files": sorted([JAIL_PATH, FILTER_OVERRIDE])},
        {
            "role": "ssh",
            "unit": "ssh",
            "files": ["/etc/ssh/sshd_config.d/99-ssh-guard.conf"],
            "check": "sshd -t -f /etc/ssh/sshd_config",
        },
    ]


def test_drop_in_only_with_per_source_limits() -> None:
    """fail2ban off, per-source limits in the drop-in, OpenSSH 9.6."""

    cfg = SshGuardConfig(
        fail2ban_enabled=False,
        per_source_net_block_size="32:64",
        login_grace_time="60",
        timed_revert_seconds=900,
    )
    responses = {**probe(openssh="OpenSSH_9.6p1 Ubuntu-3ubuntu13.14, OpenSSL 3.0.13 30 Jan 2024"), **fakehost.UBUNTU}

    bundle = plan_bundle(run_timed(responses, cfg))

    assert [step["name"] for step in bundle["steps"]] == [
        "Ensure /etc/ssh/sshd_config.d",
        "Write /etc/ssh/sshd_config.d/99-ssh-guard.conf",
        "Validate the sshd configuration",
        "Reload ssh for the new drop-in",
    ]
    assert bundle["steps"][1]["content"] == render_dropin(cfg)
    assert bundle["steps"][2]["command"] == validate_command(cfg)
    assert bundle["steps"][3]["command"] == reload_command("ssh")
    assert [service["role"] for service in bundle["services"]] == ["ssh"]
    assert [entry["path"] for entry in bundle["files"]] == ["/etc/ssh/sshd_config.d/99-ssh-guard.conf"]


# --- parity: the timed steps are the plain deploy's operations ------------------------


def scenarios() -> dict[str, tuple[SshGuardConfig, dict[str, Any]]]:
    stale = converged(NFT_HOST, loaded_marker=18)
    fixed = converged(stock="fixed", override="ours")
    fresh = {**probe(stock="missing", loaded_marker=None), **fakehost.UBUNTU}
    no_dropin = SshGuardConfig(sshd_dropin_enabled=False)
    no_fail2ban = SshGuardConfig(fail2ban_enabled=False)
    return {
        "exposed defaults": (DEFAULT, exposed_host()),
        "exposed nftables host": (NFT_HOST, exposed_host()),
        "iptables host": (IPTABLES_HOST, converged(IPTABLES_HOST, sshd_session=False, loaded_marker=2)),
        "stale running jail": (NFT_HOST, stale),
        "fixed package filter": (DEFAULT, fixed),
        "fresh host": (DEFAULT, fresh),
        "converged": (NFT_HOST, converged(NFT_HOST)),
        "no drop-in": (no_dropin, exposed_host()),
        "no fail2ban": (no_fail2ban, exposed_host()),
        "filter fix off": (DEFAULT.model_copy(update={"fail2ban_sshd_filter_fix": "off"}), exposed_host()),
        "classic backend": (DEFAULT.model_copy(update={"fail2ban_backend": "auto"}), exposed_host()),
    }


SCENARIOS = scenarios()


@pytest.mark.parametrize("name", SCENARIOS)
def test_timed_steps_are_the_plain_operations_in_order(name: str) -> None:
    cfg, responses = SCENARIOS[name]
    plain = run_deploy_fake(deploy_ssh_guard, cfg, responses=responses)
    state = HostState.parse("\n".join(responses[": ssh_guard probe"]))
    installed = cfg.fail2ban_enabled and "fail2ban" in str(responses.get("dpkg -l", ""))

    bundle = transaction_bundle(cfg.model_copy(update={"timed_revert_seconds": 900}), state, installed=installed)

    assert ["SSH guard | " + step["name"] for step in bundle["steps"]] == [op.name for op in plain.ops]
    kinds = {
        "dir": "files.directory",
        "file": "files.put",
        "absent": "server.shell",
        "package": "apt.packages",
        "service": "systemd.service",
        "shell": "server.shell",
    }
    assert all(step["kind"] in kinds for step in bundle["steps"])
    for step in bundle["steps"]:
        if step["kind"] == "file":
            expected = {
                JAIL_PATH: render_jail(cfg),
                cfg.sshd_dropin_path: render_dropin(cfg),
            }.get(step["path"])
            if expected is not None:
                assert step["content"] == expected
        if step["name"] == "Check the jail":
            assert step["command"] == gate_command(cfg, final=True)
        if step["name"] == "Check the jail before the package installs":
            assert step["command"] == gate_command(cfg, final=False)


@pytest.mark.parametrize("name", ["exposed defaults", "exposed nftables host", "fresh host", "stale running jail"])
def test_timed_conditions_mirror_the_plain_ones(name: str) -> None:
    """Every shell step the plain deploy ran also runs from the bundle when the same steps change."""

    cfg, responses = SCENARIOS[name]
    plain = run_deploy_fake(deploy_ssh_guard, cfg, responses=responses)
    state = HostState.parse("\n".join(responses[": ssh_guard probe"]))
    installed = cfg.fail2ban_enabled and "fail2ban" in str(responses.get("dpkg -l", ""))
    bundle = transaction_bundle(cfg.model_copy(update={"timed_revert_seconds": 900}), state, installed=installed)
    changed_plain = set(plain.changed_ops)

    # Replay the bundle's conditions with the plain run's changes as the change set.
    changed: set[str] = set()
    ran: list[str] = []
    for step in bundle["steps"]:
        name_ = "SSH guard | " + step["name"]
        if step["kind"] == "shell":
            hit = step["always"] or bool(changed.intersection(step["when"]))
        else:
            hit = name_ in changed_plain
        if hit:
            changed.add(step["id"])
            ran.append(name_)
    assert ran == plain.changed_ops
