"""``deploy_ssh_guard`` with ``timed_revert_seconds`` (fake connector), and its parity with the plain deploy.

The host program itself is tested in ``test_base_ssh_guard_tx.py`` (stubs) and
``test_base_ssh_guard_docker.py`` (real systemd).
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.base import SshGuardConfig, deploy_ssh_guard
from ops_deploy.base.ssh_guard import (
    CLOUD_INIT_READ_FAILED,
    FILTER_OVERRIDE,
    JAIL_PATH,
    TX_PROGRAM,
    TX_PROGRAM_PATH,
    HostState,
    cloud_init_digest,
    gate_command,
    probe_command,
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


def test_auth_directives_on_top_of_a_confirmed_dropin() -> None:
    """fail2ban off, the per-source drop-in already there: only the drop-in, its check and the reload."""

    before = SshGuardConfig(fail2ban_enabled=False, per_source_net_block_size="32:64", timed_revert_seconds=900)
    cfg = before.model_copy(update={"password_authentication": "no", "permit_root_login": "prohibit-password"})
    responses = {
        **probe(openssh="OpenSSH_9.6p1 Ubuntu-3ubuntu13.20, OpenSSL 3.0.13 30 Jan 2024", sshd_session=False),
        **fakehost.UBUNTU,
        **fakehost.directory("/etc/ssh/sshd_config.d"),
        **fakehost.file("/etc/ssh/sshd_config.d/99-ssh-guard.conf", render_dropin(before)),
    }
    responses = with_tx(responses, "confirmed 1 0123456789abcdef0123456789abcdef")

    bundle = plan_bundle(run_timed(responses, cfg))

    assert bundle["expect_generation"] == 1
    assert [step["name"] for step in bundle["steps"]] == [
        "Ensure /etc/ssh/sshd_config.d",
        "Write /etc/ssh/sshd_config.d/99-ssh-guard.conf",
        "Validate the sshd configuration",
        "Reload ssh for the new drop-in",
    ]
    assert bundle["steps"][1]["content"] == render_dropin(cfg)
    assert render_dropin(cfg).endswith(
        "PerSourceNetBlockSize 32:64\nPasswordAuthentication no\nPermitRootLogin prohibit-password\n"
    )
    assert bundle["steps"][2]["command"] == validate_command(cfg)
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
        "auth directives": (
            no_fail2ban.model_copy(update={"password_authentication": "no", "permit_root_login": "prohibit-password"}),
            exposed_host(),
        ),
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


# --- cloud-init's drop-in (sshd_remove_cloud_init_dropin) ---------------------------

CLOUD_INIT = "/etc/ssh/sshd_config.d/50-cloud-init.conf"
REMOVE_CLOUD_INIT = f"Remove {CLOUD_INIT} (cloud-init's PasswordAuthentication)"
PWAUTH = b"PasswordAuthentication yes\n"
# macmini's form: fail2ban off, no per-source limit, the three auth directives.
CLOUD = SshGuardConfig(
    fail2ban_enabled=False,
    per_source_max_startups="",
    password_authentication="no",
    kbd_interactive_authentication="no",
    permit_root_login="prohibit-password",
    timed_revert_seconds=900,
    sshd_remove_cloud_init_dropin=True,
)


def cloud_init_host(content: bytes | None = PWAUTH, *, kind: str = "", read: str = "ok") -> dict[str, Any]:
    """An Ubuntu host without the drop-in yet whose probe also reports cloud-init's file (None: missing)."""

    responses = {
        **probe(openssh="OpenSSH_9.6p1 Ubuntu-3ubuntu13.20, OpenSSL 3.0.13 30 Jan 2024", sshd_session=False),
        **fakehost.UBUNTU,
        **fakehost.directory("/etc/ssh/sshd_config.d"),
    }
    responses[": ssh_guard probe"] = [*responses[": ssh_guard probe"], *cloud_init_lines(content, kind=kind, read=read)]
    return responses


def cloud_init_lines(content: bytes | None = PWAUTH, *, kind: str = "", read: str = "ok") -> list[str]:
    """The probe's lines; ``read``: ``ok``, ``failed`` (the marker after the bytes) or ``none`` (no line)."""

    if content is None:
        return [f"cloud_init_kind={kind or 'missing'}"]
    lines = [f"cloud_init_kind={kind or ('regular file' if content else 'regular empty file')}"]
    if kind in ("", "regular file", "regular empty file") and read != "none":
        data = content + (CLOUD_INIT_READ_FAILED if read == "failed" else b"")
        lines.append(f"cloud_init_b64={base64.b64encode(data).decode()}")
    return lines


def test_cloud_init_removal_is_off_by_default_and_not_probed() -> None:
    assert SshGuardConfig().sshd_remove_cloud_init_dropin is False
    assert "cloud_init" not in probe_command(SshGuardConfig())
    assert "50-cloud-init.conf" in probe_command(CLOUD)


@pytest.mark.parametrize(
    "update",
    [
        {"timed_revert_seconds": 0},
        {"password_authentication": None},
        {"password_authentication": "yes"},
        {"sshd_dropin_enabled": False},
        {"sshd_dropin_path": CLOUD_INIT},
        {"sshd_remove_cloud_init_dropin": "yes"},
        {"sshd_remove_cloud_init_dropin": 1},
    ],
    ids=["plain deploy", "no password value", "password yes", "no drop-in", "drop-in is cloud-init's", "str", "int"],
)
def test_cloud_init_removal_needs_password_no_and_the_timed_revert(update: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        SshGuardConfig(**{**CLOUD.model_dump(), **update})


def test_the_cloud_init_probe_is_read_only() -> None:
    command = probe_command(CLOUD)

    words = set(re.findall(r"[A-Za-z_-]+", command))
    assert not words & {"rm", "mv", "cp", "tee", "mkdir", "touch", "chmod", "chown", "unlink", "truncate"}
    assert ">" not in re.sub(r"2?>(/dev/null|&1)", "", command)


def test_cloud_init_probe_parsing() -> None:
    state = HostState.parse("\n".join(cloud_init_host()[": ssh_guard probe"]))

    assert state.cloud_init_kind == "regular file"
    assert base64.b64decode(state.cloud_init_b64 or "") == PWAUTH
    assert cloud_init_digest(CLOUD, state) == hashlib.sha256(PWAUTH).hexdigest()
    assert HostState().cloud_init_kind == "missing"
    assert cloud_init_digest(CLOUD, HostState()) is None


def test_cloud_init_file_is_removed_in_the_same_transaction_as_the_drop_in() -> None:
    bundle = plan_bundle(run_timed(cloud_init_host(), CLOUD))

    assert [step["name"] for step in bundle["steps"]] == [
        "Ensure /etc/ssh/sshd_config.d",
        REMOVE_CLOUD_INIT,
        "Write /etc/ssh/sshd_config.d/99-ssh-guard.conf",
        "Validate the sshd configuration",
        "Reload ssh for the new drop-in",
    ]
    remove, write, validate, reload_ = bundle["steps"][1:]
    assert (remove["kind"], remove["path"]) == ("absent", CLOUD_INIT)
    # The host removes only the probed content.
    assert remove["expect_sha256"] == hashlib.sha256(PWAUTH).hexdigest()
    assert write["content"] == render_dropin(CLOUD)
    assert render_dropin(CLOUD).splitlines()[1:] == [
        "PasswordAuthentication no",
        "KbdInteractiveAuthentication no",
        "PermitRootLogin prohibit-password",
    ]
    # Either change validates and reloads; validation checks the effective values.
    assert validate["when"] == reload_["when"] == [remove["id"], write["id"]]
    assert validate["command"] == validate_command(CLOUD)
    assert "'passwordauthentication no'" in validate["command"]
    # Both files are snapshotted, so a revert puts cloud-init's file back (owner and mode included).
    assert [entry["path"] for entry in bundle["files"]] == ["/etc/ssh/sshd_config.d/99-ssh-guard.conf", CLOUD_INIT]
    assert bundle["services"] == [
        {
            "role": "ssh",
            "unit": "ssh",
            "files": ["/etc/ssh/sshd_config.d/99-ssh-guard.conf", CLOUD_INIT],
            "check": "sshd -t -f /etc/ssh/sshd_config",
        }
    ]


def test_cloud_init_removal_on_top_of_an_existing_drop_in() -> None:
    """marina's form: fail2ban and PerSourceMaxStartups 5 stay, the auth lines are added."""

    before = IPTABLES_HOST
    cfg = before.model_copy(
        update={
            "password_authentication": "no",
            "kbd_interactive_authentication": "no",
            "permit_root_login": "prohibit-password",
            "timed_revert_seconds": 900,
            "sshd_remove_cloud_init_dropin": True,
        }
    )
    responses = converged(before, loaded_actions="iptables-multiport")
    responses.update(fakehost.file("/etc/ssh/sshd_config.d/99-ssh-guard.conf", render_dropin(before)))
    responses[": ssh_guard probe"] = [*responses[": ssh_guard probe"], *cloud_init_lines()]

    bundle = plan_bundle(run_timed(responses, cfg))

    names = [step["name"] for step in bundle["steps"]]
    assert names[-4:] == [
        REMOVE_CLOUD_INIT,
        "Write /etc/ssh/sshd_config.d/99-ssh-guard.conf",
        "Validate the sshd configuration",
        "Reload ssh for the new drop-in",
    ]
    assert render_dropin(cfg).splitlines()[1:] == [
        "PerSourceMaxStartups 5",
        "PasswordAuthentication no",
        "KbdInteractiveAuthentication no",
        "PermitRootLogin prohibit-password",
    ]
    assert [entry["path"] for entry in bundle["files"]][-2:] == [
        "/etc/ssh/sshd_config.d/99-ssh-guard.conf",
        CLOUD_INIT,
    ]


def test_a_missing_cloud_init_file_is_managed_and_must_stay_missing() -> None:
    bundle = plan_bundle(run_timed(cloud_init_host(None), CLOUD))

    [remove] = [step for step in bundle["steps"] if step["name"] == REMOVE_CLOUD_INIT]
    assert remove["kind"] == "absent"
    assert remove["expect_absent"] is True
    assert "expect_sha256" not in remove
    assert CLOUD_INIT in [entry["path"] for entry in bundle["files"]]
    validate = next(step for step in bundle["steps"] if step["name"] == "Validate the sshd configuration")
    write = next(step for step in bundle["steps"] if step["kind"] == "file")
    assert validate["when"] == [remove["id"], write["id"]]


@pytest.mark.parametrize(
    "content",
    [
        b"",
        b"PasswordAuthentication no\n",
        b"passwordauthentication=yes",
        b"# written by cloud-init\n\n  PasswordAuthentication yes  # x\r\n",
    ],
    ids=["empty", "no", "equals", "comments"],
)
def test_cloud_init_files_with_only_password_lines_are_accepted(content: bytes) -> None:
    bundle = plan_bundle(run_timed(cloud_init_host(content), CLOUD))

    [remove] = [step for step in bundle["steps"] if step["name"] == REMOVE_CLOUD_INIT]
    assert remove["expect_sha256"] == hashlib.sha256(content).hexdigest()


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"content": PWAUTH + b"PermitRootLogin yes\n"}, "1 line(s) other than"),
        ({"content": b"Match User scanner\n  PasswordAuthentication yes\n"}, "1 line(s) other than"),
        ({"content": b"PasswordAuthentication\n"}, "other than PasswordAuthentication"),
        ({"content": b"PasswordAuthentication yes\x00\nAllowUsers x\n"}, "bytes other than printable ASCII"),
        ({"content": "PasswordAuthentication jä\n".encode()}, "bytes other than printable ASCII"),
        ({"content": b"#" * 4097}, "larger than 4096 bytes"),
        ({"content": b"", "kind": "symbolic link"}, "is a symbolic link, not a regular file"),
        ({"content": b"", "kind": "fifo"}, "is a fifo, not a regular file"),
        ({"content": b"x", "read": "failed"}, "could not be read"),
        ({"content": PWAUTH, "read": "failed"}, "could not be read"),
        ({"content": b"x", "read": "none"}, "could not be read"),
    ],
    ids=[
        "other directive",
        "match block",
        "no value",
        "nul byte",
        "non-ascii",
        "too large content",
        "symlink",
        "fifo",
        "read error",
        "read error after good bytes",
        "no read line",
    ],
)
def test_cloud_init_files_with_anything_else_are_refused(kwargs: dict[str, Any], message: str) -> None:
    result = run_deploy_fake(deploy_ssh_guard, CLOUD, responses=cloud_init_host(**kwargs))

    assert not result.succeeded
    assert message in str(result.error)
    assert "not removed" in str(result.error)
    assert result.executed_commands == []
    assert result.uploaded_paths == []
    assert not any(PLAN in command for command in result.fact_commands)


def test_bad_base64_from_the_probe_is_refused() -> None:
    responses = cloud_init_host()
    lines = responses[": ssh_guard probe"]
    responses[": ssh_guard probe"] = [
        "cloud_init_b64=***" if line.startswith("cloud_init_b64=") else line for line in lines
    ]

    result = run_deploy_fake(deploy_ssh_guard, CLOUD, responses=responses)

    assert not result.succeeded
    assert "bad base64" in str(result.error)
