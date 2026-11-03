import logging
from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.base import IpOptionsDropConfig, deploy_ip_options_drop
from ops_deploy.base.ip_options_drop import (
    RULESET_PATH,
    SERVICE,
    STATUS_COMMAND,
    UNIT_PATH,
    TableStatus,
    check_command,
    parse_status,
    render_ruleset,
    render_service,
)
from ops_deploy.testing import run_deploy_fake
from tests.fakehost import LINUX, directory, file

P = "IPv4 options drop | "
SYSTEMD = {**LINUX, "cat /proc/1/comm": ["systemd"]}
STATUS = "echo no-nft"
CHECK = "nft -c -f -"
# What nftables 1.0.6, 1.0.9 and 1.1.3 print for the loaded table (checked on all three).
LISTING = [
    "table ip ip_options_drop {",
    "\tchain prerouting {",
    "\t\ttype filter hook prerouting priority raw; policy accept;",
    "\t\tmeta l4proto tcp ip hdrlength > 5 counter packets 7 bytes 448 drop",
    "\t}",
    "}",
]
LOADED = ["loaded", *LISTING]
FRESH = [
    P + "Ensure /etc/ops-deploy",
    P + f"Write {RULESET_PATH}",
    P + f"Install systemd unit {SERVICE}",
    P + f"Reload systemd for {SERVICE}",
    P + f"Enable {SERVICE}",
    P + f"Start {SERVICE}",
]


def kinds(unit: str = "missing", ruleset: str = "missing") -> dict[str, Any]:
    return {f"stat -c %F {UNIT_PATH}": [unit], f"stat -c %F {RULESET_PATH}": [ruleset]}


def unit(active: str = "inactive", file_state: str = "", load: str = "not-found") -> dict[str, Any]:
    lines = [f"Id={SERVICE}", f"LoadState={load}", f"ActiveState={active}", f"UnitFileState={file_state}", "---"]
    return {"for unit in": lines}


def host(*, status: list[str], installed: bool, active: str = "active", file_state: str = "enabled") -> dict[str, Any]:
    responses: dict[str, Any] = {**SYSTEMD, STATUS: status, CHECK: []}
    if installed:
        responses |= {
            **kinds("regular file", "regular file"),
            **unit(active, file_state, "loaded"),
            **directory("/etc/ops-deploy"),
            **directory("/etc/systemd/system"),
            **file(RULESET_PATH, render_ruleset()),
            **file(UNIT_PATH, render_service()),
        }
    else:
        responses |= {**kinds(), **unit()}
    return responses


def planned_mutations(run: Any) -> list[str]:
    """What ``--dry`` lists as a change, minus the read-only checks."""

    return [name for name in run.planned_changes if not run.op(name).read_only]


def actions(run: Any) -> list[str]:
    """Executed commands without the ``files.put`` ownership and mode commands."""

    return [c for c in run.executed_commands if not c.startswith(("chown ", "chmod ", "mv ", "rm -f /tmp"))]


PRESENT = IpOptionsDropConfig()
ABSENT = IpOptionsDropConfig(state="absent")


def test_ruleset_replaces_only_its_own_table() -> None:
    ruleset = render_ruleset()
    statements = [line for line in ruleset.splitlines() if line and not line.startswith("#")]
    assert statements[:3] == [
        "table ip ip_options_drop",
        "delete table ip ip_options_drop",
        "table ip ip_options_drop {",
    ]
    assert "\t\ttype filter hook prerouting priority -300; policy accept;" in statements
    assert "\t\tmeta l4proto tcp ip hdrlength gt 5 counter drop" in statements
    assert "flush" not in ruleset


def test_unit_loads_after_nftables_and_follows_its_restarts_and_reloads() -> None:
    lines = render_service().splitlines()
    for expected in (
        "DefaultDependencies=no",
        "Before=network-pre.target",
        "After=nftables.service",
        "PartOf=nftables.service",
        "ReloadPropagatedFrom=nftables.service",
        f"ConditionPathExists={RULESET_PATH}",
        "Type=oneshot",
        "RemainAfterExit=yes",
        f"ExecStart=/usr/sbin/nft -f {RULESET_PATH}",
        f"ExecReload=/usr/sbin/nft -f {RULESET_PATH}",
        "ExecStop=-/usr/sbin/nft delete table ip ip_options_drop",
        "WantedBy=sysinit.target",
    ):
        assert expected in lines


def test_first_run_installs_enables_and_starts(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="pyinfra")

    run = run_deploy_fake(deploy_ip_options_drop, PRESENT, responses=host(status=["absent"], installed=False))

    assert run.succeeded, run.error
    assert run.mutating_changed_ops == FRESH
    assert sorted(run.uploaded_paths) == sorted([RULESET_PATH, UNIT_PATH])
    assert run.upload(RULESET_PATH).decode() == render_ruleset()
    assert run.upload(UNIT_PATH).decode() == render_service()
    shell = [c for c in run.executed_commands if c.startswith("systemctl") and "is-active" not in c]
    assert shell == ["systemctl daemon-reload", f"systemctl enable {SERVICE}", f"systemctl start {SERVICE}"]
    assert check_command("present") in run.executed_commands
    # The kernel checked the exact ruleset while planning.
    assert [payload for command, payload in run.stdin if CHECK in command] == [render_ruleset()]
    assert "ip_options_drop: table ip ip_options_drop not loaded" in caplog.text


def test_converged_host_changes_nothing_and_logs_the_counter(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="pyinfra")

    run = run_deploy_fake(deploy_ip_options_drop, PRESENT, responses=host(status=LOADED, installed=True))

    assert run.succeeded, run.error
    assert run.mutating_changed_ops == []
    assert planned_mutations(run) == []
    assert run.uploaded_paths == []
    assert run.executed_commands == [check_command("present")]
    assert "loaded; dropped 7 packet(s), 448 byte(s) since it was last loaded" in caplog.text


@pytest.mark.parametrize(
    ("status", "name"),
    [
        (["absent"], "flushed by something else"),
        (["loaded", *LISTING[:3], "\t\tip saddr 192.0.2.1 accept", *LISTING[3:]], "an extra rule"),
        (["loaded", *[line.replace("drop", "accept") for line in LISTING]], "rule changed"),
    ],
)
def test_missing_or_changed_table_is_reloaded(status: list[str], name: str) -> None:
    run = run_deploy_fake(deploy_ip_options_drop, PRESENT, responses=host(status=status, installed=True))

    assert run.succeeded, (name, run.error)
    assert run.mutating_changed_ops == [P + f"Reload {SERVICE} (table missing or changed)"]
    assert run.executed_commands == [f"systemctl reload {SERVICE}", check_command("present")]


def test_changed_ruleset_file_reloads_the_active_unit() -> None:
    responses = {**host(status=LOADED, installed=True), **file(RULESET_PATH, "old\n")}

    run = run_deploy_fake(deploy_ip_options_drop, PRESENT, responses=responses)

    assert run.succeeded, run.error
    assert run.mutating_changed_ops == [P + f"Write {RULESET_PATH}", P + f"Reload {SERVICE}"]
    assert actions(run) == [f"systemctl reload {SERVICE}", check_command("present")]


def test_changed_unit_reloads_systemd_then_the_unit() -> None:
    responses = {**host(status=LOADED, installed=True), **file(UNIT_PATH, "[Unit]\n")}

    run = run_deploy_fake(deploy_ip_options_drop, PRESENT, responses=responses)

    assert run.succeeded, run.error
    assert actions(run) == [
        "systemctl daemon-reload",
        f"systemctl reload {SERVICE}",
        check_command("present"),
    ]


@pytest.mark.parametrize(
    ("active", "file_state"), [("inactive", "enabled"), ("failed", "disabled"), ("inactive", "enabled-runtime")]
)
def test_inactive_or_disabled_unit_is_started_and_enabled(active: str, file_state: str) -> None:
    run = run_deploy_fake(
        deploy_ip_options_drop,
        PRESENT,
        responses=host(status=LOADED, installed=True, active=active, file_state=file_state),
    )

    assert run.succeeded, run.error
    expected = [f"systemctl start {SERVICE}", check_command("present")]
    if file_state != "enabled":
        expected.insert(0, f"systemctl enable {SERVICE}")
    assert run.executed_commands == expected


def test_runtime_only_enablement_is_made_persistent() -> None:
    run = run_deploy_fake(
        deploy_ip_options_drop,
        PRESENT,
        responses=host(status=LOADED, installed=True, active="active", file_state="enabled-runtime"),
    )

    assert run.succeeded, run.error
    assert run.mutating_changed_ops == [P + f"Enable {SERVICE}"]
    assert run.executed_commands == [f"systemctl enable {SERVICE}", check_command("present")]


def test_refuses_without_nft_before_any_change() -> None:
    run = run_deploy_fake(deploy_ip_options_drop, PRESENT, responses=host(status=["no-nft"], installed=False))

    assert "needs nftables (/usr/sbin/nft)" in str(run.error)
    assert run.executed_commands == []


def test_refuses_when_the_kernel_rejects_the_ruleset() -> None:
    responses = {**host(status=["absent"], installed=False), CHECK: ["Error: syntax", "", "ops-deploy-probe-failed"]}

    run = run_deploy_fake(deploy_ip_options_drop, PRESENT, responses=responses)

    assert "nft -c refused the ruleset" in str(run.error)
    assert run.executed_commands == []


def test_refuses_a_symlinked_unit() -> None:
    responses = {**host(status=["absent"], installed=False), **kinds(unit="symbolic link")}

    run = run_deploy_fake(deploy_ip_options_drop, PRESENT, responses=responses)

    assert f"{UNIT_PATH} is a symbolic link" in str(run.error)
    assert run.executed_commands == []


def test_unreadable_nft_state_fails_before_any_change() -> None:
    responses = {**host(status=["absent"], installed=False), STATUS: ["", "ops-deploy-probe-failed"]}

    run = run_deploy_fake(deploy_ip_options_drop, PRESENT, responses=responses)

    assert "could not read the nftables state" in str(run.error)
    assert run.executed_commands == []


def test_refuses_non_systemd_host() -> None:
    run = run_deploy_fake(deploy_ip_options_drop, PRESENT, responses={**LINUX, "cat /proc/1/comm": ["init"]})

    assert "requires a systemd-managed host" in str(run.error)
    assert run.ops == []


def test_absent_disables_stops_removes_and_deletes() -> None:
    run = run_deploy_fake(deploy_ip_options_drop, ABSENT, responses=host(status=LOADED, installed=True))

    assert run.succeeded, run.error
    assert run.mutating_changed_ops == [
        P + f"Disable and stop {SERVICE}",
        P + f"Remove {UNIT_PATH}",
        P + f"Remove {RULESET_PATH}",
        P + f"Reload systemd after removing {SERVICE}",
        P + "Delete table ip ip_options_drop",
    ]
    commands = run.executed_commands
    assert commands[:2] == [f"systemctl disable {SERVICE}", f"systemctl stop {SERVICE}"]
    assert f"rm -f {UNIT_PATH}" in commands
    assert f"rm -f {RULESET_PATH}" in commands
    assert commands[-3:] == [
        "systemctl daemon-reload",
        "if /usr/sbin/nft list tables ip | grep -qx 'table ip ip_options_drop'; "
        "then /usr/sbin/nft delete table ip ip_options_drop; fi",
        check_command("absent"),
    ]
    # No nft -c for removal.
    assert not any(CHECK in command for command in run.fact_commands)


def test_absent_deletes_a_table_loaded_without_the_unit() -> None:
    run = run_deploy_fake(deploy_ip_options_drop, ABSENT, responses=host(status=LOADED, installed=False))

    assert run.succeeded, run.error
    assert run.mutating_changed_ops == [P + "Delete table ip ip_options_drop"]


@pytest.mark.parametrize("status", [["absent"], ["no-nft"]])
def test_absent_on_a_clean_host_changes_nothing(status: list[str]) -> None:
    run = run_deploy_fake(deploy_ip_options_drop, ABSENT, responses=host(status=status, installed=False))

    assert run.succeeded, run.error
    assert run.mutating_changed_ops == []
    assert planned_mutations(run) == []
    assert run.executed_commands == [check_command("absent")]


@pytest.mark.parametrize(
    ("answer", "expected"),
    [
        ("absent\n", TableStatus(loaded=False)),
        ("no-nft\n", TableStatus(loaded=False, nft_missing=True)),
        ("\n".join(LOADED), TableStatus(loaded=True, current=True, packets=7, bytes=448)),
        ("\n".join(LOADED).replace("priority raw", "priority -300"), TableStatus(True, True, 7, 448)),
        ("loaded\ntable ip ip_options_drop {\n}\n", TableStatus(loaded=True)),
    ],
)
def test_parse_status(answer: str, expected: TableStatus) -> None:
    assert parse_status(answer) == expected


@pytest.mark.parametrize("answer", [None, "", "maybe\n", "absent\ntable ip ip_options_drop {\n"])
def test_parse_status_refuses_unreadable_answers(answer: str | None) -> None:
    with pytest.raises(Exception, match="ip_options_drop"):
        parse_status(answer)


def test_status_command_only_reads() -> None:
    assert "list tables ip" in STATUS_COMMAND
    assert "list table ip ip_options_drop" in STATUS_COMMAND
    for verb in ("add ", "delete ", "flush ", "-f "):
        assert verb not in STATUS_COMMAND


@pytest.mark.parametrize("state", ["", "disabled", True])
def test_rejects_invalid_config(state: object) -> None:
    with pytest.raises(ValidationError):
        IpOptionsDropConfig.model_validate({"state": state})


def test_rejects_unknown_keys() -> None:
    with pytest.raises(ValidationError):
        IpOptionsDropConfig.model_validate({"table": "other"})
