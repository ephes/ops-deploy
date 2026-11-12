"""default_qdisc against the fake connector: first run, converged run, drift and refusals."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.base import DefaultQdiscConfig, deploy_default_qdisc
from ops_deploy.base.default_qdisc import (
    SERVICE,
    SYSCTL_PATH,
    device_unit,
    render_service,
    render_sysctl,
    root_qdisc,
)
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests.fakehost import LINUX, directory, file

P = "Default qdisc | "
UNIT_PATH = f"/etc/systemd/system/{SERVICE}"
CFG = DefaultQdiscConfig(interfaces=("enp4s0",))
# What macmini shows today (a tg3 NIC brought up by the initramfs before the sysctl).
MQ = ["qdisc mq 0: root ", "qdisc pfifo_fast 0: parent :1 bands 3 priomap 1 2 2 2 1 2 0 0 1 1 1 1 1 1 1 1"]
FQ_CODEL = [
    "qdisc fq_codel 8001: root refcnt 2 limit 10240p flows 1024 quantum 1514 target 5ms interval 100ms "
    "memory_limit 32Mb ecn drop_batch 64 "
]


def unit(file_state: str) -> dict[str, Any]:
    load = "loaded" if file_state else "not-found"
    return {
        "for unit in": [
            f"Id={SERVICE}",
            f"LoadState={load}",
            "ActiveState=inactive",
            f"UnitFileState={file_state}",
            "---",
        ]
    }


def host(
    cfg: DefaultQdiscConfig = CFG,
    *,
    running: str = "fq_codel",
    qdiscs: dict[str, list[str]] | None = None,
    installed: bool = True,
) -> dict[str, Any]:
    responses: dict[str, Any] = {
        **LINUX,
        "cat /proc/1/comm": ["systemd"],
        "cat /proc/sys/net/core/default_qdisc": [running],
        "test -x /usr/sbin/tc": ["present"],
        **directory("/etc/sysctl.d"),
        **directory("/etc/systemd/system"),
    }
    for interface in cfg.interfaces:
        responses[f"test -d /sys/class/net/{interface} "] = ["present"]
        responses[f"tc qdisc show dev {interface} root"] = (qdiscs or {}).get(interface, FQ_CODEL)
    if installed:
        responses |= {
            **file(SYSCTL_PATH, render_sysctl(cfg)),
            **file(UNIT_PATH, render_service(cfg)),
            **unit("enabled"),
        }
    else:
        responses |= unit("")
    return responses


def overlay(base: dict[str, Any], drift: dict[str, Any]) -> dict[str, Any]:
    """``base`` with ``drift`` taking precedence (the first matching key wins, so drift goes first)."""

    return {**drift, **{key: value for key, value in base.items() if key not in drift}}


def deploy(cfg: DefaultQdiscConfig, responses: dict[str, Any]) -> FakeRun:
    run = run_deploy_fake(deploy_default_qdisc, cfg, responses=responses)
    assert run.succeeded, run.error
    return run


def actions(run: FakeRun) -> list[str]:
    """Executed commands without the ``files.put`` ownership, mode and staging commands."""

    return [c for c in run.executed_commands if not c.startswith(("chown ", "chmod ", "mv ", "rm -f /tmp"))]


def test_rendered_files() -> None:
    assert render_sysctl(CFG) == (
        "# Managed by ops-deploy base.default_qdisc; local changes are overwritten.\n"
        "net.core.default_qdisc = fq_codel\n"
    )
    assert render_service(DefaultQdiscConfig(interfaces=("enp4s0", "br-lan"))) == (
        "# Managed by ops-deploy base.default_qdisc; local changes are overwritten.\n"
        "[Unit]\n"
        "Description=fq_codel as root qdisc on enp4s0 br-lan\n"
        "Wants=sys-subsystem-net-devices-enp4s0.device sys-subsystem-net-devices-br\\x2dlan.device\n"
        "After=sys-subsystem-net-devices-enp4s0.device sys-subsystem-net-devices-br\\x2dlan.device\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        "RemainAfterExit=yes\n"
        "ExecStart=/usr/sbin/tc qdisc replace dev enp4s0 root fq_codel\n"
        "ExecStart=/usr/sbin/tc qdisc replace dev br-lan root fq_codel\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )


def test_device_unit_escapes_dashes_only() -> None:
    assert device_unit("enp4s0") == "sys-subsystem-net-devices-enp4s0.device"
    assert device_unit("br-lan.10") == "sys-subsystem-net-devices-br\\x2dlan.10.device"


@pytest.mark.parametrize(
    ("shown", "kind"),
    [
        (MQ, "mq"),
        (FQ_CODEL, "fq_codel"),
        (["qdisc noqueue 0: root refcnt 2 "], "noqueue"),
        (["qdisc fq_codel 0: dev enp4s0 root refcnt 2 limit 10240p"], "fq_codel"),
        ([], None),
        (['Cannot find device "enp9s0"'], None),
    ],
)
def test_root_qdisc(shown: list[str], kind: str | None) -> None:
    assert root_qdisc("\n".join(shown)) == kind


def test_first_run_on_macmini_replaces_mq_and_enables_the_boot_unit() -> None:
    run = deploy(CFG, host(qdiscs={"enp4s0": MQ}, installed=False))

    assert run.upload(SYSCTL_PATH).decode() == render_sysctl(CFG)
    assert run.upload(UNIT_PATH).decode() == render_service(CFG)
    # The running default already is fq_codel (Ubuntu's 10-bufferbloat.conf): no sysctl -w.
    assert actions(run) == [
        "systemctl daemon-reload",
        f"systemctl enable {SERVICE}",
        "/usr/sbin/tc qdisc replace dev enp4s0 root fq_codel",
    ]
    assert not any(f"start {SERVICE}" in c or "restart" in c for c in run.executed_commands)


def test_running_default_is_set_when_it_differs() -> None:
    run = deploy(CFG, host(running="pfifo_fast"))

    assert run.mutating_changed_ops == [f"{P}Set net.core.default_qdisc to fq_codel"]
    assert actions(run) == ["sysctl -w net.core.default_qdisc=fq_codel"]


def test_converged_host_plans_no_change() -> None:
    run = deploy(CFG, host())

    assert run.planned_changes == []
    assert run.changed_ops == []
    assert run.uploads == []
    assert run.executed_commands == []


def test_second_run_after_the_replace_plans_no_change() -> None:
    # The state the first run leaves: files in place, unit enabled, fq_codel at the root.
    first = deploy(CFG, host(qdiscs={"enp4s0": MQ}, installed=False))
    assert first.mutating_changed_ops

    second = deploy(CFG, host(qdiscs={"enp4s0": FQ_CODEL}))
    assert second.planned_changes == []
    assert second.executed_commands == []


def test_only_interfaces_without_fq_codel_are_replaced() -> None:
    cfg = DefaultQdiscConfig(interfaces=("enp4s0", "enp5s0"))

    run = deploy(cfg, host(cfg, qdiscs={"enp5s0": ["qdisc pfifo_fast 0: root refcnt 2 bands 3"]}))

    assert run.mutating_changed_ops == [f"{P}Replace the root qdisc of enp5s0 (pfifo_fast) with fq_codel"]
    assert actions(run) == ["/usr/sbin/tc qdisc replace dev enp5s0 root fq_codel"]


def test_unit_drift_reloads_without_starting_and_disabled_unit_is_enabled() -> None:
    responses = overlay(host(), {**file(UNIT_PATH, "[Unit]\n"), **unit("disabled")})

    run = deploy(CFG, responses)

    assert run.mutating_changed_ops == [
        f"{P}Install systemd unit {SERVICE}",
        f"{P}Reload systemd for {SERVICE}",
        f"{P}Enable {SERVICE}",
    ]
    assert actions(run) == ["systemctl daemon-reload", f"systemctl enable {SERVICE}"]


def test_sysctl_file_drift_is_rewritten_alone() -> None:
    responses = overlay(host(), file(SYSCTL_PATH, "net.core.default_qdisc = fq\n"))

    run = deploy(CFG, responses)

    assert run.mutating_changed_ops == [f"{P}Install {SYSCTL_PATH}"]
    assert actions(run) == []


@pytest.mark.parametrize(
    ("drift", "message"),
    [
        ({"uname -s": ["Darwin"]}, "Linux hosts only"),
        ({"cat /proc/1/comm": ["init"]}, "systemd-managed host"),
        ({"cat /proc/sys/net/core/default_qdisc": []}, "could not read net.core.default_qdisc"),
        ({"test -x /usr/sbin/tc": []}, "needs /usr/sbin/tc"),
        ({"test -d /sys/class/net/enp4s0 ": []}, "interface enp4s0 does not exist"),
        ({"tc qdisc show dev enp4s0 root": []}, "could not read the root qdisc of enp4s0"),
    ],
)
def test_refusals_before_any_change(drift: dict[str, Any], message: str) -> None:
    run = run_deploy_fake(deploy_default_qdisc, CFG, responses=overlay(host(qdiscs={"enp4s0": MQ}), drift))

    assert not run.succeeded
    assert message in str(run.error)
    assert run.ops == []
    assert run.executed_commands == []


@pytest.mark.parametrize(
    "overrides",
    [
        {"interfaces": ()},
        {"interfaces": ("enp4s0", "enp4s0")},
        {"interfaces": ("eth0:1",)},
        {"interfaces": ("en p4s0",)},
        {"interfaces": ("-enp4s0",)},
        {"interfaces": ("enp4s0; reboot",)},
        {"interfaces": ("a" * 16,)},
        {"interfaces": ("enp4s0",), "qdisc": "fq"},
        {"interfaces": ("enp4s0",), "extra": True},
    ],
)
def test_config_validation(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        DefaultQdiscConfig(**overrides)


def test_interfaces_are_required() -> None:
    with pytest.raises(ValidationError):
        DefaultQdiscConfig()  # type: ignore[call-arg]
