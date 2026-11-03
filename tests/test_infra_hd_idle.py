"""hd-idle idle spindown: config rendering, fake-host rollout, idempotent second run."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.infra.hd_idle import (
    CONFIG_PATH,
    DROPIN_DIR,
    DROPIN_PATH,
    SERVICE,
    HdIdleConfig,
    HdIdleDisk,
    deploy_hd_idle,
    device_unit,
    render_config,
    render_dropin,
)
from ops_deploy.testing import run_deploy_fake
from tests import fakehost

DISK_A = "/dev/disk/by-id/ata-WDC_WD120EFGX-68CPHN0_WD-OWNEDA"
DISK_B = "/dev/disk/by-id/ata-WDC_WD120EFGX-68CPHN0_WD-OWNEDB"


def policy(**fields: Any) -> HdIdleConfig:
    disks = (HdIdleDisk(device=DISK_A, idle_time=1800), HdIdleDisk(device=DISK_B, idle_time=1800))
    return HdIdleConfig(**{"disks": disks, **fields})


def host(
    cfg: HdIdleConfig, *, installed: bool = True, config: bool = False, dropin: bool = False, running: bool = False
) -> dict[str, Any]:
    responses: dict[str, Any] = {
        **fakehost.UBUNTU,
        **fakehost.apt_cache_fresh(),
        **fakehost.service(SERVICE, running=running, enabled=running),
        **fakehost.directory("/etc/default"),
        **fakehost.directory("/etc/systemd/system"),
    }
    if installed:
        responses.update(fakehost.deb_installed("hd-idle"))
    if config:
        responses.update(fakehost.file(CONFIG_PATH, render_config(cfg)))
    if dropin:
        responses.update(fakehost.directory(DROPIN_DIR))
        responses.update(fakehost.file(DROPIN_PATH, render_dropin(cfg)))
    return responses


def touches_no_disk(commands: list[str]) -> None:
    for command in commands:
        assert "hdparm" not in command
        assert "smartctl" not in command
        assert "hd-idle -t" not in command
        assert "/dev/sd" not in command


def test_config_renders_global_zero_then_each_disk() -> None:
    assert render_config(policy()) == (
        "# Managed by ops-deploy infra.hd_idle; local changes are overwritten.\n"
        "# hd-idle resolves each -a link to its kernel name once, at service start.\n"
        f'HD_IDLE_OPTS="-i 0 -a {DISK_A} -i 1800 -a {DISK_B} -i 1800"\n'
    )


def test_dropin_pins_the_config_file_and_waits_for_the_links() -> None:
    unit_a = r"dev-disk-by\x2did-ata\x2dWDC_WD120EFGX\x2d68CPHN0_WD\x2dOWNEDA.device"
    unit_b = r"dev-disk-by\x2did-ata\x2dWDC_WD120EFGX\x2d68CPHN0_WD\x2dOWNEDB.device"
    assert render_dropin(policy()) == (
        "# Managed by ops-deploy infra.hd_idle; local changes are overwritten.\n"
        f"[Unit]\nWants={unit_a} {unit_b}\nAfter={unit_a} {unit_b}\n\n"
        "[Service]\nEnvironmentFile=\nEnvironmentFile=/etc/default/hd-idle\n"
    )


@pytest.mark.parametrize(
    ("path", "unit"),
    [
        # Both checked against systemd-escape --path 255 (Ubuntu 24.04).
        (
            "/dev/disk/by-id/ata-WDC_WD120EFGX-68CPHN0_WD-B00MJ7WD",
            r"dev-disk-by\x2did-ata\x2dWDC_WD120EFGX\x2d68CPHN0_WD\x2dB00MJ7WD.device",
        ),
        (
            "/dev/disk/by-id/usb-WD_Elements_25A3_53544B5433395445-0:0",
            r"dev-disk-by\x2did-usb\x2dWD_Elements_25A3_53544B5433395445\x2d0:0.device",
        ),
        ("/dev/disk/by-id/a.b+c", r"dev-disk-by\x2did-a.b\x2bc.device"),
    ],
)
def test_device_unit_matches_systemd_escape(path: str, unit: str) -> None:
    assert device_unit(path) == unit


@pytest.mark.parametrize(
    "disks",
    [
        (),
        ({"device": "/dev/sda", "idle_time": 1800},),
        ({"device": "/dev/disk/by-id/ata-owned-part1", "idle_time": 1800},),
        ({"device": "/dev/disk/by-id/../sda", "idle_time": 1800},),
        ({"device": "/dev/disk/by-id/..", "idle_time": 1800},),
        ({"device": "/dev/disk/by-id/owned disk", "idle_time": 1800},),
        ({"device": "/dev/disk/by-uuid/owned", "idle_time": 1800},),
        ({"device": DISK_A, "idle_time": 0},),
        ({"device": DISK_A, "idle_time": "1800"},),
        ({"device": DISK_A, "idle_time": 1800}, {"device": DISK_A, "idle_time": 600}),
    ],
)
def test_invalid_disks_refuse(disks: tuple[dict[str, Any], ...]) -> None:
    with pytest.raises(ValidationError):
        HdIdleConfig.model_validate({"disks": disks})


def test_other_disks_cannot_get_an_idle_time() -> None:
    with pytest.raises(ValidationError):
        policy(default_idle_time=60)


def test_fresh_host_installs_configures_and_starts() -> None:
    cfg = policy()
    run = run_deploy_fake(deploy_hd_idle, cfg, responses=host(cfg, installed=False))

    assert run.succeeded, run.error
    assert run.written(CONFIG_PATH) == render_config(cfg).encode()
    assert run.written(DROPIN_PATH) == render_dropin(cfg).encode()
    commands = run.executed_commands
    install = next(n for n, c in enumerate(commands) if "apt-get" in c and "install" in c and "hd-idle" in c)
    reload = commands.index("systemctl daemon-reload")
    start = commands.index(f"systemctl start {SERVICE}")
    assert install < reload < start
    assert f"systemctl enable {SERVICE}" in commands
    # Just started with the new config: no extra restart.
    assert f"systemctl restart {SERVICE}" not in commands
    touches_no_disk(commands)


def test_second_run_is_a_noop() -> None:
    cfg = policy()
    run = run_deploy_fake(deploy_hd_idle, cfg, responses=host(cfg, config=True, dropin=True, running=True))

    assert run.succeeded, run.error
    assert run.changed_ops == []
    assert run.executed_commands == []


def test_changed_config_restarts_without_reload() -> None:
    cfg = policy()
    responses = host(cfg, dropin=True, running=True)
    responses.update(fakehost.file(CONFIG_PATH, 'HD_IDLE_OPTS="-h"\n'))
    run = run_deploy_fake(deploy_hd_idle, cfg, responses=responses)

    assert run.succeeded, run.error
    assert run.written_paths == [CONFIG_PATH]
    commands = run.executed_commands
    assert "systemctl daemon-reload" not in commands
    assert f"systemctl restart {SERVICE}" in commands
    touches_no_disk(commands)


def test_changed_dropin_reloads_and_restarts() -> None:
    cfg = policy()
    responses = host(cfg, config=True, running=True)
    responses.update(fakehost.directory(DROPIN_DIR))
    responses.update(fakehost.file(DROPIN_PATH, "[Service]\n"))
    run = run_deploy_fake(deploy_hd_idle, cfg, responses=responses)

    assert run.succeeded, run.error
    assert run.written_paths == [DROPIN_PATH]
    commands = run.executed_commands
    assert commands.index("systemctl daemon-reload") < commands.index(f"systemctl restart {SERVICE}")


def test_needs_systemd() -> None:
    cfg = policy()
    run = run_deploy_fake(deploy_hd_idle, cfg, responses={**host(cfg), "cat /proc/1/comm": ["init"]})

    assert not run.succeeded
    assert "systemd" in str(run.error)
