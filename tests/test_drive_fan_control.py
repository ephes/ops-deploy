"""files/drive_fan_control.py: policy, readers, BMC writes, fail-safes, stop helper, calibration.

Everything runs against the fake host of :mod:`tests.drive_fan_control_fixtures`
(fake ``ipmitool``/``hdparm``/``smartctl``/``zpool`` executables, a sysfs
tree, a fake clock), through the controller's real command runner.
"""

from __future__ import annotations

import json
import os
import socket
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from tests.drive_fan_control_fixtures import (
    CALIBRATION,
    DEV_HDD1,
    DEV_HDD2,
    DFC,
    DUTY0,
    MODE0,
    FakeHost,
    config,
    config_dict,
    no_backslashes,
)


@pytest.fixture
def host(tmp_path: Path) -> FakeHost:
    return FakeHost(tmp_path)


@pytest.fixture(autouse=True)
def _no_notify_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NOTIFY_SOCKET", raising=False)


def run(host: FakeHost, cfg: Any, cycles: int) -> tuple[int, Any]:
    """cmd_run for ``cycles`` cycles (the loop stops itself), with the fake clock."""

    controller = host.controller(cfg)
    original = controller.loop

    def loop(count: int | None = None) -> None:
        original(cycles)

    controller.loop = loop
    code = DFC.cmd_run(cfg, host.paths, controller.run, controller)
    return code, controller


# -- configuration -------------------------------------------------------------------


def test_the_example_config_parses() -> None:
    cfg = config()
    assert cfg.managed_positions == (0, 1, 2)
    assert [p.position for p in cfg.protected] == [5]
    assert cfg.curves["hdd"][0] == (36.0, 35)


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"floor_pct": 24}, "floor_pct"),
        ({"floor_pct": 101}, "floor_pct"),
        ({"protected": [{"position": 2, "sensor": "FAN6_1"}]}, "never both managed and protected"),
        ({"managed": [{"position": 0, "sensor": "A"}, {"position": 0, "sensor": "B"}]}, "listed once"),
        ({"managed": []}, "managed"),
        ({"protected": []}, "protected"),
        ({"managed": [{"position": 16, "sensor": "FAN1_1"}]}, "position"),
        (
            {"curves": {"hdd": [[36, 35], [47, 101]], "nvme": [[48, 35], [72, 100]], "cpu": [[60, 35], [85, 100]]}},
            "duty",
        ),
        (
            {"curves": {"hdd": [[36, 50], [47, 40]], "nvme": [[48, 35], [72, 100]], "cpu": [[60, 35], [85, 100]]}},
            "decrease",
        ),
        (
            {"curves": {"hdd": [[47, 35], [36, 50]], "nvme": [[48, 35], [72, 100]], "cpu": [[60, 35], [85, 100]]}},
            "increase",
        ),
        ({"curves": {"hdd": [[36, 35]], "nvme": [[48, 35], [72, 100]], "cpu": [[60, 35], [85, 100]]}}, "two points"),
        ({"mode": "manual"}, "mode"),
        ({"version": 2}, "version"),
        ({"backend": "other"}, "backend"),
        ({"surprise": 1}, "unknown keys"),
        ({"hdd": [{"name": "x", "device": "/tmp/disk"}]}, "device"),
        ({"hdd": [{"name": "x", "device": "/dev/disk/../sda"}]}, "plain absolute path"),
        ({"hdd": [{"name": "cpu", "device": "/dev/sda"}]}, "must not be"),
        (
            {"nvme": [{"name": "same", "device": "/dev/nvme0n1"}], "hdd": [{"name": "same", "device": "/dev/sda"}]},
            "differ",
        ),
        ({"mode": "calibrate"}, "calibration block"),
        ({"interval_s": 5}, "interval_s"),
        ({"hdd_interval_s": 20}, "hdd_interval_s"),
        ({"decrease_step_pct": 2, "min_change_pct": 3}, "at least min_change_pct"),
        ({"calibration": {**CALIBRATION, "steps_pct": [50, 70]}}, "decrease"),
        ({"calibration": {**CALIBRATION, "steps_pct": [100, 20]}}, "steps_pct"),
        ({"calibration": {**CALIBRATION, "settle_s": 30}}, "settle_s"),
        ({"board": {"dmi_board_vendor": "x"}}, "board"),
        ({"floor_pct": True}, "floor_pct"),
    ],
)
def test_bad_configs_are_refused(changes: dict[str, Any], message: str) -> None:
    with pytest.raises(DFC.ConfigError, match=message):
        DFC.parse_config(config_dict(**changes))


# -- policy --------------------------------------------------------------------------


def test_curves_interpolate_and_clamp_to_their_ends() -> None:
    curve = config().curves["hdd"]
    assert DFC.interpolate(curve, 20) == 35
    assert DFC.interpolate(curve, 36) == 35
    assert DFC.interpolate(curve, 38) == 40
    assert DFC.interpolate(curve, 42) == 60
    assert DFC.interpolate(curve, 47) == 100
    assert DFC.interpolate(curve, 60) == 100


def readings(**kw: Any) -> Any:
    hdd = {name: DFC.HddReading("active", celsius) for name, celsius in kw.pop("hdd", {}).items()}
    return DFC.Readings(hdd=hdd, **kw)


def test_the_demand_is_the_highest_ask_clamped_to_the_floor() -> None:
    cfg = config()
    assert DFC.demand(cfg, readings(cpu=40.0, nvme={"fast-nvme": 44.0})) == (35, ["floor"])
    target, why = DFC.demand(cfg, readings(cpu=40.0, nvme={"fast-nvme": 60.0}, hdd={"tank-hdd-1": 41.0}))
    assert target == 65
    assert why == ["fast-nvme 60.0C"]
    target, why = DFC.demand(cfg, readings(cpu=40.0, hdd={"tank-hdd-1": 41.0, "tank-hdd-2": 45.0}))
    assert (target, why) == (84, ["tank-hdd-2 45C"])
    assert DFC.demand(cfg, readings(cpu=90.0))[0] == 100


def test_standby_disks_ask_nothing() -> None:
    cfg = config()
    standby = DFC.Readings(cpu=40.0, hdd={"tank-hdd-1": DFC.HddReading("standby")})
    assert DFC.demand(cfg, standby) == (35, ["floor"])


def test_a_running_scan_feeds_forward() -> None:
    cfg = config()
    assert DFC.demand(cfg, DFC.Readings(cpu=40.0, scans={"tank": True, "fast": False})) == (60, ["scan tank"])
    assert DFC.demand(cfg, DFC.Readings(cpu=40.0, scans={"tank": True, "fast": True})) == (85, ["scan fast"])
    assert DFC.demand(cfg, DFC.Readings(cpu=40.0, scans=None))[0] == 35


def test_increases_apply_at_once_and_decreases_wait_and_step() -> None:
    cfg = config()
    slew = DFC.Slew(duty=50)
    assert slew.next(52, cfg, failsafe=False) == 50  # below min_change_pct
    assert slew.next(60, cfg, failsafe=False) == 60
    assert [slew.next(40, cfg, failsafe=False) for _ in range(6)] == [60, 60, 55, 50, 45, 40]
    assert slew.next(37, cfg, failsafe=False) == 40  # within the step: hold
    assert slew.next(100, cfg, failsafe=False) == 100
    assert slew.next(35, cfg, failsafe=True) == 100
    # A target that bounces back up resets the hold.
    slew = DFC.Slew(duty=60)
    assert [slew.next(t, cfg, failsafe=False) for t in (50, 50, 58, 50, 50, 50)] == [60, 60, 60, 60, 60, 55]


def test_an_update_keeps_every_unmanaged_byte_and_reads_back(host: FakeHost) -> None:
    bmc = DFC.Bmc(host.runner(), sleep=lambda s: None)
    assert bmc.update("duty", dict.fromkeys((0, 1, 2), 0x40)) == (0x40, 0x40, 0x40, *DUTY0[3:])
    assert host.load()["duty"] == [0x40, 0x40, 0x40, *DUTY0[3:]]
    writes = host.bmc_writes()
    assert len(writes) == 1
    assert bmc.update("duty", dict.fromkeys((0, 1, 2), 0x40)) == tuple(host.load()["duty"])
    assert len(host.bmc_writes()) == 1  # nothing to change: no write


def test_a_byte_someone_else_changes_meanwhile_is_never_written_back(host: FakeHost) -> None:
    # Right after the first write another position is set to manual: the read-back
    # differs, and the retry reads again and keeps that change.
    host.update(drift_on_write={"kind": "mode", "position": 7, "value": 2})
    bmc = DFC.Bmc(host.runner(), sleep=lambda s: None)

    bmc.update("mode", dict.fromkeys((0, 1, 2), DFC.MANUAL))

    assert host.load()["mode"] == [2, 2, 2, 0, 0, 0, 0, 2, *[0] * 8]
    # The fresh read already shows the managed bytes taken: no second write over position 7.
    assert len(host.bmc_writes()) == 1


def test_a_retry_writes_the_fresh_bytes_not_the_first_vector(host: FakeHost) -> None:
    # The first write fails and someone else changes position 9 before the retry:
    # the retry is built from a fresh read and keeps that change.
    host.update(fail={"set_duty": 1})
    bmc = DFC.Bmc(host.runner(), sleep=lambda s: None)
    original = bmc.run

    def once(argv: Any, timeout: float) -> Any:
        result = original(argv, timeout)
        if argv[6:7] == ["0x0e"] and host.load().get("fail"):
            state = host.load()
            state["fail"] = {}
            state["duty"][9] = 0x55
            host.state = state
            host.save()
        return result

    bmc.run = once
    bmc.update("duty", dict.fromkeys((0, 1, 2), 0x40))

    duty_writes = [w for w in host.bmc_writes() if w[6] == "0x0e"]
    assert len(duty_writes) == 2
    assert duty_writes[1][7 + 9] == "0x55"
    assert host.load()["duty"] == [0x40, 0x40, 0x40, *DUTY0[3:9], 0x55, *DUTY0[10:]]


def test_malformed_updates_are_refused_before_any_command(host: FakeHost) -> None:
    bmc = DFC.Bmc(host.runner(), sleep=lambda s: None)
    for kind, changes in (("mode", {0: 3}), ("duty", {0: 101}), ("duty", {16: 50}), ("other", {0: 1})):
        with pytest.raises(DFC.BmcError):
            bmc.update(kind, changes)
    assert host.calls() == []


# -- parsers -------------------------------------------------------------------------


def test_bytes_ignore_noise_and_refuse_anything_else() -> None:
    assert DFC.parse_bytes(" 14 14 1e 1e 1e 1e 1e 1e 1e 1e 1e 1e 1e 1e 1e 1e\n") == tuple(DUTY0)
    noisy = "Received a response with unexpected ID 0 vs. 1\n 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00\n"
    assert DFC.parse_bytes(noisy) == tuple(MODE0)
    for bad in ("", " 00 00", " 00 " * 17, "zz " * 16, " 00" * 16 + "\n" + " 00" * 16):
        with pytest.raises(DFC.BmcError):
            DFC.parse_bytes(bad)


def test_fan_lines_and_no_reading() -> None:
    text = "FAN1_1           | 11h | lnc |  7.0 | 400 RPM\nFAN4_1           | 14h | ns  |  7.0 | No Reading\n"
    assert DFC.parse_fans(text) == {"FAN1_1": 400.0, "FAN4_1": None}


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ({"temperature": {"current": 41}}, ("temperature", 41.0)),
        (
            {"ata_smart_attributes": {"table": [{"id": 194, "raw": {"string": "43 (Min/Max 20/59)"}}]}},
            ("temperature", 43.0),
        ),
        ({"smartctl": {"messages": [{"string": "Device is in STANDBY mode, exit(2)"}]}}, ("standby", None)),
        ({"smartctl": {"messages": [{"string": "Device is in SLEEP mode, exit(2)"}]}}, ("standby", None)),
        ({"temperature": {"current": 0}}, ("error", None)),
        ({}, ("error", None)),
    ],
)
def test_smart_json(payload: dict[str, Any], expected: tuple[str, float | None]) -> None:
    assert DFC.parse_smart_temperature(json.dumps(payload)) == expected


def test_smart_garbage_is_an_error() -> None:
    assert DFC.parse_smart_temperature("not json") == ("error", None)


def test_scans() -> None:
    text = (
        "  pool: fast\n state: ONLINE\n  scan: scrub in progress since Mon Oct 19 02:26:33 2026\n"
        "  pool: tank\n state: ONLINE\n  scan: resilver in progress since Mon Oct 19 00:51:10 2026\n"
        "  pool: idle\n  scan: scrub paused since Mon Oct 19 00:51:10 2026\n"
    )
    assert DFC.parse_scans(text, ["fast", "tank", "idle"]) == {"fast": True, "tank": True, "idle": False}
    with pytest.raises(ValueError, match="missing"):
        DFC.parse_scans(text, ["missing"])


# -- readers -------------------------------------------------------------------------


def test_a_disk_in_standby_is_never_queried_further(host: FakeHost) -> None:
    drive = config().hdd[0]
    reading = DFC.read_hdd(drive, host.runner())

    assert reading.state == "standby"
    assert host.calls("smartctl") == []
    assert host.calls("hdparm") == [["hdparm", "-C", DEV_HDD1]]


def test_a_spinning_disk_is_read_with_n_standby(host: FakeHost) -> None:
    host.update(hdparm={DEV_HDD1: "active/idle", DEV_HDD2: "standby"})
    reading = DFC.read_hdd(config().hdd[0], host.runner())

    assert (reading.state, reading.celsius) == ("active", 41.0)
    assert host.calls("smartctl") == [["smartctl", "-n", "standby", "-d", "sat", "-A", "-j", DEV_HDD1]]


def test_a_disk_that_went_to_standby_in_between_is_standby(host: FakeHost) -> None:
    host.update(hdparm={DEV_HDD1: "active/idle", DEV_HDD2: "standby"}, smart={DEV_HDD1: "standby"})
    assert DFC.read_hdd(config().hdd[0], host.runner()).state == "standby"


@pytest.mark.parametrize(
    ("hdparm", "smart"),
    [({"rc": 5}, {"temp": 40}), ("unknown", {"temp": 40}), ("active/idle", "garbage")],
)
def test_reader_failures_are_errors(host: FakeHost, hdparm: Any, smart: Any) -> None:
    host.update(hdparm={DEV_HDD1: hdparm, DEV_HDD2: "standby"}, smart={DEV_HDD1: smart})
    assert DFC.read_hdd(config().hdd[0], host.runner()).state == "error"


def test_a_hanging_tool_times_out(host: FakeHost, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(DFC, "TIMEOUT_HDPARM", 0.3)
    host.update(sleep={"hdparm": 3})
    reading = DFC.read_hdd(config().hdd[0], host.runner())
    assert reading.state == "error"
    assert "timed out" in reading.error


def test_cpu_and_nvme_come_from_hwmon(host: FakeHost) -> None:
    cfg = config()
    assert DFC.read_cpu(cfg, host.paths) == 42.5
    assert DFC.read_nvme(cfg.nvme[0], host.paths) == 44.85


def test_an_implausible_hwmon_value_is_an_error(host: FakeHost) -> None:
    host.set_cpu(-200)
    with pytest.raises(ValueError, match="implausible"):
        DFC.read_cpu(config(), host.paths)


# -- observe mode ----------------------------------------------------------------------


def test_observe_never_writes_and_records_what_it_would_set(host: FakeHost, capsys: pytest.CaptureFixture[str]) -> None:
    code, _ = run(host, config(), 20)

    assert code == 0
    assert host.bmc_writes() == []
    assert host.load()["mode"] == MODE0
    assert host.load()["duty"] == DUTY0
    status = host.status()
    assert status["mode"] == "observe"
    assert status["bmc_control"] == 0
    assert status["bmc_writes"] == 0
    assert status["target_pct"] == 35
    # From 100 % at the start down to the target, 5 points a cycle after a 3-cycle hold.
    assert status["duty_pct"] == 35
    assert host.metric("duty_pct") == "35"
    assert host.metric("healthy") == "1"
    assert host.metric("failsafe") == "0"
    assert host.metric("managed_auto") == "1"
    assert host.metric("hdd_max_c") == "na"
    assert host.metric("hdd_active") == "0"
    assert host.metric("scan_active") == "0"
    assert "would set 100% (target 35%: floor)" in capsys.readouterr().err
    assert host.control()["control"] is False
    assert no_backslashes(host.calls())


def test_observe_reads_disks_only_every_hdd_interval(host: FakeHost) -> None:
    run(host, config(), 25)  # 25 cycles of 30 s: polls at 0, 300, 600 s

    assert len(host.calls("hdparm")) == 3 * 2
    assert host.calls("smartctl") == []


def test_spinning_disks_raise_the_would_be_duty(host: FakeHost) -> None:
    host.update(hdparm={DEV_HDD1: "active/idle", DEV_HDD2: "active/idle"})
    run(host, config(), 2)

    status = host.status()
    assert status["target_pct"] == 84
    assert status["duty_pct"] == 100
    assert host.metric("hdd_max_c") == "45.0"
    assert host.metric("hdd_active") == "2"
    assert host.bmc_writes() == []


def test_a_scrub_raises_the_target(host: FakeHost) -> None:
    host.update(zpool={"pools": {"tank": "scrub in progress since Mon Oct 19 00:51:10 2026", "fast": "none requested"}})
    run(host, config(), 1)

    assert host.status()["target_pct"] == 60
    assert host.metric("scan_active") == "1"


def test_a_failing_disk_read_is_retried_next_cycle_then_fails_safe(host: FakeHost) -> None:
    controller = host.controller(config())
    controller.step()
    host.clock.sleep(30)
    host.update(hdparm={DEV_HDD1: {"rc": 5}, DEV_HDD2: "standby"})
    controller.step()  # not due for 300 s: the failure is not seen yet
    assert len(host.calls("hdparm")) == 2
    host.clock.sleep(300)
    controller.step()
    first = host.status()
    host.clock.sleep(30)
    controller.step()
    second = host.status()

    assert first["failsafe"] == 0  # one failure is not yet a failsafe
    assert first["healthy"] == 1
    assert second["failsafe"] == 1
    assert second["target_pct"] == 100
    assert second["duty_pct"] == 100
    assert "failsafe: tank-hdd-1" in second["reasons"]
    assert host.metric("healthy") == "0"
    assert len(host.calls("hdparm")) == 2 + 2 + 2  # the retry polls the next cycle, not after 300 s


def test_a_missing_cpu_sensor_fails_safe(host: FakeHost) -> None:
    (host.root / "sys" / "class" / "hwmon" / "hwmon0" / "temp1_input").unlink()
    run(host, config(), 2)
    assert host.status()["failing"] == ["cpu"]
    assert host.status()["duty_pct"] == 100


def test_the_hwmon_values_are_read_after_the_slow_polls(host: FakeHost, monkeypatch: pytest.MonkeyPatch) -> None:
    host.update(hdparm={DEV_HDD1: "active/idle", DEV_HDD2: "active/idle"})
    controller = host.controller(config())
    runner = controller.run
    original = runner.__call__

    finished: list[tuple[str, float]] = []

    def slow(argv: Any, timeout: float) -> Any:
        result = original(argv, timeout)
        host.clock.now += 40  # every command takes 40 s
        finished.append((" ".join(argv[:4]), host.clock.now))
        return result

    monkeypatch.setattr(runner, "__call__", slow)
    controller.run = slow
    controller.bmc.run = slow
    read_at: list[float] = []
    original_cpu = DFC.read_cpu

    def read_cpu(cfg: Any, paths: Any) -> float:
        read_at.append(host.clock.now)
        return float(original_cpu(cfg, paths))

    monkeypatch.setattr(DFC, "read_cpu", read_cpu)

    controller.step()

    status = host.status()
    inputs = [at for command, at in finished if not command.startswith("ipmitool -I open raw")]
    assert len(inputs) == 1 + 4 + 1  # fans, two disks (hdparm, smartctl), zpool
    assert read_at == [max(inputs)]  # the CPU is read after every slow input
    assert controller.sources["cpu"].last_ok == max(inputs)
    assert status["failsafe"] == 0
    assert status["cpu_c"] == 42.5


def test_a_stale_input_fails_safe(host: FakeHost) -> None:
    controller = host.controller(config())
    controller.step()
    controller.sources["fast-nvme"].last_ok = host.clock.now - 1000
    controller.readings.nvme.clear()
    controller.clock = lambda: host.clock.now + 1  # time passes, the source is not read again
    assert "fast-nvme" in controller.failing_inputs(host.clock.now + 1)


# -- active mode ---------------------------------------------------------------------


def test_active_takes_only_the_managed_positions_at_full_duty_first(host: FakeHost) -> None:
    code, _ = run(host, config(mode="active"), 1)

    assert code == 0
    state = host.load()
    assert state["mode"][:3] == [2, 2, 2]
    assert state["mode"][3:] == MODE0[3:]
    assert state["duty"] == [100, 100, 100, *DUTY0[3:]]
    writes = host.bmc_writes()
    # Duty first (inactive while auto), then the mode; each read back.
    assert [w[6] for w in writes] == ["0x0e", "0x11"]
    assert writes[0][7:] == [f"0x{v:02x}" for v in [100, 100, 100, *DUTY0[3:]]]
    assert host.metric("bmc_control") == "1"
    assert host.control()["control"] is True


def test_active_steps_down_and_writes_each_step(host: FakeHost) -> None:
    run(host, config(mode="active"), 20)

    duties = [int(w[7], 16) for w in host.bmc_writes() if w[6] == "0x0e"]
    assert duties == [100, 95, 90, 85, 80, 75, 70, 65, 60, 55, 50, 45, 40, 35]
    assert host.load()["duty"][:3] == [35, 35, 35]
    assert host.load()["duty"][3:] == DUTY0[3:]


def test_a_stalled_fan_forces_full_duty(host: FakeHost) -> None:
    run(host, config(mode="active"), 20)
    host.update(manual_rpm={"FAN2_1": {"35": None}})
    controller = host.controller(config(mode="active"))
    controller.control = True
    controller.slew.duty = 35
    controller.step()
    assert host.status()["stalled"] == []
    controller.step()
    assert host.status()["stalled"] == ["FAN2_1"]
    assert host.load()["duty"][:3] == [100, 100, 100]


def test_unreadable_fans_force_full_duty_in_active_mode(host: FakeHost) -> None:
    host.update(fail={"sdr": 1})
    run(host, config(mode="active"), 3)
    assert "failsafe: fans" in host.status()["reasons"]
    assert host.load()["duty"][:3] == [100, 100, 100]


def test_a_write_that_does_not_read_back_restores_auto_and_exits(host: FakeHost) -> None:
    host.update(ignore_set=["mode"])
    code, _ = run(host, config(mode="active"), 1)

    assert code == DFC.EXIT_BMC
    mode_writes = [w for w in host.bmc_writes() if w[6] == "0x11"]
    # The manual write and its retry did not read back; the BMC never left auto,
    # so the restore finds nothing to write.
    assert [w[7:10] for w in mode_writes] == [["0x02"] * 3, ["0x02"] * 3]
    assert host.load()["mode"] == MODE0
    assert host.control()["control"] is False


def test_a_failing_duty_write_restores_auto(host: FakeHost) -> None:
    run(host, config(mode="active"), 2)
    host.update(fail={"set_duty": 1})
    controller = host.controller(config(mode="active"))
    controller.control = True
    controller.slew.duty = 100

    code = DFC._run(controller)

    assert code == DFC.EXIT_BMC
    assert host.load()["mode"] == MODE0
    assert host.control()["control"] is False


def test_protected_fans_not_in_auto_refuse_active_mode(host: FakeHost) -> None:
    host.update(mode=[0, 0, 0, 0, 0, 2, *[0] * 10])
    code, _ = run(host, config(mode="active"), 1)
    assert code == DFC.EXIT_CONFIG
    assert host.bmc_writes() == []


def test_managed_fans_put_back_to_manual_are_retaken(host: FakeHost) -> None:
    controller = host.controller(config(mode="active"))
    controller.take_control()
    host.update(mode=MODE0)
    controller.cycle = DFC.SUMMARY_EVERY
    controller.step()
    assert host.load()["mode"][:3] == [2, 2, 2]


# -- board identity --------------------------------------------------------------------


@pytest.mark.parametrize(
    "change",
    [
        lambda h: (h.root / "sys/class/dmi/id/board_name").write_text("OTHER\n"),
        lambda h: h.update(mc_info=h.load()["mc_info"].replace("6.09", "6.10")),
        lambda h: h.update(mc_info=h.load()["mc_info"].replace("8217 (0x2019)", "8218 (0x201a)")),
    ],
    ids=["board", "firmware", "product"],
)
def test_another_board_or_firmware_is_refused_without_a_write(host: FakeHost, change: Any) -> None:
    change(host)
    for mode in ("observe", "active"):
        code, _ = run(host, config(mode=mode), 1)
        assert code == DFC.EXIT_CONFIG
    assert host.bmc_writes() == []
    assert host.calls("hdparm") == []


def test_an_unreadable_bmc_identity_is_retried_not_refused(host: FakeHost) -> None:
    host.update(fail={"mc": 1})
    for mode in ("observe", "active"):
        code, _ = run(host, config(mode=mode), 1)
        assert code == DFC.EXIT_BMC
    assert host.bmc_writes() == []
    assert host.calls("hdparm") == []


# -- stop helper ---------------------------------------------------------------------


def test_stop_without_control_touches_nothing(host: FakeHost) -> None:
    run(host, config(), 2)
    calls = len(host.calls())
    for result in ("success", "watchdog", "exit-code", ""):
        assert DFC.cmd_stop_post(host.paths, host.runner(), result, sleep=lambda s: None) == 0
    assert len(host.calls()) == calls
    assert host.metric("healthy") == "0"


def test_a_clean_stop_restores_auto(host: FakeHost) -> None:
    host.update(mode=[0] * 7 + [2] + [0] * 8)  # an unmanaged position someone else set to manual
    run(host, config(mode="active", protected=[{"position": 5, "sensor": "FAN6_1"}]), 3)

    assert DFC.cmd_stop_post(host.paths, host.runner(), "success", sleep=lambda s: None) == 0

    assert host.load()["mode"] == [0] * 7 + [2] + [0] * 8
    assert host.control()["control"] is False
    assert host.metric("bmc_control") == "0"


@pytest.mark.parametrize("result", ["watchdog", "exit-code", "signal", "core-dump", "timeout", ""])
def test_any_other_stop_forces_full_duty(host: FakeHost, result: str) -> None:
    run(host, config(mode="active"), 20)

    assert DFC.cmd_stop_post(host.paths, host.runner(), result, sleep=lambda s: None) == 0

    state = host.load()
    assert state["mode"][:3] == [2, 2, 2]
    assert state["duty"] == [100, 100, 100, *DUTY0[3:]]
    assert host.metric("failsafe") == "1"
    assert host.control()["control"] is True


def test_when_full_duty_fails_the_stop_restores_auto(host: FakeHost) -> None:
    run(host, config(mode="active"), 20)  # down at the floor: 100 % needs a write
    host.update(fail={"set_duty": 1})

    assert DFC.cmd_stop_post(host.paths, host.runner(), "watchdog", sleep=lambda s: None) == 0

    assert host.load()["mode"] == MODE0
    assert host.control()["control"] is False


def test_the_stop_follows_the_runtime_state_not_the_config(host: FakeHost) -> None:
    run(host, config(mode="active"), 2)
    # The deploy already wrote an observe config; the stopping process still held the BMC.
    os.environ["SERVICE_RESULT"] = "success"
    try:
        assert DFC.main(["stop-post", "--config", "/nonexistent"], host.paths) == 0
    finally:
        del os.environ["SERVICE_RESULT"]
    assert host.load()["mode"] == MODE0


def test_observe_never_writes_fans_an_earlier_run_left_and_reports_them(host: FakeHost) -> None:
    run(host, config(mode="active"), 2)
    # The process died without its stop helper restoring the BMC.
    assert host.load()["mode"][:3] == [2, 2, 2]
    before = len(host.bmc_writes())

    code, _ = run(host, config(), 5)

    assert code == 0
    assert len(host.bmc_writes()) == before
    assert host.load()["mode"][:3] == [2, 2, 2]
    assert host.status()["leftover_control"] == [0, 1, 2]
    assert host.metric("healthy") == "0"
    assert host.control()["control"] is True  # still recorded: the clean stop releases them
    assert DFC.cmd_stop_post(host.paths, host.runner(), "success", sleep=lambda s: None) == 0
    assert host.load()["mode"] == MODE0


def test_observe_reports_managed_fans_someone_else_set_to_manual(host: FakeHost) -> None:
    host.update(mode=[2, 0, 0, *[0] * 13])
    run(host, config(), 2)

    assert host.bmc_writes() == []
    assert host.metric("managed_auto") == "0"
    assert host.metric("healthy") == "0"


def test_the_stop_helper_writes_nothing_on_another_board_or_firmware(host: FakeHost) -> None:
    run(host, config(mode="active"), 2)
    host.update(mc_info=host.load()["mc_info"].replace("6.09", "6.10"))
    before = len(host.bmc_writes())

    for result in ("success", "watchdog"):
        assert DFC.cmd_stop_post(host.paths, host.runner(), result, sleep=lambda s: None) == 1

    assert len(host.bmc_writes()) == before
    assert host.control()["control"] is True


def test_the_stop_helper_writes_nothing_without_a_recorded_identity(host: FakeHost) -> None:
    run(host, config(mode="active"), 2)
    state = host.control()
    state["identity"] = {}
    host.paths.control_file.write_text(json.dumps(state))
    before = len(host.bmc_writes())

    assert DFC.cmd_stop_post(host.paths, host.runner(), "success", sleep=lambda s: None) == 1
    assert len(host.bmc_writes()) == before


def test_a_start_on_another_firmware_leaves_held_fans_alone(host: FakeHost) -> None:
    run(host, config(mode="active"), 2)
    host.update(mc_info=host.load()["mc_info"].replace("6.09", "6.10"))
    before = len(host.bmc_writes())

    for mode in ("observe", "active"):
        code, _ = run(host, config(mode=mode), 1)
        assert code == DFC.EXIT_CONFIG

    assert len(host.bmc_writes()) == before


# -- calibration ---------------------------------------------------------------------


def calibrate_config(**changes: Any) -> Any:
    return config(mode="calibrate", calibration={**CALIBRATION, **changes})


def test_calibration_maps_measures_restores_and_runs_once(host: FakeHost) -> None:
    code, _ = run(host, calibrate_config(), 2)

    assert code == 0
    report = json.loads(host.paths.calibration_file.read_text())
    assert report["result"] == "ok"
    assert report["restored"] is True
    assert sorted(report["mapping"]) == ["0", "1", "2"]
    assert [step["duty_pct"] for step in report["steps"]] == [100, 50, 30]
    assert report["suggested_floor_pct"] == 30
    assert host.load()["mode"] == MODE0
    assert host.load()["duty"] == DUTY0
    assert host.control()["control"] is False
    writes = len(host.bmc_writes())

    run(host, calibrate_config(), 2)
    assert len(host.bmc_writes()) == writes  # the same id does not run again


def test_calibration_aborts_on_a_stall_and_restores(host: FakeHost) -> None:
    host.update(manual_rpm={"FAN3_1": {"30": 0}})
    code, _ = run(host, calibrate_config(), 1)

    report = json.loads(host.paths.calibration_file.read_text())
    assert code == 0
    assert report["result"] == "aborted"
    assert "FAN3_1" in report["reason"]
    assert report["suggested_floor_pct"] is None
    assert host.load()["mode"] == MODE0
    assert host.load()["duty"] == DUTY0


def test_calibration_aborts_when_another_fan_mode_changes(host: FakeHost) -> None:
    host.update(drift_mode_after_reads=4, drift_position=5)  # during the baseline samples
    run(host, calibrate_config(), 1)
    report = json.loads(host.paths.calibration_file.read_text())
    assert report["result"] == "aborted"
    assert "unmanaged" in report["reason"]


def test_calibration_aborts_when_the_wrong_fan_rises(host: FakeHost) -> None:
    host.update(positions={"FAN1_1": 1, "FAN2_1": 0, "FAN3_1": 2, "FAN6_1": 5})
    run(host, calibrate_config(), 1)
    report = json.loads(host.paths.calibration_file.read_text())
    assert report["result"] == "aborted"
    assert "did not raise FAN1_1" in report["reason"]
    assert host.load()["mode"] == MODE0


def run_with_hook(host: FakeHost, cfg: Any, cycles: int, hook: Any) -> tuple[int, Any]:
    """cmd_run like :func:`run`, calling ``hook(n)`` after the n-th BMC command."""

    controller = host.controller(cfg)
    original = controller.run
    count = [0]

    def counting(argv: Any, timeout: float) -> Any:
        result = original(argv, timeout)
        if argv[0] == "ipmitool":
            count[0] += 1
            hook(count[0])
        return result

    controller.run = counting
    controller.bmc.run = counting
    loop = controller.loop
    controller.loop = lambda count=None: loop(cycles)
    return DFC.cmd_run(cfg, host.paths, counting, controller), controller


def test_calibration_is_skipped_without_a_write_while_an_input_fails(host: FakeHost) -> None:
    cpu = host.root / "sys" / "class" / "hwmon" / "hwmon0" / "temp1_input"
    cpu.unlink()
    code, _ = run(host, calibrate_config(), 1)

    assert code == 0
    assert host.bmc_writes() == []
    report = json.loads(host.paths.calibration_file.read_text())
    assert report["result"] == "skipped"
    assert "cpu" in report["reason"]

    host.set_cpu(40.0)  # the next start runs the same id
    run(host, calibrate_config(), 1)
    assert json.loads(host.paths.calibration_file.read_text())["result"] == "ok"


def test_calibration_is_skipped_while_a_scrub_runs(host: FakeHost) -> None:
    host.update(zpool={"pools": {"tank": "scrub in progress since Mon Oct 19 00:51:10 2026", "fast": "none"}})
    run(host, calibrate_config(), 1)

    assert host.bmc_writes() == []
    assert "scrub" in json.loads(host.paths.calibration_file.read_text())["reason"]


def test_calibration_aborts_and_restores_when_a_drive_warms_up(host: FakeHost) -> None:
    def hook(n: int) -> None:
        if n == 30:
            host.set_nvme(70.0)  # the curves now ask for more than abort_target_pct

    code, _ = run_with_hook(host, calibrate_config(), 1, hook)

    assert code == 0
    report = json.loads(host.paths.calibration_file.read_text())
    assert report["result"] == "aborted"
    assert "the curves ask for" in report["reason"]
    assert report["restored"] is True
    assert host.load()["mode"] == MODE0
    assert host.load()["duty"] == DUTY0


def test_calibration_aborts_and_restores_when_an_input_fails_meanwhile(host: FakeHost) -> None:
    def hook(n: int) -> None:
        cpu = host.root / "sys" / "class" / "hwmon" / "hwmon0" / "temp1_input"
        if n == 30 and cpu.exists():
            cpu.unlink()

    run_with_hook(host, calibrate_config(), 1, hook)

    report = json.loads(host.paths.calibration_file.read_text())
    assert report["result"] == "aborted"
    assert "required inputs failing: cpu" in report["reason"]
    assert host.load()["mode"] == MODE0
    assert host.load()["duty"] == DUTY0


# -- entry point and systemd ---------------------------------------------------------


def test_check_config(host: FakeHost, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    good = tmp_path / "good.json"
    good.write_text(json.dumps(config_dict()))
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(config_dict(floor_pct=10)))
    assert DFC.main(["check-config", "--config", str(good)], host.paths) == 0
    assert DFC.main(["check-config", "--config", str(bad)], host.paths) == DFC.EXIT_CONFIG
    assert DFC.main(["run", "--config", str(bad)], host.paths) == DFC.EXIT_CONFIG


@pytest.fixture
def notify_socket(monkeypatch: pytest.MonkeyPatch) -> Iterator[socket.socket]:
    folder = tempfile.mkdtemp(prefix="dfc")
    path = os.path.join(folder, "n")
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    sock.bind(path)
    sock.settimeout(0.1)
    monkeypatch.setenv("NOTIFY_SOCKET", path)
    yield sock
    sock.close()
    os.unlink(path)
    os.rmdir(folder)


def test_ready_and_watchdog_reach_systemd(host: FakeHost, notify_socket: socket.socket) -> None:
    run(host, config(), 2)
    messages = []
    try:
        while True:
            messages.append(notify_socket.recv(4096).decode())
    except TimeoutError:
        pass
    assert "READY=1" in messages
    assert any(m.startswith("WATCHDOG=1") for m in messages)
    assert "STOPPING=1" in messages


def test_every_command_is_an_argv_without_backslashes(host: FakeHost) -> None:
    host.update(hdparm={DEV_HDD1: "active/idle", DEV_HDD2: "active/idle"})
    run(host, config(mode="active"), 3)
    DFC.cmd_stop_post(host.paths, host.runner(), "success", sleep=lambda s: None)
    assert host.calls()
    assert no_backslashes(host.calls())
    assert DFC.__file__
    source = Path(DFC.__file__).read_text()
    assert "shell=True" not in source
    assert "os.system" not in source
