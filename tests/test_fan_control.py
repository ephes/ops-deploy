"""thermal_monitoring's ``fan_control``: config, the controller's JSON, the identity guard and the deploy's plans."""

from __future__ import annotations

import json
import subprocess
from typing import Any

import pytest

from ops_deploy.core import ConfigValidationError
from ops_deploy.helpers.probes import FAILED, probe_command
from ops_deploy.services.thermal_monitoring import (
    FAN_CONTROL_METRICS,
    FAN_CONTROL_METRICS_DIR,
    ThermalMonitoringConfig,
    deploy_thermal_monitoring,
)
from ops_deploy.services.thermal_monitoring import fan_control as fc_module
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests import fakehost
from tests.drive_fan_control_fixtures import CALIBRATION, DFC, MC_INFO, config_dict
from tests.test_thermal_monitoring import CFG, SECRETS, converged

P = "Thermal monitoring | "
SERVICE = "drive-fan-control.service"
SCRIPT = "/usr/local/libexec/drive-fan-control/drive_fan_control.py"
CONFIG = "/etc/drive-fan-control/config.json"
UNIT = f"/etc/systemd/system/{SERVICE}"


def fan_control(**changes: Any) -> dict[str, Any]:
    """The deploy's ``fan_control`` block for the controller config of the fixtures."""

    data = config_dict()
    for key in ("version", "decrease_step_pct", "decrease_hold_cycles", "min_change_pct", "failure_cycles"):
        data.pop(key)
    data.pop("stall_cycles")
    data.update(changes)
    return data


def make_cfg(**changes: Any) -> ThermalMonitoringConfig:
    return ThermalMonitoringConfig.model_validate({**CFG.model_dump(), "fan_control": fan_control(**changes)})


FC_CFG = make_cfg()


def identity(*, vendor: str = "ExampleRack", board: str = "EX650D4U", mc: str = MC_INFO, mode: str = "") -> list[str]:
    mode = mode or " " + " ".join(["00"] * 16)
    return ["@dmi", vendor, board, "@mc", *mc.splitlines(), "@mode", mode]


PROBE = probe_command(fc_module.identity_probe_command())


def fc_converged(cfg: ThermalMonitoringConfig = FC_CFG, **extra: Any) -> dict[str, Any]:
    fc = cfg.fan_control
    assert fc is not None
    return {
        **converged(cfg),
        PROBE: identity(),
        **fakehost.deb_installed("python3", "apache2-utils", *fc.packages),
        **fakehost.directory("/usr/local/libexec/drive-fan-control"),
        **fakehost.directory("/etc/drive-fan-control"),
        **fakehost.file(SCRIPT, fc_module.SCRIPT_SOURCE.read_text(), mode="-rwxr-xr-x"),
        **fakehost.file(CONFIG, fc_module.render_config(fc)),
        **fakehost.file(UNIT, fc_module.render_unit()),
        **fakehost.service(SERVICE),
        **extra,
    }


def run(responses: dict[str, Any], cfg: ThermalMonitoringConfig = FC_CFG, *, ok: bool = True) -> FakeRun:
    result = run_deploy_fake(deploy_thermal_monitoring, cfg, SECRETS, responses=responses)
    assert result.succeeded is ok, result.error
    return result


# -- config --------------------------------------------------------------------------


def test_the_controller_parses_what_the_deploy_writes() -> None:
    fc = FC_CFG.fan_control
    assert fc is not None
    parsed = DFC.parse_config(json.loads(fc_module.render_config(fc)))
    assert parsed.mode == "observe"
    assert parsed.managed_positions == (0, 1, 2)
    assert parsed == DFC.parse_config(config_dict())
    calibrating = make_cfg(mode="calibrate", calibration=CALIBRATION).fan_control
    assert calibrating is not None
    assert DFC.parse_config(json.loads(fc_module.render_config(calibrating))).calibration.id == "first"


def test_without_fan_control_nothing_changes_in_the_config() -> None:
    assert CFG.fan_control is None
    assert "fan_control" not in CFG.model_dump(exclude_none=True)


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"floor_pct": 24}, "floor_pct"),
        ({"protected": [{"position": 0, "sensor": "FAN6_1"}]}, "never both managed and protected"),
        ({"protected": []}, "protected"),
        ({"managed": []}, "managed"),
        (
            {"curves": {"hdd": [[36, 35], [47, 101]], "nvme": [[48, 35], [72, 100]], "cpu": [[60, 35], [85, 100]]}},
            "less_than_equal",
        ),
        (
            {"curves": {"hdd": [[47, 35], [36, 50]], "nvme": [[48, 35], [72, 100]], "cpu": [[60, 35], [85, 100]]}},
            "increase",
        ),
        ({"mode": "calibrate"}, "calibration block"),
        ({"mode": "manual"}, "mode"),
        ({"hdd": [{"name": "x", "device": "/srv/disk"}]}, "device"),
        ({"hdd": [{"name": "fans", "device": "/dev/sda"}]}, "must not be"),
        ({"board": {**config_dict()["board"], "bmc_firmware": []}}, "bmc_firmware"),
        ({"extra": 1}, "extra"),
        ({"interval_s": 300}, "interval_s"),
        ({"hdd_interval_s": 20}, "hdd_interval_s"),
    ],
)
def test_bad_fan_control_is_refused(changes: dict[str, Any], message: str) -> None:
    with pytest.raises(ConfigValidationError, match=message):
        make_cfg(**changes)


def test_the_metric_names_are_the_controllers() -> None:
    assert FAN_CONTROL_METRICS == DFC.METRICS
    assert str(FAN_CONTROL_METRICS_DIR) == str(DFC.Paths().metrics_dir)


def test_the_unit_runs_the_installed_script_with_its_config() -> None:
    unit = fc_module.render_unit()
    assert f"ExecStart=/usr/bin/python3 -I -B {SCRIPT} run --config {CONFIG}\n" in unit
    assert f"ExecStopPost=/usr/bin/python3 -I -B {SCRIPT} stop-post --config {CONFIG}\n" in unit
    for line in ("Type=notify", "WatchdogSec=90", "Restart=always", "RestartPreventExitStatus=78"):
        assert f"\n{line}\n" in unit
    assert f"RestartPreventExitStatus={DFC.EXIT_CONFIG}" in unit


# -- identity guard ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("answer", "message"),
    [
        (identity(board="OTHER"), "DMI board"),
        (identity(vendor="Other"), "DMI board"),
        (identity(mc=MC_INFO.replace("6.09", "6.10")), "firmware"),
        (identity(mc=MC_INFO.replace("8217 (0x2019)", "1 (0x1)")), "manufacturer/product"),
        (identity(mc=MC_INFO.replace("49622", "1")), "manufacturer/product"),
        (identity(mode=" 00 00 00 00 00 02 00 00 00 00 00 00 00 00 00 00"), "positions \\[5\\]"),
        (identity(mode=" 00 00"), "unreadable"),
        (["@dmi", "x"], "every section"),
        ([FAILED], "cannot read"),
    ],
)
def test_the_deploy_refuses_another_board_or_busy_fans_before_any_operation(answer: list[str], message: str) -> None:
    result = run(fc_converged(FC_CFG, **{PROBE: answer}), ok=False)

    assert result.ops == []
    assert message.replace("\\", "").split("[")[0] in str(result.error)


def test_managed_fans_in_manual_mode_are_the_controllers() -> None:
    answer = identity(mode=" 02 02 02 00 00 00 00 00 00 00 00 00 00 00 00 00")
    assert run(fc_converged(FC_CFG, **{PROBE: answer})).mutating_changed_ops == []


# -- plans ---------------------------------------------------------------------------


def test_a_converged_host_plans_only_read_only_checks() -> None:
    result = run(fc_converged())

    assert result.mutating_changed_ops == []
    assert f"{P}Require {SERVICE} in observe mode" in [op.name for op in result.ops if op.changed]
    assert result.op(f"{P}Require {SERVICE} in observe mode").read_only
    assert not any("0x11" in c or "0x0e" in c for c in result.executed_commands + result.fact_commands)


def test_a_fresh_host_installs_the_controller_and_starts_it() -> None:
    responses = {**converged(FC_CFG), PROBE: identity(), **fakehost.deb_installed("python3", "apache2-utils")}

    result = run(responses)

    assert result.mutating_changed_ops == [
        f"{P}Install the fan control packages",
        f"{P}Ensure /usr/local/libexec/drive-fan-control",
        f"{P}Ensure /etc/drive-fan-control",
        f"{P}Install {SCRIPT}",
        f"{P}Install {CONFIG}",
        f"{P}Install systemd unit {SERVICE}",
        f"{P}Reload systemd for {SERVICE}",
        f"{P}Enable {SERVICE}",
        f"{P}Start {SERVICE}",
    ]
    assert result.upload(SCRIPT) == fc_module.SCRIPT_SOURCE.read_bytes()
    assert json.loads(result.upload(CONFIG)) == FC_CFG.fan_control.controller_config()  # type: ignore[union-attr]
    assert result.upload(UNIT).decode() == fc_module.render_unit()
    assert not any(c.startswith("systemctl restart") for c in result.executed_commands)
    # The thermal part is untouched by the fan control block.
    assert not any(name.startswith((f"{P}Install /usr/local/bin", f"{P}Write")) for name in result.mutating_changed_ops)
    assert not any("0x11" in c or "0x0e" in c for c in result.executed_commands)


def test_a_new_mode_rewrites_the_config_and_restarts_the_controller() -> None:
    active = make_cfg(mode="active")

    result = run(fc_converged(FC_CFG), active)

    assert result.mutating_changed_ops == [f"{P}Install {CONFIG}", f"{P}Restart {SERVICE}"]
    assert f"{P}Require {SERVICE} in active mode" in [op.name for op in result.ops]
    assert json.loads(result.upload(CONFIG))["mode"] == "active"


def test_a_changed_script_restarts_the_controller() -> None:
    responses = fc_converged(**fakehost.file(SCRIPT, "#!/usr/bin/python3\n", mode="-rwxr-xr-x"))

    result = run(responses)

    assert result.mutating_changed_ops == [f"{P}Install {SCRIPT}", f"{P}Restart {SERVICE}"]


def test_a_changed_unit_reloads_and_restarts_the_controller() -> None:
    result = run(fc_converged(**fakehost.file(UNIT, "[Service]\n")))

    assert result.mutating_changed_ops == [
        f"{P}Install systemd unit {SERVICE}",
        f"{P}Reload systemd for {SERVICE}",
        f"{P}Restart {SERVICE}",
    ]


def test_a_stopped_controller_is_started_without_a_restart() -> None:
    result = run(fc_converged(**fakehost.service(SERVICE, running=False)))

    assert result.mutating_changed_ops == [f"{P}Start {SERVICE}"]


def test_disabled_stops_and_disables_the_service_without_touching_the_bmc() -> None:
    disabled = make_cfg(enabled=False)

    result = run(fc_converged(disabled), disabled)

    assert result.mutating_changed_ops == [f"{P}Stop and disable {SERVICE}"]
    assert "systemctl stop drive-fan-control.service" in result.executed_commands
    assert not any("ipmitool" in c for c in result.executed_commands + result.fact_commands)
    assert not any(SCRIPT in path or CONFIG in path for path in result.uploaded_paths)


def test_disabled_is_a_no_op_when_the_service_is_gone() -> None:
    disabled = make_cfg(enabled=False)
    responses = {**fc_converged(disabled), **fakehost.service(SERVICE, running=False, enabled=False)}

    assert run(responses, disabled).mutating_changed_ops == []


def test_the_verification_fails_when_the_service_reports_nothing_of_its_own() -> None:
    check = fc_module.verify_command(FC_CFG.fan_control)  # type: ignore[arg-type]
    result = run({**fc_converged(), check: {"success": False}}, ok=False)

    assert result.op(f"{P}Require {SERVICE} in observe mode").succeeded is False


def test_the_verification_reads_the_status_of_this_process_and_mode() -> None:
    fc = FC_CFG.fan_control
    assert fc is not None
    command = fc_module.verify_command(fc)
    assert "systemctl show -p MainPID --value drive-fan-control.service" in command
    assert "/run/drive-fan-control/status.json" in command
    assert '"$pid" observe 0' in command
    assert "\\" not in command
    calibrate = make_cfg(mode="calibrate", calibration=CALIBRATION).fan_control
    assert calibrate is not None
    assert fc_module.verify_command(calibrate).startswith("systemctl is-active --quiet")


@pytest.mark.parametrize(
    ("status", "mode", "bmc", "ok"),
    [
        ({"pid": 4242, "mode": "observe", "bmc_control": 0, "healthy": 1}, "observe", 0, True),
        ({"pid": 4241, "mode": "observe", "bmc_control": 0, "healthy": 1}, "observe", 0, False),
        ({"pid": 4242, "mode": "active", "bmc_control": 0, "healthy": 1}, "observe", 0, False),
        ({"pid": 4242, "mode": "observe", "bmc_control": 1, "healthy": 1}, "observe", 0, False),
        ({"pid": 4242, "mode": "observe", "bmc_control": 0, "healthy": 0}, "observe", 0, False),
        ({"pid": 4242, "mode": "active", "bmc_control": 1, "healthy": 1}, "active", 1, True),
    ],
)
def test_the_status_check_itself(status: dict[str, Any], mode: str, bmc: int, ok: bool) -> None:
    fc = make_cfg(mode=mode).fan_control
    assert fc is not None
    script = fc_module.verify_command(fc)
    check = script.split("python3 -I -c ", 1)[1].split(' "$pid"', 1)[0]
    code = subprocess.run(
        ["sh", "-c", f"python3 -I -c {check} 4242 {mode} {bmc}"],
        input=json.dumps(status),
        text=True,
        capture_output=True,
        check=False,
    ).returncode
    assert (code == 0) is ok


def test_every_command_is_valid_shell() -> None:
    responses = {**converged(FC_CFG), PROBE: identity(), **fakehost.deb_installed("python3", "apache2-utils")}
    result = run(responses)
    for command in result.executed_commands + result.fact_commands:
        checked = subprocess.run(["sh", "-n", "-c", command], capture_output=True, text=True, check=False)
        assert checked.returncode == 0, checked.stderr
