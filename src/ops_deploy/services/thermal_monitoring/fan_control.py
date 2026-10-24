"""Optional drive-aware case-fan control for ``thermal_monitoring`` (the ``fan_control`` block).

The BMC of some server boards drives the case fans from a CPU-derived index
only and never sees drive temperatures. ``fan_control`` installs a small
controller service, ``drive-fan-control``, that reads the drives itself and
sets the duty of the configured case-fan positions through the BMC
(``files/drive_fan_control.py``, standard library only, its docstring lists
the behaviour). Without the block nothing here runs: the thermal deploy plans
exactly what it planned before (``tests/test_thermal_monitoring_golden.py``).

The deploy never writes the BMC itself; the service owns every write. While
planning, a read-only probe reads the DMI board, ``ipmitool mc info`` and the
vendor GET of the fan mode bytes; the deploy refuses unless the board and the
BMC identity and firmware are the configured ones and every position the
controller does not manage is in BMC auto mode. The controller's
configuration is checked here with the controller's own parser before it is
written, so the host never gets one the service would refuse.
"""

from __future__ import annotations

import importlib.util
import itertools
import json
import shlex
import sys
from functools import cache
from io import StringIO
from pathlib import Path, PurePosixPath
from types import ModuleType
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictFloat, StrictInt, model_validator
from pyinfra.api import DeployError
from pyinfra.api.operation import OperationMeta
from pyinfra.operations import apt, files, server, systemd

from ops_deploy.helpers import mark_read_only, service_rollout, systemd_unit
from ops_deploy.helpers.probes import probe

SCRIPT_SOURCE = Path(__file__).parent / "files" / "drive_fan_control.py"
SERVICE = "drive-fan-control.service"
LIBEXEC = PurePosixPath("/usr/local/libexec/drive-fan-control")
SCRIPT_PATH = LIBEXEC / "drive_fan_control.py"
CONFIG_DIR = PurePosixPath("/etc/drive-fan-control")
CONFIG_PATH = CONFIG_DIR / "config.json"
RUN_DIR = PurePosixPath("/run/drive-fan-control")
METRICS_DIR = RUN_DIR / "metrics"
STATUS_PATH = RUN_DIR / "status.json"
# The numeric files the controller keeps in METRICS_DIR (one value each, "na" when unknown);
# a thermal exporter ``sysfs_sensors`` entry can serve any of them.
METRICS = (
    "duty_pct",
    "target_pct",
    "healthy",
    "failsafe",
    "bmc_control",
    "managed_auto",
    "hdd_max_c",
    "hdd_active",
    "scan_active",
)
POSITIONS = 16
DMI = PurePosixPath("/sys/class/dmi/id")
IPMITOOL = ("ipmitool", "-I", "open")
GET_MODE = ("raw", "0x3a", "0xd0", "0x12")
# How long the deploy waits for the started service to report its first cycle.
VERIFY_TRIES = 45
VERIFY_DELAY = 2

Percent = Annotated[StrictInt, Field(ge=0, le=100)]
Name = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:@+-]{0,63}$")]
Sensor = Annotated[str, Field(pattern=r"^[A-Za-z0-9_]{1,32}$")]
Device = Annotated[str, Field(pattern=r"^/dev/[A-Za-z0-9_.:/+@-]{1,240}$")]
Pool = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")]
Text = Annotated[str, Field(pattern=r"^[!-~](?:[ -~]{0,62}[!-~])?$")]
Package = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9+.-]*$")]
Temperature = Annotated[StrictInt | StrictFloat, Field(ge=-20, le=120)]


class _Part(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, validate_default=True, hide_input_in_errors=True)


class FanPosition(_Part):
    """One of the BMC's 16 fan positions (0 = FAN1) and the ``ipmitool sdr`` sensor of its fan."""

    position: Annotated[StrictInt, Field(ge=0, le=POSITIONS - 1)]
    sensor: Sensor


class Board(_Part):
    """The board and BMC the fan commands are known to be right for."""

    dmi_board_vendor: Text
    dmi_board_name: Text
    bmc_manufacturer_id: Annotated[StrictInt, Field(ge=0, le=0xFFFFFF)]
    bmc_product_id: Annotated[StrictInt, Field(ge=0, le=0xFFFF)]
    bmc_firmware: tuple[Annotated[str, Field(pattern=r"^[0-9A-Za-z.]{1,16}$")], ...] = Field(min_length=1)


class HwmonSensor(_Part):
    hwmon_name: Name
    label: Name


class NvmeDrive(_Part):
    name: Name
    device: Device


class HddDrive(_Part):
    name: Name
    device: Device
    smart_type: Literal["sat", "ata", "auto"] = "sat"


class ScanPool(_Part):
    """A ZFS pool whose running scrub or resilver raises the duty to at least ``min_pct``."""

    pool: Pool
    min_pct: Percent


Curve = tuple[tuple[Temperature, Percent], ...]


class Curves(_Part):
    """Piecewise linear (temperature °C, duty %) points: below the first point its duty, above the last its duty."""

    hdd: Curve
    nvme: Curve
    cpu: Curve

    @model_validator(mode="after")
    def _monotonic(self) -> Curves:
        for name in ("hdd", "nvme", "cpu"):
            points = getattr(self, name)
            if len(points) < 2:
                raise ValueError(f"curves.{name} needs at least two points")
            for (t0, d0), (t1, d1) in itertools.pairwise(points):
                if t1 <= t0 or d1 < d0:
                    raise ValueError(f"curves.{name}: temperatures must increase and duties must not decrease")
        return self


class Calibration(_Part):
    """``mode: calibrate`` runs once per ``id``: header mapping, duty staircase, BMC restored."""

    id: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")]
    mapping_hold_s: Annotated[StrictInt, Field(ge=10, le=300)] = 60
    steps_pct: tuple[Annotated[StrictInt, Field(ge=25, le=100)], ...] = (100, 70, 50, 40, 35, 30)
    step_hold_s: Annotated[StrictInt, Field(ge=10, le=600)] = 90
    sample_interval_s: Annotated[StrictInt, Field(ge=1, le=30)] = 5
    settle_s: Annotated[StrictInt, Field(ge=0, le=120)] = 20
    tach_step_rpm: Annotated[StrictInt, Field(ge=1, le=2000)] = 400
    oscillation_steps: Annotated[StrictInt, Field(ge=1, le=10)] = 2
    min_rpm: Annotated[StrictInt, Field(ge=0, le=10000)] = 600
    # Abort (BMC restored) as soon as the curves ask for this duty or a scrub/resilver runs.
    abort_target_pct: Annotated[StrictInt, Field(ge=25, le=100)] = 60


class FanControl(_Part):
    """The controller's settings (``docs/services/thermal_monitoring.md``, "fan_control")."""

    # False: the service is stopped and disabled (its clean stop restores BMC auto); files stay.
    enabled: bool = True
    mode: Literal["observe", "calibrate", "active"] = "observe"
    backend: Literal["asrock_rack_ast2600"] = "asrock_rack_ast2600"
    board: Board
    managed: tuple[FanPosition, ...] = Field(min_length=1)
    protected: tuple[FanPosition, ...] = Field(min_length=1)
    floor_pct: Annotated[StrictInt, Field(ge=25, le=100)] = 35
    interval_s: Annotated[StrictInt, Field(ge=10, le=60)] = 30
    hdd_interval_s: Annotated[StrictInt, Field(ge=10, le=3600)] = 300
    cpu: HwmonSensor
    nvme: tuple[NvmeDrive, ...] = ()
    hdd: tuple[HddDrive, ...] = ()
    scan_pools: tuple[ScanPool, ...] = ()
    curves: Curves
    decrease_step_pct: Annotated[StrictInt, Field(ge=1, le=25)] = 5
    decrease_hold_cycles: Annotated[StrictInt, Field(ge=1, le=20)] = 3
    min_change_pct: Annotated[StrictInt, Field(ge=1, le=10)] = 3
    failure_cycles: Annotated[StrictInt, Field(ge=1, le=10)] = 2
    stall_cycles: Annotated[StrictInt, Field(ge=1, le=10)] = 2
    calibration: Calibration | None = None
    packages: tuple[Package, ...] = ("ipmitool", "smartmontools", "hdparm")

    @model_validator(mode="after")
    def _the_controller_accepts_it(self) -> FanControl:
        # The host script's own parser: what it would refuse at start is refused here.
        controller = controller_module()
        try:
            controller.parse_config(self.controller_config())
        except controller.ConfigError as exc:
            raise ValueError(f"fan_control: {exc}") from None
        return self

    @property
    def managed_positions(self) -> tuple[int, ...]:
        return tuple(p.position for p in self.managed)

    def controller_config(self) -> dict[str, Any]:
        """The JSON the controller reads (``/etc/drive-fan-control/config.json``)."""

        data: dict[str, Any] = {
            "version": 1,
            "mode": self.mode,
            "backend": self.backend,
            "board": {**self.board.model_dump(), "bmc_firmware": list(self.board.bmc_firmware)},
            "managed": [p.model_dump() for p in self.managed],
            "protected": [p.model_dump() for p in self.protected],
            "floor_pct": self.floor_pct,
            "interval_s": self.interval_s,
            "hdd_interval_s": self.hdd_interval_s,
            "cpu": self.cpu.model_dump(),
            "nvme": [d.model_dump() for d in self.nvme],
            "hdd": [d.model_dump() for d in self.hdd],
            "scan_pools": [p.model_dump() for p in self.scan_pools],
            "curves": {name: [list(point) for point in getattr(self.curves, name)] for name in ("hdd", "nvme", "cpu")},
            "decrease_step_pct": self.decrease_step_pct,
            "decrease_hold_cycles": self.decrease_hold_cycles,
            "min_change_pct": self.min_change_pct,
            "failure_cycles": self.failure_cycles,
            "stall_cycles": self.stall_cycles,
        }
        if self.calibration is not None:
            data["calibration"] = {**self.calibration.model_dump(), "steps_pct": list(self.calibration.steps_pct)}
        return data


@cache
def controller_module() -> ModuleType:
    """``files/drive_fan_control.py`` loaded as a module (standard library only, no side effects)."""

    spec = importlib.util.spec_from_file_location("ops_deploy_drive_fan_control", SCRIPT_SOURCE)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {SCRIPT_SOURCE}")
    module = importlib.util.module_from_spec(spec)
    # dataclasses resolve string annotations through sys.modules while the module executes.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def render_config(fc: FanControl) -> str:
    return json.dumps(fc.controller_config(), indent=1, sort_keys=True) + "\n"


def render_unit() -> str:
    script = shlex.join(["/usr/bin/python3", "-I", "-B", str(SCRIPT_PATH)])
    config = shlex.join(["--config", str(CONFIG_PATH)])
    return f"""[Unit]
Description=Drive-aware case fan control through the BMC (ops-deploy thermal_monitoring fan_control)
After=local-fs.target
# Five failed starts in 30 minutes leave it failed (and the fans as its stop left them).
StartLimitIntervalSec=1800
StartLimitBurst=5

[Service]
Type=notify
NotifyAccess=main
ExecStart={script} run {config}
# Restores BMC auto after a clean stop, sets the managed fans to 100 % after anything else;
# acts only while the controller holds the BMC (its runtime state, not this unit's mode).
ExecStopPost={script} stop-post {config}
WatchdogSec=90
Restart=always
RestartSec=15
# 78: wrong board, firmware or configuration; nothing was written to the BMC.
RestartPreventExitStatus=78
TimeoutStartSec=120
# The stop helper's worst case: identity read, then up to two read-modify-write
# attempts of each vector (5 s per vendor command) and the fallback to auto.
TimeoutStopSec=180
RuntimeDirectory=drive-fan-control
RuntimeDirectoryMode=0755
RuntimeDirectoryPreserve=yes
StateDirectory=drive-fan-control
StateDirectoryMode=0750
UMask=0022
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ProtectControlGroups=yes
ProtectKernelModules=yes
ProtectHostname=yes
RestrictRealtime=yes
LockPersonality=yes
RestrictAddressFamilies=AF_UNIX AF_NETLINK

[Install]
WantedBy=multi-user.target
"""


# The probe prints marked sections; the deploy parses them on the controller.
_PROBE_SECTIONS = ("dmi", "mc", "mode")


def identity_probe_command() -> str:
    """Read-only: DMI board vendor and name, ``ipmitool mc info`` and the fan mode bytes (vendor GET)."""

    dmi = shlex.join(["cat", str(DMI / "board_vendor"), str(DMI / "board_name")])
    mc = shlex.join([*IPMITOOL, "mc", "info"])
    mode = shlex.join([*IPMITOOL, *GET_MODE])
    return f"echo @dmi && {dmi} && echo @mc && {mc} && echo @mode && {mode}"


def parse_identity_probe(output: str) -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {}
    current: list[str] | None = None
    for line in output.splitlines():
        if line.startswith("@") and line[1:] in _PROBE_SECTIONS:
            current = sections.setdefault(line[1:], [])
        elif current is not None:
            current.append(line)
    if set(sections) != set(_PROBE_SECTIONS):
        raise ValueError("the identity probe did not print every section")
    return sections


def check_identity(fc: FanControl, output: str) -> list[str]:
    """Why the probed board, BMC or fan modes rule this configuration out (empty: fine)."""

    controller = controller_module()
    try:
        sections = parse_identity_probe(output)
    except ValueError as exc:
        return [str(exc)]
    problems = []
    dmi = [line.strip() for line in sections["dmi"]]
    if dmi[:2] != [fc.board.dmi_board_vendor, fc.board.dmi_board_name] or len(dmi) != 2:
        wanted = f"{fc.board.dmi_board_vendor} {fc.board.dmi_board_name}"
        problems.append(f"the DMI board is {' '.join(dmi)!r}, not {wanted!r}")
    info = controller.parse_mc_info("\n".join(sections["mc"]))
    product = info.get("Product ID", "").split()
    firmware = info.get("Firmware Revision", "")
    identity = (info.get("Manufacturer ID", ""), product[0] if product else "")
    if identity != (str(fc.board.bmc_manufacturer_id), str(fc.board.bmc_product_id)):
        problems.append(f"the BMC manufacturer/product is {identity}, not the configured one")
    if firmware not in fc.board.bmc_firmware:
        problems.append(f"the BMC firmware {firmware!r} is not in {list(fc.board.bmc_firmware)}")
    try:
        mode = controller.parse_bytes("\n".join(sections["mode"]))
    except controller.BmcError as exc:
        problems.append(f"the fan mode bytes are unreadable: {exc}")
    else:
        others = [i for i in range(POSITIONS) if i not in fc.managed_positions and mode[i] != 0]
        if others:
            problems.append(f"fan positions {others} that the controller does not manage are not in BMC auto mode")
    return problems


def verify_command(fc: FanControl) -> str:
    """Read-only: the running service reports a healthy cycle of its own (this PID) in the configured mode.

    Healthy: every required input read and, in ``active`` mode, every managed
    fan turning. ``calibrate`` reports its first cycle only after the
    calibration, so there it is enough that the unit is active.
    """

    service = shlex.quote(SERVICE)
    if fc.mode == "calibrate":
        return f"systemctl is-active --quiet {service} || {{ systemctl status --no-pager {service} >&2; exit 1; }}"
    expect = 1 if fc.mode == "active" else 0
    check = (
        "import json,sys; s=json.load(sys.stdin); "
        "sys.exit(0 if s.get('pid')==int(sys.argv[1]) and s.get('mode')==sys.argv[2] "
        "and s.get('bmc_control')==int(sys.argv[3]) and s.get('healthy')==1 else 1)"
    ).replace("'", '"')
    status = shlex.quote(str(STATUS_PATH))
    reading = f'python3 -I -c {shlex.quote(check)} "$pid" {shlex.quote(fc.mode)} {expect} < {status}'
    failure = shlex.quote(f"{SERVICE} reports no healthy {fc.mode} cycle of its own")
    return (
        "i=0; while :; do "
        f"pid=$(systemctl show -p MainPID --value {service}); "
        f'if [ "$pid" != 0 ] && [ -f {status} ] && {reading}; then exit 0; fi; '
        f'i=$((i + 1)); [ "$i" -ge {VERIFY_TRIES} ] && break; sleep {VERIFY_DELAY}; done; '
        f"echo {failure} >&2; systemctl status --no-pager {service} >&2; exit 1"
    )


def require_identity(fc: FanControl) -> None:
    """While planning, before any operation: the board, BMC and fan modes this configuration is for."""

    output = probe(identity_probe_command(), name="board, BMC identity and fan modes")
    if output is None:
        raise DeployError("fan_control: cannot read the board, the BMC identity or the fan modes (ipmitool, DMI)")
    problems = check_identity(fc, output)
    if problems:
        raise DeployError("fan_control refused: " + "; ".join(problems))


def deploy_fan_control(fc: FanControl) -> list[OperationMeta]:
    """The controller's packages, files and unit; the service enabled, started and restarted on change.

    Call :func:`require_identity` first, before the deploy plans anything. With
    ``enabled: false`` the service is only stopped and disabled: its clean stop
    restores BMC auto on the positions it held.
    """

    if not fc.enabled:
        stop = systemd.service(name=f"Stop and disable {SERVICE}", service=SERVICE, running=False, enabled=False)
        return [stop]
    apt.packages(name="Install the fan control packages", packages=list(fc.packages))
    for directory in (LIBEXEC, CONFIG_DIR):
        files.directory(name=f"Ensure {directory}", path=str(directory), user="root", group="root", mode="0755")
    script = files.put(
        name=f"Install {SCRIPT_PATH}",
        src=str(SCRIPT_SOURCE),
        dest=str(SCRIPT_PATH),
        user="root",
        group="root",
        mode="0755",
    )
    config = files.put(
        name=f"Install {CONFIG_PATH}",
        src=StringIO(render_config(fc)),
        dest=str(CONFIG_PATH),
        user="root",
        group="root",
        mode="0644",
    )
    unit = systemd_unit(SERVICE, render_unit())
    service_rollout(SERVICE, units=[unit], restart_when=[script, config])
    verify = mark_read_only(server.shell(name=f"Require {SERVICE} in {fc.mode} mode", commands=[verify_command(fc)]))
    return [script, config, unit, verify]
