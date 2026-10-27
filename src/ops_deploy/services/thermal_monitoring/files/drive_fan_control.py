#!/usr/bin/python3
"""drive-fan-control: drive-aware case-fan control through the BMC.

Installed by ops-deploy's ``thermal_monitoring`` deploy when its optional
``fan_control`` block is set (``docs/services/thermal_monitoring.md``,
"fan_control"). Standard library only; runs as root under systemd
(``Type=notify``, watchdog).

Inputs: the CPU temperature and every configured NVMe drive from hwmon each
cycle; every configured HDD every ``hdd_interval_s``, and only while it spins
(``hdparm -C`` first, then ``smartctl -n standby``, so no read ever wakes a
disk); scrub and resilver state of the configured ZFS pools each cycle. The
demand is the highest duty any curve or scan asks for, clamped to
``[floor_pct, 100]``. Increases apply at once; a decrease needs the target to
stay ``decrease_step_pct`` below the duty for ``decrease_hold_cycles`` cycles
and then steps down ``decrease_step_pct`` per cycle.

Modes:

- ``observe``: computes and records what it would set; never writes the BMC,
  also not positions an earlier run left under control (it reports them as
  unhealthy; the stop helper releases them at the next clean stop).
- ``active``: puts the managed fan positions (never the protected ones, e.g.
  the CPU fan) into manual mode and writes their duty. Every write attempt
  reads the 16 bytes right before and changes only the managed positions, and
  is read back; a mismatch is retried once from a fresh read, then the managed
  positions go back to BMC auto and the process exits. Before it takes
  control, positions an earlier run still holds that are not managed now go
  back to BMC auto (read back), so no fan stays under a control nobody
  records; when that run's record is from another board, BMC or firmware it
  refuses instead. A required input that is missing, stale or fails
  ``failure_cycles`` times in a row, and a managed fan that reads no RPM or
  0 RPM for ``stall_cycles`` cycles, force 100 %.
  The hwmon sensors are read last in a cycle, right before the decision, and
  staleness is measured at the time of the decision.
- ``calibrate``: once per ``calibration.id``, maps each managed position to its
  fan and measures a duty staircase, restores the BMC's previous mode and duty
  bytes of the managed positions (read back), writes ``calibration.json``,
  then observes. It does not start, and it aborts, while a required input
  fails (a single failed read is enough), a scrub or resilver runs, the scan
  state of a configured pool is unknown (``zpool status`` failed or shows no
  scan line for it) or the curves ask for ``abort_target_pct``; until its
  first BMC write that is a skip, and the same id runs again at the next
  start. It does not start
  either while positions an earlier run left under control are still held.

Board and firmware must match the configured identity (DMI board vendor and
name, BMC manufacturer and product ID, firmware revision) or the process exits
78 (configuration error) without touching the BMC. The identity is recorded
with the control state.

``stop-post`` (``ExecStopPost=``) acts only when this controller holds the BMC
(the runtime state file says so, whatever the configuration says now) and the
board, BMC and firmware are still the recorded ones: after a clean stop
(``SERVICE_RESULT=success``) it restores BMC auto on the managed positions,
after anything else it sets them to 100 % (auto if that fails), with read-back.

The BMC commands are ASRock Rack's for AST2600 boards (technical document
TSDQA-72): ``raw 0x3a 0xd0 0x12`` reads the 16 mode bytes (``0x00`` default,
``0x02`` manual), ``0x0f`` the 16 duty bytes, ``0x11`` and ``0x0e`` write them.
"""

from __future__ import annotations

import argparse
import itertools
import json
import math
import os
import re
import signal
import socket
import subprocess
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

CONFIG_VERSION = 1
POSITIONS = 16
AUTO = 0x00
MANUAL = 0x02
FULL = 100
MIN_FLOOR = 25
EXIT_CONFIG = 78
EXIT_BMC = 75
MODES = ("observe", "calibrate", "active")
BACKENDS = ("asrock_rack_ast2600",)

IPMITOOL = ("ipmitool", "-I", "open")
GET_MODE = ("raw", "0x3a", "0xd0", "0x12")
GET_DUTY = ("raw", "0x3a", "0xd0", "0x0f")
SET_MODE = ("raw", "0x3a", "0xd0", "0x11")
SET_DUTY = ("raw", "0x3a", "0xd0", "0x0e")

TIMEOUT_IPMI = 15.0  # mc info, sdr
TIMEOUT_IPMI_RAW = 5.0  # the vendor GETs and SETs (they answer within a second)
TIMEOUT_HDPARM = 10.0
TIMEOUT_SMARTCTL = 30.0
TIMEOUT_ZPOOL = 15.0
READBACK_DELAY = 0.5
SLEEP_CHUNK = 10.0
SUMMARY_EVERY = 20

ACTIVE_STATES = frozenset({"active/idle", "active", "idle", "idle_a", "idle_b", "idle_c"})
STANDBY_STATES = frozenset({"standby", "sleeping", "standby_y", "standby_z"})
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@+-]{0,63}$")
SENSOR = re.compile(r"^[A-Za-z0-9_]{1,32}$")
POOL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
DEVICE = re.compile(r"^/dev/[A-Za-z0-9_.:/+@-]{1,240}$")
SMART_TYPE = re.compile(r"^(sat|ata|auto)$")
CAL_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
BYTE = re.compile(r"^[0-9a-fA-F]{2}$")

# Input names of their own; drives may not use them.
RESERVED = frozenset({"cpu", "fans"})
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


class ConfigError(Exception):
    """The configuration, the board or the BMC state rules this controller out."""


class BmcError(Exception):
    """A BMC command failed or a write did not read back."""


# -- configuration -----------------------------------------------------------------


@dataclass(frozen=True)
class Position:
    position: int
    sensor: str


@dataclass(frozen=True)
class Drive:
    name: str
    device: str
    smart_type: str = "sat"


@dataclass(frozen=True)
class ScanPool:
    pool: str
    min_pct: int


@dataclass(frozen=True)
class Board:
    dmi_board_vendor: str
    dmi_board_name: str
    bmc_manufacturer_id: int
    bmc_product_id: int
    bmc_firmware: tuple[str, ...]


@dataclass(frozen=True)
class Calibration:
    id: str
    mapping_hold_s: int = 60
    steps_pct: tuple[int, ...] = (100, 70, 50, 40, 35, 30)
    step_hold_s: int = 90
    sample_interval_s: int = 5
    settle_s: int = 20
    tach_step_rpm: int = 400
    oscillation_steps: int = 2
    min_rpm: int = 600
    # Abort (BMC restored) as soon as the curves ask for this duty or a scan runs.
    abort_target_pct: int = 60


@dataclass(frozen=True)
class Config:
    mode: str
    backend: str
    board: Board
    managed: tuple[Position, ...]
    protected: tuple[Position, ...]
    floor_pct: int
    interval_s: int
    hdd_interval_s: int
    cpu_hwmon_name: str
    cpu_label: str
    nvme: tuple[Drive, ...]
    hdd: tuple[Drive, ...]
    scan_pools: tuple[ScanPool, ...]
    curves: dict[str, tuple[tuple[float, int], ...]]
    decrease_step_pct: int = 5
    decrease_hold_cycles: int = 3
    min_change_pct: int = 3
    failure_cycles: int = 2
    stall_cycles: int = 2
    calibration: Calibration | None = None

    @property
    def managed_positions(self) -> tuple[int, ...]:
        return tuple(p.position for p in self.managed)


def _int(value: Any, name: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ConfigError(f"{name} must be an integer from {low} to {high}")
    return value


def _str(value: Any, name: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ConfigError(f"{name} is missing or malformed")
    return value


def _mapping(value: Any, name: str, keys: set[str], required: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigError(f"{name} must be an object")
    unknown = set(value) - keys
    if unknown:
        raise ConfigError(f"{name} has unknown keys: {', '.join(sorted(unknown))}")
    missing = required - set(value)
    if missing:
        raise ConfigError(f"{name} lacks: {', '.join(sorted(missing))}")
    return value


def _list(value: Any, name: str) -> list[Any]:
    if not isinstance(value, list):
        raise ConfigError(f"{name} must be a list")
    return value


def _curve(value: Any, name: str) -> tuple[tuple[float, int], ...]:
    points = _list(value, name)
    if len(points) < 2:
        raise ConfigError(f"{name} needs at least two points")
    curve: list[tuple[float, int]] = []
    for index, point in enumerate(points):
        if not isinstance(point, list) or len(point) != 2:
            raise ConfigError(f"{name}[{index}] must be [temperature, duty]")
        temp, duty = point
        if isinstance(temp, bool) or not isinstance(temp, (int, float)) or not math.isfinite(temp):
            raise ConfigError(f"{name}[{index}] temperature must be a finite number")
        if not -20 <= temp <= 120:
            raise ConfigError(f"{name}[{index}] temperature must be from -20 to 120")
        curve.append((float(temp), _int(duty, f"{name}[{index}] duty", 0, FULL)))
    for (t0, d0), (t1, d1) in itertools.pairwise(curve):
        if t1 <= t0:
            raise ConfigError(f"{name} temperatures must increase")
        if d1 < d0:
            raise ConfigError(f"{name} duties must not decrease")
    return tuple(curve)


def _positions(value: Any, name: str) -> tuple[Position, ...]:
    result = []
    for index, item in enumerate(_list(value, name)):
        entry = _mapping(item, f"{name}[{index}]", {"position", "sensor"}, {"position", "sensor"})
        result.append(
            Position(
                _int(entry["position"], f"{name}[{index}].position", 0, POSITIONS - 1),
                _str(entry["sensor"], f"{name}[{index}].sensor", SENSOR),
            )
        )
    return tuple(result)


def _drives(value: Any, name: str, *, smart: bool) -> tuple[Drive, ...]:
    keys = {"name", "device", "smart_type"} if smart else {"name", "device"}
    result = []
    for index, item in enumerate(_list(value, name)):
        entry = _mapping(item, f"{name}[{index}]", keys, {"name", "device"})
        device = _str(entry["device"], f"{name}[{index}].device", DEVICE)
        if "/../" in f"{device}/" or "//" in device:
            raise ConfigError(f"{name}[{index}].device must be a plain absolute path")
        result.append(
            Drive(
                _str(entry["name"], f"{name}[{index}].name", NAME),
                device,
                _str(entry.get("smart_type", "sat"), f"{name}[{index}].smart_type", SMART_TYPE),
            )
        )
    names = [d.name for d in result]
    if len(set(names)) != len(names):
        raise ConfigError(f"{name} names must be unique")
    if set(names) & RESERVED:
        raise ConfigError(f"{name} names must not be {' or '.join(sorted(RESERVED))}")
    return tuple(result)


def parse_config(raw: Any) -> Config:
    """The controller's configuration; refuses anything it would not act on safely."""

    keys = {
        "version",
        "mode",
        "backend",
        "board",
        "managed",
        "protected",
        "floor_pct",
        "interval_s",
        "hdd_interval_s",
        "cpu",
        "nvme",
        "hdd",
        "scan_pools",
        "curves",
        "decrease_step_pct",
        "decrease_hold_cycles",
        "min_change_pct",
        "failure_cycles",
        "stall_cycles",
        "calibration",
    }
    data = _mapping(raw, "config", keys, keys - {"calibration"})
    if data["version"] != CONFIG_VERSION:
        raise ConfigError(f"config version must be {CONFIG_VERSION}")
    if data["mode"] not in MODES:
        raise ConfigError(f"mode must be one of {', '.join(MODES)}")
    if data["backend"] not in BACKENDS:
        raise ConfigError(f"backend must be one of {', '.join(BACKENDS)}")
    board_keys = {"dmi_board_vendor", "dmi_board_name", "bmc_manufacturer_id", "bmc_product_id", "bmc_firmware"}
    board_raw = _mapping(data["board"], "board", board_keys, board_keys)
    firmware = _list(board_raw["bmc_firmware"], "board.bmc_firmware")
    if not firmware or not all(isinstance(f, str) and re.fullmatch(r"[0-9A-Za-z.]{1,16}", f) for f in firmware):
        raise ConfigError("board.bmc_firmware must list firmware revisions")
    text = re.compile(r"^[ -~]{1,64}$")
    board = Board(
        _str(board_raw["dmi_board_vendor"], "board.dmi_board_vendor", text).strip(),
        _str(board_raw["dmi_board_name"], "board.dmi_board_name", text).strip(),
        _int(board_raw["bmc_manufacturer_id"], "board.bmc_manufacturer_id", 0, 0xFFFFFF),
        _int(board_raw["bmc_product_id"], "board.bmc_product_id", 0, 0xFFFF),
        tuple(firmware),
    )
    managed = _positions(data["managed"], "managed")
    protected = _positions(data["protected"], "protected")
    if not managed:
        raise ConfigError("managed must name at least one fan position")
    if not protected:
        raise ConfigError("protected must name the positions that stay in BMC auto (the CPU fan)")
    every = [p.position for p in (*managed, *protected)]
    if len(set(every)) != len(every):
        raise ConfigError("a fan position may be listed once, and never both managed and protected")
    sensors = [p.sensor for p in (*managed, *protected)]
    if len(set(sensors)) != len(sensors):
        raise ConfigError("fan sensors must be unique")
    cpu = _mapping(data["cpu"], "cpu", {"hwmon_name", "label"}, {"hwmon_name", "label"})
    curves_raw = _mapping(data["curves"], "curves", {"hdd", "nvme", "cpu"}, {"hdd", "nvme", "cpu"})
    curves = {name: _curve(points, f"curves.{name}") for name, points in curves_raw.items()}
    pools = []
    for index, item in enumerate(_list(data["scan_pools"], "scan_pools")):
        entry = _mapping(item, f"scan_pools[{index}]", {"pool", "min_pct"}, {"pool", "min_pct"})
        pools.append(
            ScanPool(
                _str(entry["pool"], f"scan_pools[{index}].pool", POOL),
                _int(entry["min_pct"], f"scan_pools[{index}].min_pct", 0, FULL),
            )
        )
    if len({p.pool for p in pools}) != len(pools):
        raise ConfigError("scan_pools must name each pool once")
    interval = _int(data["interval_s"], "interval_s", 10, 60)
    calibration = None
    if data.get("calibration") is not None:
        calibration = _calibration(data["calibration"])
    if data["mode"] == "calibrate" and calibration is None:
        raise ConfigError("mode calibrate needs a calibration block")
    nvme = _drives(data["nvme"], "nvme", smart=False)
    hdd = _drives(data["hdd"], "hdd", smart=True)
    if {d.name for d in nvme} & {d.name for d in hdd}:
        raise ConfigError("nvme and hdd names must differ")
    config = Config(
        mode=data["mode"],
        backend=data["backend"],
        board=board,
        managed=managed,
        protected=protected,
        floor_pct=_int(data["floor_pct"], "floor_pct", MIN_FLOOR, FULL),
        interval_s=interval,
        hdd_interval_s=_int(data["hdd_interval_s"], "hdd_interval_s", interval, 3600),
        cpu_hwmon_name=_str(cpu["hwmon_name"], "cpu.hwmon_name", NAME),
        cpu_label=_str(cpu["label"], "cpu.label", NAME),
        nvme=nvme,
        hdd=hdd,
        scan_pools=tuple(pools),
        curves=curves,
        decrease_step_pct=_int(data["decrease_step_pct"], "decrease_step_pct", 1, 25),
        decrease_hold_cycles=_int(data["decrease_hold_cycles"], "decrease_hold_cycles", 1, 20),
        min_change_pct=_int(data["min_change_pct"], "min_change_pct", 1, 10),
        failure_cycles=_int(data["failure_cycles"], "failure_cycles", 1, 10),
        stall_cycles=_int(data["stall_cycles"], "stall_cycles", 1, 10),
        calibration=calibration,
    )
    if config.decrease_step_pct < config.min_change_pct:
        raise ConfigError("decrease_step_pct must be at least min_change_pct")
    return config


def _calibration(raw: Any) -> Calibration:
    keys = {
        "id",
        "mapping_hold_s",
        "steps_pct",
        "step_hold_s",
        "sample_interval_s",
        "settle_s",
        "tach_step_rpm",
        "oscillation_steps",
        "min_rpm",
        "abort_target_pct",
    }
    data = _mapping(raw, "calibration", keys, keys)
    steps = _list(data["steps_pct"], "calibration.steps_pct")
    if not steps or len(steps) > 12:
        raise ConfigError("calibration.steps_pct must list 1 to 12 duties")
    parsed = tuple(_int(s, "calibration.steps_pct[]", MIN_FLOOR, FULL) for s in steps)
    if list(parsed) != sorted(parsed, reverse=True) or len(set(parsed)) != len(parsed):
        raise ConfigError("calibration.steps_pct must strictly decrease")
    calibration = Calibration(
        id=_str(data["id"], "calibration.id", CAL_ID),
        mapping_hold_s=_int(data["mapping_hold_s"], "calibration.mapping_hold_s", 10, 300),
        steps_pct=parsed,
        step_hold_s=_int(data["step_hold_s"], "calibration.step_hold_s", 10, 600),
        sample_interval_s=_int(data["sample_interval_s"], "calibration.sample_interval_s", 1, 30),
        settle_s=_int(data["settle_s"], "calibration.settle_s", 0, 120),
        tach_step_rpm=_int(data["tach_step_rpm"], "calibration.tach_step_rpm", 1, 2000),
        oscillation_steps=_int(data["oscillation_steps"], "calibration.oscillation_steps", 1, 10),
        min_rpm=_int(data["min_rpm"], "calibration.min_rpm", 0, 10000),
        abort_target_pct=_int(data["abort_target_pct"], "calibration.abort_target_pct", MIN_FLOOR, FULL),
    )
    if calibration.settle_s >= calibration.step_hold_s or calibration.settle_s >= calibration.mapping_hold_s:
        raise ConfigError("calibration.settle_s must be shorter than every hold")
    return calibration


def load_config(path: Path) -> Config:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc
    return parse_config(raw)


# -- host access -------------------------------------------------------------------


@dataclass(frozen=True)
class Paths:
    hwmon: Path = Path("/sys/class/hwmon")
    block: Path = Path("/sys/class/block")
    dmi: Path = Path("/sys/class/dmi/id")
    run_dir: Path = Path("/run/drive-fan-control")
    lib_dir: Path = Path("/var/lib/drive-fan-control")
    exec_path: str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    # Device paths (/dev/...) resolve below this root (tests point it at a scratch tree).
    dev_root: Path = Path("/")

    @property
    def metrics_dir(self) -> Path:
        return self.run_dir / "metrics"

    @property
    def control_file(self) -> Path:
        return self.run_dir / "control.json"

    @property
    def status_file(self) -> Path:
        return self.run_dir / "status.json"

    @property
    def calibration_file(self) -> Path:
        return self.lib_dir / "calibration.json"


@dataclass(frozen=True)
class Result:
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def log(level: int, message: str) -> None:
    # The syslog priority prefix journald understands: 3 error, 4 warning, 6 info.
    sys.stderr.write(f"<{level}>{message}\n")
    sys.stderr.flush()


def notify(message: str) -> None:
    """sd_notify(3) without libsystemd: one datagram to $NOTIFY_SOCKET."""

    address = os.environ.get("NOTIFY_SOCKET", "")
    if not address:
        return
    if address.startswith("@"):
        address = "\0" + address[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.connect(address)
            sock.sendall(message.encode())
    except OSError as exc:
        log(4, f"sd_notify failed: {exc}")


class Runner:
    """Runs one command (an argv list, never a shell) with a timeout and a clean environment."""

    def __init__(self, exec_path: str, after: Callable[[], None] = lambda: None) -> None:
        self.env = {"PATH": exec_path, "LC_ALL": "C", "LANG": "C"}
        self.after = after
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, argv: Sequence[str], timeout: float) -> Result:
        self.calls.append(tuple(argv))
        try:
            done = subprocess.run(
                list(argv),
                capture_output=True,
                text=True,
                errors="replace",
                timeout=timeout,
                check=False,
                env=self.env,
                stdin=subprocess.DEVNULL,
            )
            result = Result(done.returncode, done.stdout, done.stderr)
        except FileNotFoundError:
            result = Result(127, "", f"{argv[0]}: not found")
        except subprocess.TimeoutExpired:
            result = Result(124, "", f"{argv[0]}: timed out after {timeout:g}s")
        except OSError as exc:
            result = Result(126, "", f"{argv[0]}: {exc}")
        self.after()
        return result


def _first_line(text: str) -> str:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return lines[-1][:200] if lines else ""


# -- BMC -----------------------------------------------------------------------------


def parse_bytes(stdout: str) -> tuple[int, ...]:
    """The 16 hex bytes ``ipmitool raw`` prints for the vendor GETs (one line of them, nothing else)."""

    rows = [line.split() for line in stdout.splitlines() if line.strip()]
    rows = [words for words in rows if all(BYTE.fullmatch(w) for w in words)]
    if len(rows) != 1 or len(rows[0]) != POSITIONS:
        raise BmcError(f"expected one line of {POSITIONS} hex bytes, got {stdout.strip()[:120]!r}")
    return tuple(int(w, 16) for w in rows[0])


def parse_mc_info(stdout: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in stdout.splitlines():
        key, sep, value = line.partition(":")
        if sep and key.strip() and not key.startswith(" "):
            fields[key.strip()] = value.strip()
    return fields


def parse_fans(stdout: str) -> dict[str, float | None]:
    """``ipmitool sdr type fan``: sensor name -> RPM, ``None`` for "No Reading"."""

    fans: dict[str, float | None] = {}
    for line in stdout.splitlines():
        parts = [part.strip() for part in line.split("|")]
        if len(parts) < 5 or not parts[0]:
            continue
        match = re.fullmatch(r"(-?[0-9]+(?:\.[0-9]+)?) RPM", parts[4])
        fans[parts[0]] = float(match.group(1)) if match else None
    return fans


class Bmc:
    def __init__(self, run: Runner, sleep: Callable[[float], None] = time.sleep) -> None:
        self.run = run
        self.sleep = sleep
        self.writes = 0

    def _call(self, *args: str, timeout: float = TIMEOUT_IPMI) -> Result:
        return self.run([*IPMITOOL, *args], timeout)

    def _get(self, command: Sequence[str]) -> tuple[int, ...]:
        result = self._call(*command, timeout=TIMEOUT_IPMI_RAW)
        if not result.ok:
            raise BmcError(f"ipmitool {' '.join(command)} failed ({result.returncode}): {_first_line(result.stderr)}")
        return parse_bytes(result.stdout)

    def mode(self) -> tuple[int, ...]:
        return self._get(GET_MODE)

    def duty(self) -> tuple[int, ...]:
        return self._get(GET_DUTY)

    def mc_info(self) -> dict[str, str]:
        result = self._call("mc", "info")
        if not result.ok:
            raise BmcError(f"ipmitool mc info failed ({result.returncode}): {_first_line(result.stderr)}")
        return parse_mc_info(result.stdout)

    def fans(self) -> dict[str, float | None]:
        result = self._call("sdr", "type", "fan")
        if not result.ok:
            raise BmcError(f"ipmitool sdr type fan failed ({result.returncode}): {_first_line(result.stderr)}")
        return parse_fans(result.stdout)

    def update(self, kind: str, changes: Mapping[int, int]) -> tuple[int, ...]:
        """Set ``changes`` (position -> byte) in the ``mode`` or ``duty`` bytes and read them back.

        Every attempt reads the 16 bytes right before writing and keeps every
        position it does not change as read then, so a byte someone else
        changed in between is never written back over. A write whose read-back
        differs is attempted once more (with a fresh read); then BmcError.
        """

        if kind not in ("mode", "duty"):
            raise BmcError(f"unknown BMC vector {kind!r}")
        read, command = (self.mode, SET_MODE) if kind == "mode" else (self.duty, SET_DUTY)
        top = MANUAL if kind == "mode" else FULL
        if not all(0 <= p < POSITIONS and 0 <= v <= top for p, v in changes.items()):
            raise BmcError(f"refusing malformed {kind} changes {dict(changes)}")
        problem = ""
        for attempt in (1, 2):
            try:
                current = read()
            except BmcError as exc:
                problem = str(exc)
                continue
            wanted = list(current)
            for position, value in changes.items():
                wanted[position] = value
            if tuple(wanted) == current:
                return current
            self.writes += 1
            result = self._call(*command, *(f"0x{value:02x}" for value in wanted), timeout=TIMEOUT_IPMI_RAW)
            if not result.ok:
                problem = f"write {attempt} failed ({result.returncode}): {_first_line(result.stderr)}"
                log(4, problem)
                continue
            self.sleep(READBACK_DELAY)
            try:
                back = read()
            except BmcError as exc:
                problem = f"read-back after write {attempt} failed: {exc}"
                log(4, problem)
                continue
            if back == tuple(wanted):
                return back
            problem = f"read-back after write {attempt} is {_hex(back)}, not {_hex(wanted)}"
            log(4, problem)
        raise BmcError(f"the {kind} bytes did not take {dict(changes)}: {problem}")


def _hex(vector: Sequence[int]) -> str:
    return " ".join(f"{value:02x}" for value in vector)


def read_identity(bmc: Bmc, paths: Paths) -> dict[str, Any]:
    """DMI board vendor and name, BMC manufacturer and product ID and firmware, as found now.

    Unreadable DMI is a :class:`ConfigError`; an unreadable BMC a :class:`BmcError`
    (it may not be ready yet).
    """

    found: dict[str, Any] = {}
    for key in ("board_vendor", "board_name"):
        try:
            found[key] = (paths.dmi / key).read_text(encoding="utf-8", errors="replace").strip()
        except OSError as exc:
            raise ConfigError(f"cannot read DMI {key}: {exc}") from exc
    info = bmc.mc_info()
    product = info.get("Product ID", "").split()
    try:
        found["manufacturer_id"] = int(info.get("Manufacturer ID", ""))
        found["product_id"] = int(product[0]) if product else -1
    except ValueError as exc:
        raise ConfigError(f"unreadable BMC identity {info.get('Manufacturer ID')!r} {product!r}") from exc
    found["firmware"] = info.get("Firmware Revision", "")
    return found


def check_board(config: Config, identity: Mapping[str, Any]) -> None:
    """Refuse (:class:`ConfigError`) unless ``identity`` is the configured board, BMC and firmware."""

    board = config.board
    if (identity["board_vendor"], identity["board_name"]) != (board.dmi_board_vendor, board.dmi_board_name):
        raise ConfigError(
            f"board {identity['board_vendor']!r} {identity['board_name']!r} is not the configured "
            f"{board.dmi_board_vendor!r} {board.dmi_board_name!r}"
        )
    if (identity["manufacturer_id"], identity["product_id"]) != (board.bmc_manufacturer_id, board.bmc_product_id):
        found = (identity["manufacturer_id"], identity["product_id"])
        raise ConfigError(f"BMC manufacturer/product {found} is not the configured one")
    if identity["firmware"] not in board.bmc_firmware:
        raise ConfigError(f"BMC firmware {identity['firmware']!r} is not in the allowlist {list(board.bmc_firmware)}")


# -- inputs --------------------------------------------------------------------------


def _read_millidegrees(path: Path) -> float:
    value = int(path.read_text(encoding="ascii").strip())
    celsius = value / 1000.0
    if not -40.0 <= celsius <= 150.0:
        raise ValueError(f"{path} reads an implausible {celsius:.1f} C")
    return celsius


def _labelled_temperature(hwmon: Path, label: str) -> float | None:
    for label_file in sorted(hwmon.glob("temp*_label")):
        try:
            if label_file.read_text(encoding="utf-8", errors="replace").strip() == label:
                return _read_millidegrees(label_file.with_name(label_file.name.replace("_label", "_input")))
        except FileNotFoundError:
            continue
    return None


def read_cpu(config: Config, paths: Paths) -> float:
    found = []
    for hwmon in sorted(paths.hwmon.glob("hwmon*")):
        try:
            name = (hwmon / "name").read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            continue
        if name == config.cpu_hwmon_name:
            value = _labelled_temperature(hwmon, config.cpu_label)
            if value is not None:
                found.append(value)
    if not found:
        raise ValueError(f"no hwmon {config.cpu_hwmon_name!r} with label {config.cpu_label!r}")
    return max(found)


def read_nvme(drive: Drive, paths: Paths) -> float:
    """The drive's Composite temperature from the hwmon of its controller (never wakes anything)."""

    block = os.path.basename(os.path.realpath(paths.dev_root / drive.device.lstrip("/")))
    if not re.fullmatch(r"nvme[0-9]+n[0-9]+", block):
        raise ValueError(f"{drive.device} does not resolve to an NVMe namespace")
    controller = os.path.realpath(paths.block / block / "device")
    for hwmon in sorted(paths.hwmon.glob("hwmon*")):
        if os.path.realpath(hwmon / "device") != controller:
            continue
        value = _labelled_temperature(hwmon, "Composite")
        if value is None:
            value = _read_millidegrees(hwmon / "temp1_input")
        return value
    raise ValueError(f"no hwmon for {drive.name}")


def parse_power_state(stdout: str) -> str:
    match = re.search(r"drive state is:\s*(\S+)", stdout)
    return match.group(1) if match else ""


def parse_smart_temperature(stdout: str) -> tuple[str, float | None]:
    """``smartctl -j`` output: ("temperature", value), ("standby", None) or ("error", None)."""

    try:
        data = json.loads(stdout)
    except ValueError:
        return "error", None
    if not isinstance(data, dict):
        return "error", None
    messages = data.get("smartctl", {}).get("messages", []) if isinstance(data.get("smartctl"), dict) else []
    for message in messages if isinstance(messages, list) else []:
        text = message.get("string", "") if isinstance(message, dict) else ""
        if re.search(r"Device is in (STANDBY|SLEEP)", str(text)):
            return "standby", None
    current = data.get("temperature", {}).get("current") if isinstance(data.get("temperature"), dict) else None
    if isinstance(current, (int, float)) and not isinstance(current, bool) and 0 < current < 100:
        return "temperature", float(current)
    table = data.get("ata_smart_attributes", {}).get("table", [])
    for attribute in table if isinstance(table, list) else []:
        if isinstance(attribute, dict) and attribute.get("id") == 194:
            raw = str(attribute.get("raw", {}).get("string", "")) if isinstance(attribute.get("raw"), dict) else ""
            match = re.match(r"\s*([0-9]+)", raw)
            if match and 0 < int(match.group(1)) < 100:
                return "temperature", float(match.group(1))
    return "error", None


@dataclass
class HddReading:
    state: str  # "active", "standby" or "error"
    celsius: float | None = None
    error: str = ""


def read_hdd(drive: Drive, run: Runner) -> HddReading:
    """``hdparm -C`` first; ``smartctl -n standby`` only for a spinning disk."""

    power = run(["hdparm", "-C", drive.device], TIMEOUT_HDPARM)
    if not power.ok:
        return HddReading("error", error=f"hdparm -C failed ({power.returncode}): {_first_line(power.stderr)}")
    state = parse_power_state(power.stdout)
    if state in STANDBY_STATES:
        return HddReading("standby")
    if state not in ACTIVE_STATES:
        return HddReading("error", error=f"unknown power state {state!r}")
    smart = run(["smartctl", "-n", "standby", "-d", drive.smart_type, "-A", "-j", drive.device], TIMEOUT_SMARTCTL)
    if smart.returncode in (124, 126, 127):
        return HddReading("error", error=_first_line(smart.stderr))
    kind, value = parse_smart_temperature(smart.stdout)
    if kind == "standby":
        return HddReading("standby")
    if kind == "temperature":
        return HddReading("active", value)
    return HddReading("error", error=f"smartctl exit {smart.returncode} without a temperature")


def parse_scan_states(stdout: str, pools: Sequence[str]) -> dict[str, bool | None]:
    """``zpool status``: pool -> scrub or resilver in progress, ``None`` without a scan line."""

    found: dict[str, bool | None] = {}
    current = None
    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("pool:"):
            current = stripped.partition(":")[2].strip()
            found[current] = None
        elif stripped.startswith("scan:") and current is not None:
            found[current] = bool(re.search(r"\b(scrub|resilver) in progress\b", stripped))
    missing = [pool for pool in pools if pool not in found]
    if missing:
        raise ValueError(f"zpool status lists no {', '.join(missing)}")
    return {pool: found[pool] for pool in pools}


def read_scan_states(config: Config, run: Runner) -> dict[str, bool | None]:
    pools = [p.pool for p in config.scan_pools]
    if not pools:
        return {}
    result = run(["zpool", "status", "-p", *pools], TIMEOUT_ZPOOL)
    if not result.ok:
        raise ValueError(f"zpool status failed ({result.returncode}): {_first_line(result.stderr)}")
    return parse_scan_states(result.stdout, pools)


# -- policy --------------------------------------------------------------------------


def interpolate(curve: Sequence[tuple[float, int]], temperature: float) -> float:
    if temperature <= curve[0][0]:
        return float(curve[0][1])
    for (t0, d0), (t1, d1) in itertools.pairwise(curve):
        if temperature <= t1:
            return d0 + (d1 - d0) * (temperature - t0) / (t1 - t0)
    return float(curve[-1][1])


@dataclass
class Readings:
    cpu: float | None = None
    nvme: dict[str, float] = field(default_factory=dict)
    hdd: dict[str, HddReading] = field(default_factory=dict)
    scans: dict[str, bool] | None = None


def demand(config: Config, readings: Readings) -> tuple[int, list[str]]:
    """The duty the inputs ask for, clamped to [floor, 100], and which inputs asked."""

    asks: list[tuple[float, str]] = []
    if readings.cpu is not None:
        asks.append((interpolate(config.curves["cpu"], readings.cpu), f"cpu {readings.cpu:.1f}C"))
    for name, celsius in readings.nvme.items():
        asks.append((interpolate(config.curves["nvme"], celsius), f"{name} {celsius:.1f}C"))
    spinning = {name: r.celsius for name, r in readings.hdd.items() if r.state == "active" and r.celsius is not None}
    if spinning:
        name = max(spinning, key=lambda n: spinning[n] or 0.0)
        hottest = spinning[name] or 0.0
        asks.append((interpolate(config.curves["hdd"], hottest), f"{name} {hottest:.0f}C"))
    for pool in config.scan_pools:
        if readings.scans and readings.scans.get(pool.pool):
            asks.append((float(pool.min_pct), f"scan {pool.pool}"))
    target = config.floor_pct
    reasons = ["floor"]
    if asks:
        top = max(value for value, _ in asks)
        target = min(FULL, max(config.floor_pct, math.ceil(top - 1e-9)))
        if target > config.floor_pct:
            reasons = [why for value, why in asks if math.ceil(value - 1e-9) >= target]
    return target, reasons


@dataclass
class Slew:
    """Increases at once; a decrease after ``hold`` cycles at least ``step`` below, ``step`` at a time."""

    duty: int = FULL
    below: int = 0

    def next(self, target: int, config: Config, *, failsafe: bool) -> int:
        if failsafe:
            self.below = 0
            self.duty = FULL
        elif target > self.duty:
            self.below = 0
            if target - self.duty >= config.min_change_pct or target == FULL:
                self.duty = target
        elif self.duty - target >= config.decrease_step_pct:
            self.below += 1
            if self.below >= config.decrease_hold_cycles:
                self.duty = max(target, self.duty - config.decrease_step_pct)
        else:
            self.below = 0
        return self.duty


# -- state files ---------------------------------------------------------------------


def atomic_write(path: Path, text: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def write_metrics(paths: Paths, values: dict[str, float | int | None]) -> None:
    for name in METRICS:
        value = values.get(name)
        text = "na" if value is None else (f"{value:.1f}" if isinstance(value, float) else str(int(value)))
        atomic_write(paths.metrics_dir / name, text + "\n")


def read_control(paths: Paths) -> dict[str, Any]:
    try:
        data = json.loads(paths.control_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def write_control(
    paths: Paths, *, control: bool, managed: Sequence[int], note: str, identity: Mapping[str, Any] | None = None
) -> None:
    """The runtime state the stop helper acts on: who holds which positions, on which board and firmware."""

    payload = {
        "control": control,
        "managed": list(managed),
        "identity": dict(identity or {}),
        "note": note,
        "pid": os.getpid(),
        "ts": int(time.time()),
    }
    atomic_write(paths.control_file, json.dumps(payload, sort_keys=True) + "\n")


# -- the controller ------------------------------------------------------------------


@dataclass
class Source:
    """Health of one required input."""

    failures: int = 0
    last_ok: float | None = None
    error: str = ""


class Controller:
    def __init__(
        self,
        config: Config,
        paths: Paths,
        run: Runner,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.config = config
        self.paths = paths
        self.run = run
        self.bmc = Bmc(run, sleep)
        self.clock = clock
        self.sleep = sleep
        self.slew = Slew()
        self.sources: dict[str, Source] = {}
        self.readings = Readings()
        self.last_hdd_poll: float | None = None
        self.hdd_failed = False
        self.stall: dict[str, int] = {}
        self.control = False
        self.stop = False
        self.cycle = 0
        self.last_logged: tuple[Any, ...] = ()
        self.managed_auto: int | None = None
        self.fan_rpm: dict[str, float | None] = {}
        # The board, BMC and firmware validated at start (recorded with the control state).
        self.identity: dict[str, Any] = {}
        # Positions an earlier run left under control; observe and calibrate never write them.
        self.leftover: list[int] = []
        # Why the scan state of the configured pools is not known (empty when it is): the
        # demand treats an unknown scan as none, the calibration refuses to run on it.
        self.scan_unknown = ""

    def release_unmanaged(self, held: Sequence[int], recorded: Mapping[str, Any]) -> None:
        """Before ``active`` takes control: positions an earlier run still holds (``held``, its
        record) that are not managed now go back to BMC auto, read back.

        Claiming the managed positions overwrites the record the stop helper acts
        on, so a position left out of it would stay under a control nobody
        records. The release is refused (:class:`ConfigError`, nothing written)
        when that record is from another board, BMC or firmware than the one
        validated at this start, like the stop helper refuses then. The record
        keeps only what is still held, so a failure after the release never puts
        a released position back under control.
        """

        managed = self.config.managed_positions
        others = [p for p in held if p not in managed]
        if not others:
            return
        if not recorded or dict(recorded) != self.identity:
            raise ConfigError(
                f"positions {others} are still held by an earlier run whose record is from another board, "
                "BMC or firmware; refusing to take control"
            )
        log(4, f"positions {others} are still under an earlier run's control and not managed now; restoring BMC auto")
        restore_auto(self.bmc, others)
        kept = [p for p in held if p in managed]
        write_control(
            self.paths, control=bool(kept), managed=kept, note="released positions not managed now", identity=recorded
        )
        log(6, f"positions {others} are back in BMC auto mode (read back)")

    # The controller holds the managed positions in manual mode from here on.
    def take_control(self) -> None:
        managed = self.config.managed_positions
        self._require_protected_auto(self.bmc.mode())
        self._claim("taking control")
        self.bmc.update("duty", dict.fromkeys(managed, FULL))
        self.bmc.update("mode", dict.fromkeys(managed, MANUAL))
        self._claim("manual")
        log(6, f"took control of positions {list(managed)} at {FULL}%")

    def _claim(self, note: str) -> None:
        """Record (before any write) that this controller holds the managed positions on this board."""

        write_control(
            self.paths, control=True, managed=self.config.managed_positions, note=note, identity=self.identity
        )
        self.control = True

    def _require_protected_auto(self, mode: Sequence[int]) -> None:
        busy = [p.sensor for p in self.config.protected if mode[p.position] != AUTO]
        if busy:
            raise ConfigError(f"protected fans {busy} are not in BMC auto mode; refusing to take control")

    def _write_duty(self, duty: int) -> None:
        self.bmc.update("duty", dict.fromkeys(self.config.managed_positions, duty))

    def restore_auto(self, note: str) -> None:
        restore_auto(self.bmc, self.config.managed_positions)
        write_control(self.paths, control=False, managed=self.config.managed_positions, note=note)
        self.control = False

    def _source(self, name: str, ok: bool, now: float, error: str = "") -> None:
        source = self.sources.setdefault(name, Source())
        if ok:
            source.failures = 0
            source.last_ok = now
            source.error = ""
        else:
            source.failures += 1
            source.error = error

    def read_inputs(self) -> None:
        """Every input: the slow ones (disks when due, scans) first, the hwmon ones last.

        Each source is stamped with the time it was read, and the hwmon sensors
        are read right before the decision, so a slow disk poll never leaves
        the CPU or NVMe value it acts on old.
        """

        config = self.config
        now = self.clock()
        due = self.last_hdd_poll is None or self.hdd_failed or now - self.last_hdd_poll >= config.hdd_interval_s
        if config.hdd and due:
            self.last_hdd_poll = now
            self.hdd_failed = False
            for drive in config.hdd:
                reading = read_hdd(drive, self.run)
                if reading.state == "error":
                    self.hdd_failed = True
                    previous = self.readings.hdd.get(drive.name)
                    # Keep the last good reading until the failure counts as a failsafe.
                    if previous is None or previous.state == "error":
                        self.readings.hdd[drive.name] = reading
                    self._source(drive.name, False, self.clock(), reading.error)
                else:
                    self.readings.hdd[drive.name] = reading
                    self._source(drive.name, True, self.clock())
        try:
            states = read_scan_states(config, self.run)
        except ValueError as exc:
            self.readings.scans = None
            self.scan_unknown = str(exc)
            if self.cycle % SUMMARY_EVERY == 0:
                log(4, f"scan state unavailable: {exc}")
        else:
            # A pool without a scan line feeds nothing forward, as before; only the calibration minds.
            self.readings.scans = {pool: bool(running) for pool, running in states.items()}
            unknown = [pool for pool, running in states.items() if running is None]
            self.scan_unknown = f"zpool status shows no scan line for {', '.join(unknown)}" if unknown else ""
        try:
            self.readings.cpu = read_cpu(config, self.paths)
            self._source("cpu", True, self.clock())
        except (OSError, ValueError) as exc:
            self.readings.cpu = None
            self._source("cpu", False, self.clock(), str(exc))
        for drive in config.nvme:
            try:
                self.readings.nvme[drive.name] = read_nvme(drive, self.paths)
                self._source(drive.name, True, self.clock())
            except (OSError, ValueError) as exc:
                self.readings.nvme.pop(drive.name, None)
                self._source(drive.name, False, self.clock(), str(exc))

    def _stale(self, name: str, interval: float, now: float) -> bool:
        source = self.sources.get(name)
        if source is None:
            return True
        limit = 3 * interval + self.config.interval_s
        return source.failures >= self.config.failure_cycles or source.last_ok is None or now - source.last_ok > limit

    def required(self) -> dict[str, float]:
        """The required inputs and their poll intervals."""

        config = self.config
        names = {"cpu": float(config.interval_s)}
        names.update({d.name: float(config.interval_s) for d in config.nvme})
        names.update({d.name: float(config.hdd_interval_s) for d in config.hdd})
        return names

    def failing_inputs(self, now: float) -> list[str]:
        return [name for name, interval in self.required().items() if self._stale(name, interval, now)]

    def check_stall(self) -> list[str]:
        """Managed fans that read no RPM or 0 RPM for ``stall_cycles`` cycles in a row."""

        stalled = []
        for position in self.config.managed:
            rpm = self.fan_rpm.get(position.sensor)
            if rpm is None or rpm <= 0:
                self.stall[position.sensor] = self.stall.get(position.sensor, 0) + 1
            else:
                self.stall[position.sensor] = 0
            if self.stall[position.sensor] >= self.config.stall_cycles:
                stalled.append(position.sensor)
        return stalled

    def step(self) -> dict[str, Any]:
        """One cycle: read, decide, (active) write, record."""

        config = self.config
        fans_error = ""
        try:
            self.fan_rpm = self.bmc.fans()
        except BmcError as exc:
            self.fan_rpm = {}
            fans_error = str(exc)
        self._source("fans", not fans_error, self.clock(), fans_error)
        self.read_inputs()
        now = self.clock()  # the time of the decision: every staleness counts up to here
        failing = self.failing_inputs(now)
        if config.mode == "active" and self._stale("fans", config.interval_s, now):
            failing.append("fans")
        stalled = self.check_stall() if config.mode == "active" else []
        target, reasons = demand(config, self.readings)
        failsafe = bool(failing or stalled)
        if failsafe:
            target = FULL
            reasons = [f"failsafe: {name}" for name in failing] + [f"stall: {name}" for name in stalled]
        before = self.slew.duty
        duty = self.slew.next(target, config, failsafe=failsafe)
        if self.control and duty != before:
            self._write_duty(duty)
        if self.cycle % SUMMARY_EVERY == 0 or self.managed_auto is None:
            self._refresh_bmc_state()
        # Not in control, the managed fans should be in BMC auto mode; anything else
        # (control an earlier run left, someone else's manual mode) needs a look.
        foreign = not self.control and self.managed_auto == 0
        unhealthy = failsafe or self._stale("fans", config.interval_s, now) or bool(self.leftover) or foreign
        spinning = {n: r.celsius for n, r in self.readings.hdd.items() if r.state == "active" and r.celsius is not None}
        values: dict[str, float | int | None] = {
            "duty_pct": duty,
            "target_pct": target,
            "healthy": int(not unhealthy),
            "failsafe": int(failsafe),
            "bmc_control": int(self.control),
            "managed_auto": self.managed_auto,
            "hdd_max_c": max(spinning.values()) if spinning else None,
            "hdd_active": len(spinning),
            "scan_active": None if self.readings.scans is None else int(any(self.readings.scans.values())),
        }
        write_metrics(self.paths, values)
        status = {
            "ts": int(time.time()),
            "mode": config.mode,
            "cycle": self.cycle,
            "pid": os.getpid(),
            "reasons": reasons,
            "failing": failing,
            "stalled": stalled,
            "bmc_writes": self.bmc.writes,
            "cpu_c": self.readings.cpu,
            "nvme_c": dict(self.readings.nvme),
            "hdd": {n: {"state": r.state, "celsius": r.celsius} for n, r in self.readings.hdd.items()},
            "scans": self.readings.scans,
            "fans_rpm": {p.sensor: self.fan_rpm.get(p.sensor) for p in (*config.managed, *config.protected)},
            "errors": {name: s.error for name, s in self.sources.items() if s.error},
            "leftover_control": self.leftover,
            **values,
        }
        atomic_write(self.paths.status_file, json.dumps(status, sort_keys=True) + "\n")
        self._log_cycle(values, reasons, failing, stalled)
        notify(f"WATCHDOG=1\nSTATUS={config.mode}: duty {duty}% target {target}% ({', '.join(reasons)})")
        self.cycle += 1
        return status

    def _refresh_bmc_state(self) -> None:
        """Re-read the mode bytes; in control, put back what someone else changed on the managed fans."""

        managed = self.config.managed_positions
        if self.control:
            mode = self.bmc.mode()
            if any(mode[p] != MANUAL for p in managed):
                log(4, f"managed fans left manual mode ({_hex(mode)}); taking them back")
                self.bmc.update("mode", dict.fromkeys(managed, MANUAL))
            duty = self.bmc.duty()
            if any(duty[p] != self.slew.duty for p in managed):
                log(4, f"managed fan duty changed behind the controller ({_hex(duty)}); writing it again")
                self.bmc.update("duty", dict.fromkeys(managed, self.slew.duty))
            self.managed_auto = 0
            return
        try:
            mode = self.bmc.mode()
        except BmcError as exc:
            log(4, f"cannot read the BMC fan mode: {exc}")
            self.managed_auto = None
            return
        self.managed_auto = int(all(mode[p] == AUTO for p in managed))
        if not self.managed_auto:
            mode_name = self.config.mode
            log(4, f"managed fan positions are not in BMC auto mode ({_hex(mode)}); {mode_name} mode leaves them")

    def _log_cycle(self, values: dict[str, Any], reasons: list[str], failing: list[str], stalled: list[str]) -> None:
        key = (values["duty_pct"], values["target_pct"], values["failsafe"], tuple(failing), tuple(stalled))
        verb = "set" if self.control else "would set"
        if key != self.last_logged:
            level = 4 if failing or stalled else 6
            log(level, f"{verb} {values['duty_pct']}% (target {values['target_pct']}%: {', '.join(reasons)})")
            self.last_logged = key
        elif self.cycle % SUMMARY_EVERY == 0:
            log(6, f"{verb} {values['duty_pct']}% (target {values['target_pct']}%: {', '.join(reasons)})")

    def wait(self, seconds: float) -> None:
        end = self.clock() + seconds
        while not self.stop:
            left = end - self.clock()
            if left <= 0:
                return
            self.sleep(min(SLEEP_CHUNK, left))
            notify("WATCHDOG=1")

    def loop(self, cycles: int | None = None) -> None:
        done = 0
        while not self.stop and (cycles is None or done < cycles):
            started = self.clock()
            self.step()
            done += 1
            if cycles is not None and done >= cycles:
                break
            self.wait(self.config.interval_s - (self.clock() - started))


def restore_auto(bmc: Bmc, managed: Sequence[int]) -> None:
    """Managed positions back to BMC auto, every other byte as read just before each attempt; read back."""

    bmc.update("mode", dict.fromkeys(managed, AUTO))


def force_full(bmc: Bmc, managed: Sequence[int]) -> None:
    """Managed positions to manual at 100 %, every other byte as read just before each attempt; read back."""

    bmc.update("duty", dict.fromkeys(managed, FULL))
    bmc.update("mode", dict.fromkeys(managed, MANUAL))


# -- calibration ---------------------------------------------------------------------


class CalibrationAbort(Exception):
    pass


class Calibrator:
    """Header mapping and a duty staircase on the managed positions, then the BMC as it was."""

    def __init__(self, controller: Controller) -> None:
        self.c = controller
        assert controller.config.calibration is not None
        self.cal = controller.config.calibration
        # Whether a write command reached the BMC (until then a failure is a skip).
        self.wrote = False

    def _guard(self) -> None:
        """Abort unless every required input reads, the scan state of every configured pool is
        known and no scan runs, and the curves ask for less than ``abort_target_pct``."""

        c = self.c
        c.read_inputs()
        now = c.clock()
        # No grace while the fans run below the controller's duty: a source that failed
        # its latest read counts, not only one that failed failure_cycles times.
        latest = {name for name in c.required() if (source := c.sources.get(name)) is not None and source.failures}
        failing = sorted(set(c.failing_inputs(now)) | latest)
        if failing:
            raise CalibrationAbort(f"required inputs failing: {', '.join(failing)}")
        # Fail closed: an unreadable scan state is not "no scan running".
        if c.config.scan_pools and (c.readings.scans is None or c.scan_unknown):
            raise CalibrationAbort(f"scan state unknown: {c.scan_unknown or 'zpool status not read'}")
        if c.readings.scans and any(c.readings.scans.values()):
            raise CalibrationAbort("a scrub or resilver is running")
        target, reasons = demand(c.config, c.readings)
        if target >= self.cal.abort_target_pct:
            raise CalibrationAbort(f"the curves ask for {target}% ({', '.join(reasons)})")

    def _sample(self, seconds: float, mode0: Sequence[int], *, stall: bool = False) -> dict[str, list[float | None]]:
        """RPM samples of the managed fans after ``settle_s``; aborts when an input fails or warms up
        (:meth:`_guard`), when an unmanaged mode byte changes and, with ``stall``, as soon as a
        managed fan reads no RPM or 0 RPM."""

        samples: dict[str, list[float | None]] = {p.sensor: [] for p in self.c.config.managed}
        end = self.c.clock() + seconds
        start = self.c.clock()
        while not self.c.stop:
            now = self.c.clock()
            if now >= end:
                break
            self._guard()
            mode = self.c.bmc.mode()
            unmanaged = [i for i in range(POSITIONS) if i not in self.c.config.managed_positions]
            if any(mode[i] != mode0[i] for i in unmanaged):
                raise CalibrationAbort(f"an unmanaged fan mode byte changed ({_hex(mode)})")
            fans = self.c.bmc.fans()
            if now - start >= self.cal.settle_s:
                for position in self.c.config.managed:
                    rpm = fans.get(position.sensor)
                    samples[position.sensor].append(rpm)
                    if stall and (rpm is None or rpm <= 0):
                        raise CalibrationAbort(f"{position.sensor} stopped ({rpm})")
            self.c.wait(min(self.cal.sample_interval_s, max(0.0, end - self.c.clock())))
        if self.c.stop:
            raise CalibrationAbort("stopped")
        return samples

    def _write(self, kind: str, values: dict[int, int]) -> None:
        """Change only ``values``' positions of the mode or duty bytes (fresh read per attempt); read back."""

        writes = self.c.bmc.writes
        try:
            self.c.bmc.update(kind, values)
        finally:
            self.wrote = self.wrote or self.c.bmc.writes != writes

    def run(self) -> dict[str, Any]:
        config = self.c.config
        bmc = self.c.bmc
        managed = config.managed_positions
        mode0 = bmc.mode()
        duty0 = bmc.duty()
        self.c._require_protected_auto(mode0)
        if any(mode0[p] != AUTO for p in config.managed_positions):
            raise ConfigError("calibration needs every managed fan in BMC auto mode first")
        # Before the BMC is touched: inputs, scans and temperatures allow it (else skipped, retried next start).
        self._guard()
        report: dict[str, Any] = {
            "id": self.cal.id,
            "started": int(time.time()),
            "mode_before": _hex(mode0),
            "duty_before": _hex(duty0),
            "mapping": {},
            "steps": [],
        }
        self.c._claim("calibrating")
        try:
            baseline = self._sample(self.cal.sample_interval_s * 2 + self.cal.settle_s, mode0)
            base_max = {s: max((v or 0.0) for v in values) if values else 0.0 for s, values in baseline.items()}
            for position in config.managed:
                self._write("duty", {position.position: FULL})
                self._write("mode", {position.position: MANUAL})
                samples = self._sample(self.cal.mapping_hold_s, mode0)
                self._write("mode", {position.position: mode0[position.position]})
                self._write("duty", {position.position: duty0[position.position]})
                peak = {s: max((v or 0.0) for v in values) if values else 0.0 for s, values in samples.items()}
                rise = peak[position.sensor] - base_max[position.sensor]
                others = {s: peak[s] - base_max[s] for s in peak if s != position.sensor}
                mapping = {"sensor": position.sensor, "rise_rpm": rise, "others": others}
                report["mapping"][str(position.position)] = mapping
                if rise < 2 * self.cal.tach_step_rpm:
                    raise CalibrationAbort(f"position {position.position} did not raise {position.sensor}")
                if any(delta > self.cal.tach_step_rpm for delta in others.values()):
                    raise CalibrationAbort(f"position {position.position} also raised another managed fan")
            self._write("duty", dict.fromkeys(managed, self.cal.steps_pct[0]))
            self._write("mode", dict.fromkeys(managed, MANUAL))
            for index, duty in enumerate(self.cal.steps_pct):
                if index:
                    self._write("duty", dict.fromkeys(managed, duty))
                step: dict[str, Any] = {"duty_pct": duty, "rpm": {}}
                try:
                    samples = self._sample(self.cal.step_hold_s, mode0, stall=True)
                except CalibrationAbort:
                    report["steps"].append(step)
                    raise
                for sensor, values in samples.items():
                    if not values or any(v is None or v <= 0 for v in values):
                        step["rpm"][sensor] = None
                        report["steps"].append(step)
                        raise CalibrationAbort(f"{sensor} stalled at {duty}%")
                    numbers = [v for v in values if v is not None]
                    spread = max(numbers) - min(numbers)
                    mean = sum(numbers) / len(numbers)
                    step["rpm"][sensor] = {"min": min(numbers), "max": max(numbers), "mean": mean}
                    if spread >= self.cal.oscillation_steps * self.cal.tach_step_rpm:
                        report["steps"].append(step)
                        raise CalibrationAbort(f"{sensor} oscillated by {spread:.0f} RPM at {duty}%")
                report["steps"].append(step)
            report["result"] = "ok"
        except (CalibrationAbort, BmcError) as exc:
            report["result"] = "aborted" if self.wrote else "skipped"
            report["reason"] = str(exc)
            log(4, f"calibration {report['result']}: {exc}")
        finally:
            try:
                self._write("mode", {p: mode0[p] for p in managed})
                self._write("duty", {p: duty0[p] for p in managed})
                write_control(self.c.paths, control=False, managed=config.managed_positions, note="calibration done")
                self.c.control = False
                report["restored"] = True
            except BmcError as exc:
                report["restored"] = False
                log(3, f"could not restore the BMC after calibration: {exc}")
            report["finished"] = int(time.time())
            report["suggested_floor_pct"] = _suggested_floor(report, self.cal)
            atomic_write(self.c.paths.calibration_file, json.dumps(report, indent=1, sort_keys=True) + "\n", 0o640)
        if not report["restored"]:
            raise BmcError("the BMC could not be restored after calibration")
        return report


def _suggested_floor(report: dict[str, Any], cal: Calibration) -> int | None:
    good = []
    for step in report.get("steps", []):
        rpm = step.get("rpm", {})
        if rpm and all(v is not None and v["min"] >= cal.min_rpm for v in rpm.values()):
            good.append(step["duty_pct"])
    return min(good) if good and report.get("result") == "ok" else None


# -- entry points --------------------------------------------------------------------


def cmd_run(config: Config, paths: Paths, run: Runner, controller: Controller | None = None) -> int:
    controller = controller or Controller(config, paths, run)

    def request_stop(signum: int, _frame: Any) -> None:
        controller.stop = True

    previous_handlers = {sig: signal.signal(sig, request_stop) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        return _run(controller)
    finally:
        for sig, handler in previous_handlers.items():
            signal.signal(sig, handler)


def _run(controller: Controller) -> int:
    config = controller.config
    paths = controller.paths
    previous = read_control(paths)
    held = [p for p in previous.get("managed", []) if isinstance(p, int) and 0 <= p < POSITIONS]
    held = held if previous.get("control") else []
    recorded = previous.get("identity") if isinstance(previous.get("identity"), dict) else {}
    try:
        controller.identity = read_identity(controller.bmc, paths)
        check_board(config, controller.identity)
    except ConfigError as exc:
        if held:
            log(3, f"positions {held} stay as an earlier run left them: this board is not the configured one")
        log(3, f"refusing to start: {exc}")
        return EXIT_CONFIG
    except BmcError as exc:
        log(3, f"cannot read the BMC identity yet: {exc}")
        return EXIT_BMC
    try:
        if config.mode == "active":
            controller.release_unmanaged(held, recorded)
            controller.take_control()
        elif held:
            # An earlier active or calibrate run still holds these positions (its stop did not
            # restore them). observe and calibrate never write: the state stays recorded, so
            # the stop helper releases them at this run's clean stop; until then unhealthy.
            controller.leftover = held
            log(4, f"positions {held} are still under an earlier run's control; {config.mode} does not write them")
        else:
            write_control(paths, control=False, managed=config.managed_positions, note=f"starting {config.mode}")
        notify("READY=1")
        if config.mode == "calibrate":
            _calibrate_once(controller)
        log(6, f"started in {config.mode} mode (interval {config.interval_s}s, HDD every {config.hdd_interval_s}s)")
        controller.loop()
    except ConfigError as exc:
        log(3, f"refusing: {exc}")
        if controller.control:
            return _restore_or_fail(controller, "config refusal")
        return EXIT_CONFIG
    except BmcError as exc:
        if not controller.control:
            log(3, f"BMC failure: {exc}")
            return EXIT_BMC
        log(3, f"BMC failure: {exc}; restoring BMC auto on the managed fans")
        return _restore_or_fail(controller, "bmc failure")
    notify("STOPPING=1")
    log(6, "stopping")
    return 0


def _restore_or_fail(controller: Controller, why: str) -> int:
    try:
        controller.restore_auto(f"{why}: auto restored")
        log(4, "managed fans are back in BMC auto mode (read back)")
    except BmcError as exc:
        log(3, f"could not restore BMC auto: {exc}")
    return EXIT_BMC


def _calibrate_once(controller: Controller) -> None:
    cal = controller.config.calibration
    assert cal is not None
    try:
        done = json.loads(controller.paths.calibration_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        done = {}
    if isinstance(done, dict) and done.get("id") == cal.id and done.get("result") != "skipped":
        log(6, f"calibration {cal.id} already ran ({done.get('result')}); observing")
        return
    if controller.leftover:
        # Claiming would overwrite the state the stop helper needs to release those fans.
        held = controller.leftover
        log(4, f"calibration {cal.id} skipped: positions {held} are still under an earlier run's control")
        return
    try:
        report = Calibrator(controller).run()
    except CalibrationAbort as exc:
        # Nothing was written; the same id runs at the next start.
        skipped = {"id": cal.id, "result": "skipped", "reason": str(exc), "finished": int(time.time())}
        atomic_write(controller.paths.calibration_file, json.dumps(skipped, indent=1, sort_keys=True) + "\n", 0o640)
        log(4, f"calibration {cal.id} skipped: {exc}; observing")
        return
    log(6, f"calibration {cal.id}: {report['result']}, suggested floor {report.get('suggested_floor_pct')}")


def cmd_stop_post(paths: Paths, run: Runner, service_result: str, sleep: Callable[[float], None] = time.sleep) -> int:
    """ExecStopPost: act only when this controller held the BMC (whatever the config says now)."""

    state = read_control(paths)
    managed = [p for p in state.get("managed", []) if isinstance(p, int) and 0 <= p < POSITIONS]
    try:
        write_metrics(paths, {"healthy": 0, "failsafe": 0, "bmc_control": int(bool(state.get("control")))})
    except OSError as exc:
        log(4, f"cannot write metrics: {exc}")
    if not state.get("control") or not managed:
        log(6, f"stop ({service_result or 'unknown'}): no BMC control held; nothing to restore")
        return 0
    bmc = Bmc(run, sleep)
    recorded = state.get("identity") or {}
    try:
        found = read_identity(bmc, paths)
    except (ConfigError, BmcError) as exc:
        log(3, f"stop: cannot read the board and BMC identity ({exc}); positions {managed} are left as they are")
        return 1
    if not recorded or found != recorded:
        log(3, f"stop: the board, BMC or firmware is not the one control was taken on; positions {managed} are left")
        return 1
    if service_result == "success":
        try:
            restore_auto(bmc, managed)
            write_control(paths, control=False, managed=managed, note="clean stop: auto restored")
            write_metrics(paths, {"healthy": 0, "failsafe": 0, "bmc_control": 0})
            log(6, f"clean stop: positions {managed} back in BMC auto mode (read back)")
            return 0
        except BmcError as exc:
            log(3, f"clean stop: could not restore BMC auto: {exc}")
            return 1
    try:
        force_full(bmc, managed)
        write_control(paths, control=True, managed=managed, note=f"{service_result}: failsafe 100%", identity=recorded)
        write_metrics(paths, {"healthy": 0, "failsafe": 1, "bmc_control": 1})
        log(4, f"stop after {service_result or 'unknown'}: positions {managed} at {FULL}% (read back)")
        return 0
    except BmcError as exc:
        log(3, f"stop after {service_result}: could not set {FULL}%: {exc}; restoring BMC auto")
    try:
        restore_auto(bmc, managed)
        write_control(paths, control=False, managed=managed, note=f"{service_result}: auto restored")
        write_metrics(paths, {"healthy": 0, "failsafe": 0, "bmc_control": 0})
        return 0
    except BmcError as exc:
        log(3, f"could not restore BMC auto either: {exc}")
        return 1


def main(argv: Sequence[str] | None = None, paths: Paths | None = None) -> int:
    parser = argparse.ArgumentParser(prog="drive-fan-control")
    parser.add_argument("command", choices=("run", "stop-post", "check-config"))
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args(argv)
    paths = paths or Paths()
    if args.command == "stop-post":
        # The runtime state decides, not the config: it may already be the next one.
        return cmd_stop_post(paths, Runner(paths.exec_path), os.environ.get("SERVICE_RESULT", ""))
    try:
        config = load_config(args.config)
    except ConfigError as exc:
        log(3, f"invalid configuration: {exc}")
        return EXIT_CONFIG
    if args.command == "check-config":
        print(f"ok: mode {config.mode}, managed {list(config.managed_positions)}")
        return 0
    return cmd_run(config, paths, Runner(paths.exec_path, after=lambda: notify("WATCHDOG=1")))


if __name__ == "__main__":
    sys.exit(main())
