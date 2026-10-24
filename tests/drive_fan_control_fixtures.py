"""A fake host for ``files/drive_fan_control.py``: fake executables, a sysfs tree, a clock.

The fake ``ipmitool``, ``hdparm``, ``smartctl`` and ``zpool`` are one Python
script (four links to it) that answers from ``state.json`` next to it and
appends every call to ``calls.jsonl``. ``ipmitool`` keeps the BMC's 16 mode and
16 duty bytes in the state, so writes change what later reads return, unless
the state says to fail or ignore them. The controller runs them through its
real :class:`Runner` (``subprocess``, timeouts, a clean environment).
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any

from ops_deploy.services.thermal_monitoring.fan_control import controller_module

DFC: ModuleType = controller_module()
DEV_NVME = "/dev/disk/by-id/nvme-Example_NVMe_0001"
DEV_HDD1 = "/dev/disk/by-id/ata-Example_HDD_0001"
DEV_HDD2 = "/dev/disk/by-id/ata-Example_HDD_0002"
MODE0 = [0] * 16
DUTY0 = [0x14, 0x14] + [0x1E] * 14
MC_INFO = """Device ID                 : 32
Device Revision           : 1
Firmware Revision         : 6.09
IPMI Version              : 2.0
Manufacturer ID           : 49622
Manufacturer Name         : Example Rack Incorporation
Product ID                : 8217 (0x2019)
Product Name              : Unknown (0x2019)
Device Available          : yes
Additional Device Support :
    Sensor Device
Aux Firmware Rev Info     :
    0x00
"""

FAKE = r"""#!{python}
import json, os, sys, time
here = os.path.dirname(os.path.abspath(sys.argv[0]))
tool = os.path.basename(sys.argv[0])
args = sys.argv[1:]
with open(os.path.join(here, "calls.jsonl"), "a") as log:
    log.write(json.dumps([tool, *args]) + "\n")
path = os.path.join(here, "state.json")
with open(path) as f:
    state = json.load(f)
def save():
    with open(path, "w") as f:
        json.dump(state, f)
def fail(key):
    rc = state.get("fail", {}).get(key)
    if rc:
        sys.stderr.write(f"fake {tool} {key} failure\n")
        sys.exit(rc)
if state.get("sleep", {}).get(tool):
    time.sleep(state["sleep"][tool])
if tool == "ipmitool":
    assert args[:2] == ["-I", "open"], args
    args = args[2:]
    if state.get("noise"):
        sys.stderr.write("Received a response with unexpected ID 0 vs. 1\n")
    if args == ["mc", "info"]:
        fail("mc")
        sys.stdout.write(state["mc_info"])
    elif args == ["sdr", "type", "fan"]:
        fail("sdr")
        for sensor, position in state["positions"].items():
            rpm = state["fans"].get(sensor)
            if position is not None and state["mode"][position] == 2:
                duty = state["duty"][position]
                rpm = state.get("manual_rpm", {}).get(sensor, {}).get(str(duty), 400 + 12 * duty)
            reading = "No Reading" if rpm is None else f"{rpm} RPM"
            print(f"{sensor:<16} | 11h | ok  |  7.0 | {reading}")
    elif args[:3] == ["raw", "0x3a", "0xd0"]:
        command = args[3]
        if command in ("0x12", "0x0f"):
            fail("get_mode" if command == "0x12" else "get_duty")
            key = "mode" if command == "0x12" else "duty"
            state["reads"] = state.get("reads", 0) + 1
            drift = state.get("drift_mode_after_reads")
            if key == "mode" and drift is not None and state["reads"] > drift and not state.get("drifted"):
                # Someone else switches another fan to manual, once.
                state["mode"][state.get("drift_position", 5)] = 2
                state["drifted"] = True
            save()
            print(" " + " ".join(f"{b:02x}" for b in state[key]))
        elif command in ("0x11", "0x0e"):
            key = "mode" if command == "0x11" else "duty"
            fail("set_" + key)
            values = [int(v, 16) for v in args[4:]]
            assert len(values) == 16, values
            if key not in state.get("ignore_set", []):
                state[key] = values
                drift = state.get("drift_on_write")
                if drift and drift["kind"] == key and not state.get("drifted_on_write"):
                    # Someone else changes another byte right after this write, once.
                    state[key][drift["position"]] = drift["value"]
                    state["drifted_on_write"] = True
                save()
        else:
            sys.exit(1)
    else:
        sys.exit(1)
elif tool == "hdparm":
    assert args[0] == "-C", args
    answer = state["hdparm"][args[1]]
    if isinstance(answer, dict):
        sys.exit(answer["rc"])
    print(f"\n{args[1]}:\n drive state is:  {answer}")
elif tool == "smartctl":
    assert args[:4] == ["-n", "standby", "-d", "sat"] and args[4:6] == ["-A", "-j"], args
    answer = state["smart"][args[6]]
    if answer == "standby":
        message = {"string": "Device is in STANDBY mode, exit(2)"}
        print(json.dumps({"smartctl": {"exit_status": 2, "messages": [message]}}))
        sys.exit(2)
    if answer == "garbage":
        print("not json")
        sys.exit(4)
    if isinstance(answer, dict) and "attr194" in answer:
        table = [{"id": 194, "raw": {"value": 0, "string": answer["attr194"]}}]
        print(json.dumps({"ata_smart_attributes": {"table": table}}))
        sys.exit(answer.get("rc", 0))
    print(json.dumps({"temperature": {"current": answer["temp"]}}))
    sys.exit(answer.get("rc", 0))
elif tool == "zpool":
    zpool = state["zpool"]
    if zpool.get("rc"):
        sys.exit(zpool["rc"])
    assert args[:2] == ["status", "-p"], args
    for pool in args[2:]:
        scan = zpool["pools"].get(pool)
        if scan is None:
            continue
        print(f"  pool: {pool}\n state: ONLINE\n  scan: {scan}\nconfig:\n")
"""


@dataclass
class Clock:
    now: float = 1000.0

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += max(seconds, 0.0)


class FakeHost:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.bin = root / "bin"
        self.bin.mkdir()
        script = self.bin / "fake_tool.py"
        script.write_text(FAKE.replace("{python}", sys.executable))
        script.chmod(0o755)
        for tool in ("ipmitool", "hdparm", "smartctl", "zpool"):
            (self.bin / tool).symlink_to(script)
        self.state: dict[str, Any] = {
            "mode": list(MODE0),
            "duty": list(DUTY0),
            "mc_info": MC_INFO,
            "positions": {"FAN1_1": 0, "FAN2_1": 1, "FAN3_1": 2, "FAN6_1": 5},
            "fans": {"FAN1_1": 400, "FAN2_1": 400, "FAN3_1": 400, "FAN6_1": 800},
            "hdparm": {DEV_HDD1: "standby", DEV_HDD2: "standby"},
            "smart": {DEV_HDD1: {"temp": 41}, DEV_HDD2: {"temp": 45}},
            "zpool": {"pools": {"tank": "scrub repaired 0B in 14:46:07 with 0 errors", "fast": "none requested"}},
        }
        self.save()
        sys_root = root / "sys"
        hwmon = sys_root / "class" / "hwmon"
        cpu = hwmon / "hwmon0"
        cpu.mkdir(parents=True)
        (cpu / "name").write_text("k10temp\n")
        (cpu / "temp1_label").write_text("Tctl\n")
        self.set_cpu(42.5)
        controller = sys_root / "devices" / "pci0000:00" / "nvme" / "nvme0"
        controller.mkdir(parents=True)
        nvme = hwmon / "hwmon1"
        nvme.mkdir()
        (nvme / "name").write_text("nvme\n")
        (nvme / "device").symlink_to(controller)
        (nvme / "temp1_label").write_text("Composite\n")
        (nvme / "temp2_label").write_text("Sensor 1\n")
        (nvme / "temp2_input").write_text("55850\n")
        self.set_nvme(44.85)
        block = sys_root / "class" / "block" / "nvme0n1"
        block.mkdir(parents=True)
        (block / "device").symlink_to(controller)
        dev = root / "dev"
        (dev / "disk" / "by-id").mkdir(parents=True)
        (dev / "nvme0n1").write_text("")
        (dev / "disk" / "by-id" / "nvme-Example_NVMe_0001").symlink_to(dev / "nvme0n1")
        dmi = sys_root / "class" / "dmi" / "id"
        dmi.mkdir(parents=True)
        (dmi / "board_vendor").write_text("ExampleRack\n")
        (dmi / "board_name").write_text("EX650D4U\n")
        self.paths = DFC.Paths(
            hwmon=hwmon,
            block=sys_root / "class" / "block",
            dmi=dmi,
            run_dir=root / "run" / "drive-fan-control",
            lib_dir=root / "var" / "lib" / "drive-fan-control",
            exec_path=f"{self.bin}:/usr/bin:/bin",
            dev_root=root,
        )
        self.clock = Clock()

    def save(self) -> None:
        (self.bin / "state.json").write_text(json.dumps(self.state))

    def load(self) -> dict[str, Any]:
        state: dict[str, Any] = json.loads((self.bin / "state.json").read_text())
        return state

    def update(self, **changes: Any) -> None:
        self.state = {**self.load(), **changes}
        self.save()

    def set_cpu(self, celsius: float) -> None:
        (self.root / "sys" / "class" / "hwmon" / "hwmon0" / "temp1_input").write_text(f"{round(celsius * 1000)}\n")

    def set_nvme(self, celsius: float) -> None:
        (self.root / "sys" / "class" / "hwmon" / "hwmon1" / "temp1_input").write_text(f"{round(celsius * 1000)}\n")

    def calls(self, tool: str | None = None) -> list[list[str]]:
        path = self.bin / "calls.jsonl"
        if not path.exists():
            return []
        calls = [json.loads(line) for line in path.read_text().splitlines()]
        return [c for c in calls if tool is None or c[0] == tool]

    def bmc_writes(self) -> list[list[str]]:
        """Every ``ipmitool raw 0x3a 0xd0 0x11|0x0e`` (mode or duty write), in order."""

        return [c for c in self.calls("ipmitool") if c[3:6] == ["raw", "0x3a", "0xd0"] and c[6] in ("0x11", "0x0e")]

    def runner(self) -> Any:
        return DFC.Runner(self.paths.exec_path)

    def controller(self, config: Any) -> Any:
        return DFC.Controller(config, self.paths, self.runner(), clock=self.clock, sleep=self.clock.sleep)

    def metric(self, name: str) -> str:
        return str((self.paths.metrics_dir / name).read_text().strip())

    def status(self) -> dict[str, Any]:
        status: dict[str, Any] = json.loads(self.paths.status_file.read_text())
        return status

    def control(self) -> dict[str, Any]:
        return dict(DFC.read_control(self.paths))


def config_dict(**changes: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "version": 1,
        "mode": "observe",
        "backend": "asrock_rack_ast2600",
        "board": {
            "dmi_board_vendor": "ExampleRack",
            "dmi_board_name": "EX650D4U",
            "bmc_manufacturer_id": 49622,
            "bmc_product_id": 8217,
            "bmc_firmware": ["6.09"],
        },
        "managed": [
            {"position": 0, "sensor": "FAN1_1"},
            {"position": 1, "sensor": "FAN2_1"},
            {"position": 2, "sensor": "FAN3_1"},
        ],
        "protected": [{"position": 5, "sensor": "FAN6_1"}],
        "floor_pct": 35,
        "interval_s": 30,
        "hdd_interval_s": 300,
        "cpu": {"hwmon_name": "k10temp", "label": "Tctl"},
        "nvme": [{"name": "fast-nvme", "device": DEV_NVME}],
        "hdd": [
            {"name": "tank-hdd-1", "device": DEV_HDD1, "smart_type": "sat"},
            {"name": "tank-hdd-2", "device": DEV_HDD2, "smart_type": "sat"},
        ],
        "scan_pools": [{"pool": "tank", "min_pct": 60}, {"pool": "fast", "min_pct": 85}],
        "curves": {
            "hdd": [[36, 35], [40, 45], [44, 75], [47, 100]],
            "nvme": [[48, 35], [55, 50], [65, 80], [72, 100]],
            "cpu": [[60, 35], [75, 60], [85, 100]],
        },
        "decrease_step_pct": 5,
        "decrease_hold_cycles": 3,
        "min_change_pct": 3,
        "failure_cycles": 2,
        "stall_cycles": 2,
    }
    data.update(changes)
    return data


CALIBRATION: dict[str, Any] = {
    "id": "first",
    "mapping_hold_s": 30,
    "steps_pct": [100, 50, 30],
    "step_hold_s": 30,
    "sample_interval_s": 5,
    "settle_s": 10,
    "tach_step_rpm": 400,
    "oscillation_steps": 2,
    "min_rpm": 600,
    "abort_target_pct": 60,
}


def config(**changes: Any) -> Any:
    return DFC.parse_config(config_dict(**changes))


def no_backslashes(calls: list[list[str]]) -> bool:
    return all("\\" not in word for call in calls for word in call)


def env_without_notify(func: Callable[[], Any]) -> Any:
    saved = os.environ.pop("NOTIFY_SOCKET", None)
    try:
        return func()
    finally:
        if saved is not None:
            os.environ["NOTIFY_SOCKET"] = saved
