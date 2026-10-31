"""Read bounded process-exit/resource metadata in the admitted synthetic guest."""

from __future__ import annotations

from collections.abc import Callable
from functools import partial
from typing import Any

from .fixture import write
from .matter_ready import PROPERTIES, bounded_command

LABELS = frozenset({"32-voice-current", "33-voice-missing-stt", "34-voice-recovery"})
CGROUPS = ("/sys/fs/cgroup", "/sys/fs/cgroup/system.slice/homeassistant.service")
MEMORY_FILES = ("memory.events", "memory.events.local", "memory.current", "memory.max", "memory.peak")


def capture(label: str, point: str) -> dict[str, Any]:
    """No application journal, registry, configuration, model/audio or user body."""
    if label not in LABELS or point not in {"before", "after"}:
        raise ValueError("unexpected owned voice diagnostic point")
    collectors: dict[str, Callable[[], Any]] = {
        "namespace": lambda: bounded_command(
            ["readlink", "/proc/1/ns/cgroup", "/proc/self/ns/cgroup", "/proc/1/ns/pid", "/proc/self/ns/pid"],
            timeout=5,
        ),
        "cgroup_membership": lambda: bounded_command(["cat", "/proc/1/cgroup", "/proc/self/cgroup"], timeout=5),
        "units": lambda: bounded_command(
            [
                "systemctl",
                "show",
                "homeassistant.service",
                "matter-server.service",
                "--property="
                + PROPERTIES
                + ",ControlGroup,ExecMainStartTimestampMonotonic,ExecMainExitTimestampMonotonic",
            ],
            timeout=5,
        ),
        "journal_service": lambda: bounded_command(
            ["systemctl", "show", "systemd-journald.service", "--property=" + PROPERTIES], timeout=5
        ),
        "manager_journal": lambda: bounded_command(
            [
                "journalctl",
                "--no-pager",
                "--unit=homeassistant.service",
                "_PID=1",
                "--lines=100",
                "--output=short-monotonic",
            ],
            timeout=10,
        ),
    }
    for index, root in enumerate(CGROUPS):
        # Fixed owned container/root and fixed HA unit paths, never a path from
        # application configuration or a process-provided journal body.
        collectors[f"memory_{index}"] = partial(
            bounded_command,
            ["head", "-v", "-c", "4096", *(root + "/" + name for name in MEMORY_FILES)],
            timeout=5,
        )
    result: dict[str, Any] = {
        "label": label,
        "point": point,
        "scope": "admitted owned shared-kernel guest; fixed root and HA unit cgroups; PID1 manager journal only",
        "journal_limit": (
            "Unavailable or empty journal is missing evidence, not proof of no exit/restart; no service activated."
        ),
        "resource_limit": "unchanged run-owned 2CPU/6GiB/2048PIDs; no limit mutation",
    }
    for name, collect in collectors.items():
        try:
            result[name] = collect()
        except Exception as error:
            result[name] = {"collection_failed": True, "error_type": type(error).__name__}
    write("voice-" + label + "-" + point + ".json", result)
    return result
