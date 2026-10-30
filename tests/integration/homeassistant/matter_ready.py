"""Bounded startup evidence for the synthetic owned Matter service only."""

from __future__ import annotations

import contextlib
import math
import os
import selectors
import signal
import socket
import stat
import subprocess
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .fixture import write

LIMIT = 1024 * 1024
PROPERTIES = "Id,LoadState,ActiveState,SubState,MainPID,Result,ExecMainCode,ExecMainStatus,NRestarts"
LOG = Path("/home/homeassistant/site/logs/matter-server.log")


def bounded_command(argv: list[str], *, timeout: float = 5) -> dict[str, Any]:
    """Drain at most 1MiB; kill/reap this owned command group on limit/timeout."""
    output = bytearray()
    limited = False
    timed_out = False
    reaped = False
    deadline = time.monotonic() + timeout
    with subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True) as process:
        assert process.stdout is not None
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        timed_out = True
                        break
                    if not selector.select(remaining):
                        timed_out = True
                        break
                    chunk = os.read(process.stdout.fileno(), min(65536, LIMIT + 1 - len(output)))
                    if not chunk:
                        break
                    output.extend(chunk)
                    if len(output) > LIMIT:
                        limited = True
                        break
                if not limited and not timed_out:
                    try:
                        process.wait(timeout=max(0.001, deadline - time.monotonic()))
                        reaped = True
                    except subprocess.TimeoutExpired:
                        timed_out = True
        finally:
            # Keep the leader unreaped until signalling, so its group ID cannot
            # be recycled. A normally completed/reaped command needs no signal.
            if not reaped:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
    return {
        "exit": process.returncode,
        "output": bytes(output[:LIMIT]).decode("utf-8", errors="replace"),
        "truncated": limited,
        "timed_out": timed_out,
    }


def observe(*, timeout: float = 5) -> dict[str, Any]:
    result = bounded_command(
        ["systemctl", "show", "matter-server.service", "--property=" + PROPERTIES], timeout=timeout
    )
    fields = dict(line.split("=", 1) for line in result.pop("output").splitlines() if "=" in line)
    fields = {name: value for name, value in fields.items() if name in PROPERTIES.split(",") and len(value) <= 256}
    return {"command": result, "properties": {name: fields.get(name) for name in PROPERTIES.split(",")}}


def diagnostics() -> None:
    """Only owned Matter startup logs; no HA journal, registry or model bodies."""
    evidence: dict[str, Any] = {}
    collectors: tuple[tuple[str, Callable[[], dict[str, Any]]], ...] = (
        ("unit", observe),
        (
            "journal",
            lambda: bounded_command(
                ["journalctl", "--no-pager", "--unit=matter-server.service", "--lines=200", "--output=short-iso"],
                timeout=10,
            ),
        ),
    )
    for name, collect in collectors:
        try:
            evidence[name] = collect()
        except (OSError, subprocess.SubprocessError):
            evidence[name] = {"collection_failed": True}
    try:
        fd = os.open(LOG, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise OSError("owned Matter log is not regular")
            stream.seek(max(0, metadata.st_size - LIMIT))
            body = stream.read(LIMIT)
        evidence["log"] = {"output": body.decode("utf-8", errors="replace"), "truncated": metadata.st_size > LIMIT}
    except FileNotFoundError:
        evidence["log"] = {"absent": True}
    except OSError:
        evidence["log"] = {"collection_failed": True}
    write("matter-startup-diagnostics.json", evidence)


def wait_ready(*, timeout: float = 90, stable_seconds: float = 20) -> None:
    """Require stable PID/restart count and port5580; never repair or restart."""
    if not (math.isfinite(timeout) and math.isfinite(stable_seconds) and 0 < stable_seconds <= timeout <= 90):
        raise ValueError("invalid owned Matter readiness bounds")
    started = time.monotonic()
    deadline = started + timeout
    stable_since: float | None = None
    previous: tuple[str, str] | None = None
    samples = []
    ready = False
    try:
        while time.monotonic() < deadline:
            sample = observe(timeout=min(5, max(0.001, deadline - time.monotonic())))
            fields = sample["properties"]
            command = sample["command"]
            port = False
            try:
                with socket.create_connection(
                    ("127.0.0.1", 5580), timeout=min(1, max(0.001, deadline - time.monotonic()))
                ):
                    port = True
            except OSError:
                pass
            now = time.monotonic()
            identity = (fields.get("MainPID"), fields.get("NRestarts"))
            healthy = (
                command["exit"] == 0
                and not command["truncated"]
                and not command["timed_out"]
                and fields.get("Id") == "matter-server.service"
                and fields.get("LoadState") == "loaded"
                and fields.get("ActiveState") == "active"
                and fields.get("SubState") == "running"
                and isinstance(identity[0], str)
                and identity[0].isdigit()
                and int(identity[0]) > 0
                and isinstance(identity[1], str)
                and identity[1].isdigit()
                and port
            )
            samples.append({"elapsed": now - started, "unit": sample, "port5580": port})
            if healthy:
                if previous != identity or stable_since is None:
                    stable_since = now
                if now - stable_since >= stable_seconds and now <= deadline:
                    ready = True
                    return
                previous = identity
            else:
                stable_since = None
                previous = None
            time.sleep(min(2, max(0, deadline - time.monotonic())))
        raise RuntimeError("owned Matter service did not become stably ready")
    finally:
        write(
            "matter-readiness.json",
            {"ready": ready, "timeout": timeout, "stable_seconds": stable_seconds, "samples": samples},
        )
        diagnostics()
