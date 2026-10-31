"""Bounded owned guest evidence/execution, never inventory or application fixtures."""

from __future__ import annotations

import datetime
import hashlib
import io
import ipaddress
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any

from pyinfra.api import State
from pyinfra.api.state import BaseStateCallback

ROOT = Path("/opt/homeassistant-fixture")
EVIDENCE = Path("/var/tmp/homeassistant-evidence")
VALUES: list[str] = []


def sanitize(text: str) -> str:
    for value in sorted(VALUES, key=len, reverse=True):
        if value:
            text = text.replace(value, "<synthetic-redacted>")
    return text


def write(name: str, data: Any) -> None:
    if "/" in name or not name.endswith(".json"):
        raise ValueError("invalid owned evidence name")
    body = sanitize(json.dumps(data, indent=2, default=str)) + "\n"
    if len(body.encode()) > 20 * 1024 * 1024:
        raise ValueError("owned evidence exceeds bound")
    (EVIDENCE / name).write_text(body)


def command(
    *args: str, stdin: str | None = None, check: bool = True, timeout: int = 300, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, input=stdin, text=True, capture_output=True, timeout=timeout, env=env, check=False)
    if check and result.returncode:
        raise RuntimeError(f"owned command failed with exit {result.returncode}; output withheld")
    return result


def default_ipv4() -> str:
    # Kernel route lookup only; this sends no packet to the public destination.
    routes = json.loads(command("ip", "-j", "route", "get", "1.1.1.1").stdout)
    value = routes[0]["prefsrc"]
    if not isinstance(value, str) or ipaddress.ip_address(value).version != 4:
        raise RuntimeError("owned guest IPv4 source is unavailable")
    return value


def metadata(path: Path) -> dict[str, Any] | None:
    try:
        stat = path.lstat()
    except FileNotFoundError:
        return None
    return {
        "mode": stat.st_mode,
        "uid": stat.st_uid,
        "gid": stat.st_gid,
        "size": stat.st_size,
        "inode": stat.st_ino,
        "mtime_ns": stat.st_mtime_ns,
        "ctime_ns": stat.st_ctime_ns,
        "link": os.readlink(path) if path.is_symlink() else None,
    }


def public_file(path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {"metadata": metadata(path)}
    if path.is_file() and not path.is_symlink():
        result["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


class BoundedLog(io.TextIOBase):
    """Original qualified Paperless streaming redactor, with guest-only raw output."""

    def __init__(self, raw: io.TextIOWrapper, durable: io.TextIOWrapper) -> None:
        self.raw = raw
        self.durable = durable
        self.size = 0
        self.pending = ""

    def write(self, text: str) -> int:
        self.size += len(text.encode())
        if self.size > 20 * 1024 * 1024:
            raise RuntimeError("owned CLI log exceeds bound")
        written = self.raw.write(text)
        self.pending = sanitize(self.pending + text)
        keep = max((len(value) for value in VALUES), default=1) - 1
        end = max(0, len(self.pending) - keep)
        self.durable.write(self.pending[:end])
        self.pending = self.pending[end:]
        self.durable.flush()
        return written

    def flush(self) -> None:
        self.raw.flush()
        self.durable.flush()


class PhaseProgress:
    """Persist only bounded phase/operation names and elapsed time, no argv/payload."""

    def __init__(self, label: str) -> None:
        if "/" in label:
            raise ValueError("invalid owned phase")
        self.path = EVIDENCE / (label + "-progress.log")
        self.started = time.monotonic()
        self.events = 0

    def record(self, event: str, names: list[str] | None = None) -> None:
        self.events += 1
        names = names or []
        if self.events > 1024 or len(names) > 10 or any(len(name) > 512 for name in names):
            raise ValueError("owned progress exceeds bound")
        with self.path.open("a") as stream:
            stream.write(
                sanitize(
                    json.dumps(
                        {
                            "event": event,
                            "names": names,
                            "elapsed_seconds": time.monotonic() - self.started,
                            "utc": datetime.datetime.now(datetime.UTC).isoformat(),
                        }
                    )
                )
                + "\n"
            )
            stream.flush()

    def callback(self) -> BaseStateCallback:
        class Callback(BaseStateCallback):
            @staticmethod
            def operation_start(state: State, op_hash: Any) -> None:
                self.record("operation-start", sorted(state.get_op_meta(op_hash).names))

            @staticmethod
            def operation_end(state: State, op_hash: Any) -> None:
                self.record("operation-end", sorted(state.get_op_meta(op_hash).names))

        return Callback()
