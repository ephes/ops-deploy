#!/usr/bin/env python3
"""Persist durable USB replication attempt state for monitoring."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
from typing import Any


PRESENT_RESULTS = {"success", "failed"}
ALL_RESULTS = PRESENT_RESULTS | {"skipped_absent"}


def _load_state(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def record_state(
    path: Path,
    *,
    result: str,
    exit_code: int,
    device_path: str,
    pool: str,
    device_name: str | None = None,
    pool_guid: str | None = None,
    device_only: bool = False,
    occurred_at: str | None = None,
    size_bytes: int | None = None,
    alloc_bytes: int | None = None,
    free_bytes: int | None = None,
) -> dict[str, Any]:
    """Record one attempt.

    The top-level fields summarize the rotation as a whole (any drive); a
    ``device_name`` additionally keeps the same fields per rotating drive under
    ``devices``. ``device_only`` records a per-drive result without touching
    the summary, which is how absent drives are recorded while another drive
    of the rotation is attached.
    """
    if result not in ALL_RESULTS:
        raise ValueError(f"unsupported result: {result}")
    if device_only and not device_name:
        raise ValueError("device_only requires device_name")

    timestamp = occurred_at or datetime.now(tz=timezone.utc).isoformat(timespec="seconds")
    state = _load_state(path)
    state["version"] = 1
    if device_name:
        devices = state.get("devices")
        if not isinstance(devices, dict):
            devices = {}
            state["devices"] = devices
        entry = devices.get(device_name)
        if not isinstance(entry, dict):
            entry = {}
            devices[device_name] = entry
        _apply_attempt(
            entry,
            result=result,
            exit_code=exit_code,
            device_path=device_path,
            pool=pool,
            pool_guid=pool_guid,
            timestamp=timestamp,
            size_bytes=size_bytes,
            alloc_bytes=alloc_bytes,
            free_bytes=free_bytes,
        )
    if not device_only:
        # The summary describes whichever drive made the latest attempt, so a
        # previous drive's identity must not linger next to a new result.
        if device_name:
            state["device_name"] = device_name
        else:
            state.pop("device_name", None)
        state.pop("pool_guid", None)
        _apply_attempt(
            state,
            result=result,
            exit_code=exit_code,
            device_path=device_path,
            pool=pool,
            pool_guid=pool_guid,
            timestamp=timestamp,
            size_bytes=size_bytes,
            alloc_bytes=alloc_bytes,
            free_bytes=free_bytes,
        )

    _write_atomically(path, state)
    return state


def _apply_attempt(
    state: dict[str, Any],
    *,
    result: str,
    exit_code: int,
    device_path: str,
    pool: str,
    pool_guid: str | None,
    timestamp: str,
    size_bytes: int | None,
    alloc_bytes: int | None,
    free_bytes: int | None,
) -> None:
    state.update(
        {
            "device_path": device_path,
            "pool": pool,
            "last_attempt_at": timestamp,
            "last_attempt_result": result,
            "last_attempt_exit_code": exit_code,
        }
    )
    if pool_guid:
        state["pool_guid"] = pool_guid

    if result in PRESENT_RESULTS:
        state.update(
            {
                "last_present_attempt_at": timestamp,
                "last_present_attempt_result": result,
                "last_present_attempt_exit_code": exit_code,
            }
        )
        if result == "success":
            state["last_success_at"] = timestamp

        if size_bytes is not None and alloc_bytes is not None and free_bytes is not None:
            state.update(
                {
                    "last_known_size_bytes": size_bytes,
                    "last_known_alloc_bytes": alloc_bytes,
                    "last_known_free_bytes": free_bytes,
                    "last_known_used_ratio": alloc_bytes / size_bytes if size_bytes > 0 else None,
                    "last_known_observed_epoch": int(
                        datetime.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()
                    ),
                    "last_known_observed_iso": timestamp,
                }
            )


def _write_atomically(path: Path, state: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(state, handle, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_name, 0o644)
        os.replace(temporary_name, path)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-path", required=True, type=Path)
    parser.add_argument("--result", required=True, choices=sorted(ALL_RESULTS))
    parser.add_argument("--exit-code", required=True, type=int)
    parser.add_argument("--device-path", required=True)
    parser.add_argument("--pool", required=True)
    parser.add_argument("--device-name")
    parser.add_argument("--pool-guid")
    parser.add_argument("--device-only", action="store_true")
    parser.add_argument("--size-bytes", type=int)
    parser.add_argument("--alloc-bytes", type=int)
    parser.add_argument("--free-bytes", type=int)
    args = parser.parse_args()
    record_state(
        args.state_path,
        result=args.result,
        exit_code=args.exit_code,
        device_path=args.device_path,
        pool=args.pool,
        device_name=args.device_name or None,
        pool_guid=args.pool_guid or None,
        device_only=args.device_only,
        size_bytes=args.size_bytes,
        alloc_bytes=args.alloc_bytes,
        free_bytes=args.free_bytes,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
