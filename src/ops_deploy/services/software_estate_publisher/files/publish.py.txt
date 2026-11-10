#!/usr/bin/env python3
"""One bounded local inventory tick; no remote execution or persistent daemon."""

from __future__ import annotations

import argparse
import json
import math
import os
import signal
import socket
import tempfile
import time
from pathlib import Path

import collect
import emit
import outbox
import send

WEEK = 7 * 86400
STATE = ".publisher.json"


def atomic_json(directory, name, value):
    target = directory / name
    if target.exists() or target.is_symlink():
        outbox.private_read(target, 65536)
    fd, temporary = tempfile.mkstemp(prefix=".publisher-", dir=directory)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, allow_nan=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
        outbox.sync_directory(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def configuration(path):
    path = Path(path).absolute()
    outbox.private_directory(path.parent)
    config = json.loads(outbox.private_read(path, 65536))
    if set(config) != {
        "policy",
        "hostnames",
        "directory",
        "endpoint",
        "credential_file",
    }:
        raise ValueError("invalid publisher configuration")
    collect.validate_policy(config["policy"])
    if (
        not isinstance(config["hostnames"], list)
        or not config["hostnames"]
        or any(not isinstance(name, str) or not name for name in config["hostnames"])
        or socket.gethostname().split(".")[0].lower() not in config["hostnames"]
        or config["policy"]["host"] not in config["hostnames"]
    ):
        raise ValueError("configuration does not belong to this host")
    if (
        not Path(config["directory"]).is_absolute()
        or not Path(config["credential_file"]).is_absolute()
    ):
        raise ValueError("absolute publisher paths required")
    config["directory"] = outbox.private_directory(config["directory"])
    outbox.private_directory(config["directory"] / "outbox")
    send.endpoint_url(config["endpoint"])
    credential = Path(config["credential_file"])
    outbox.private_directory(credential.parent)
    outbox.private_read(credential, 4096)
    return config


def timestamp(value):
    return type(value) in (int, float) and math.isfinite(value) and value > 0


def read_state(directory, host, now):
    path = directory / STATE
    if not path.exists() and not path.is_symlink():
        return {"schema_version": 1, "host": host, "last_scan": None, "last_check": now}
    state = json.loads(outbox.private_read(path, 4096))
    if (
        not isinstance(state, dict)
        or set(state) != {"schema_version", "host", "last_scan", "last_check"}
        or not isinstance(state["schema_version"], int)
        or isinstance(state["schema_version"], bool)
        or state["schema_version"] != 1
        or state["host"] != host
        or not timestamp(state["last_check"])
        or state["last_check"] > now + 300
        or (
            state["last_scan"] is not None
            and (
                not timestamp(state["last_scan"])
                or state["last_scan"] > state["last_check"]
            )
        )
    ):
        raise ValueError("invalid publisher state or clock moved backwards")
    return state


def tick(
    config, *, collect_now=False, send_only=False, retry_now=False, retry_blocked=False
):
    directory = config["directory"]
    with outbox.locked(directory):
        now = time.time()
        state = read_state(directory, config["policy"]["host"], now)
        state["last_check"] = max(now, state["last_check"])
        atomic_json(directory, STATE, state)
        result = {"checked_at": now, "scan": "not_due", "reports": []}
        due = state["last_scan"] is None or now - state["last_scan"] >= WEEK
        if not send_only and (collect_now or due):
            try:
                # Refuse an unnecessary scan when publication cannot fit, but still drain.
                with outbox.locked(directory / "outbox") as spool:
                    if len(outbox.entries(spool)) >= outbox.MAX_REPORTS:
                        raise ValueError("outbox full")
                with send.deadline(120):
                    report = emit.envelope(
                        collect.collect(config["policy"]),
                        preserve_partial=config["policy"].get(
                            "preserve_partial_applications", False
                        ),
                    )
                    emit.write_report(report, directory / "outbox")
                state["last_scan"] = now
                atomic_json(directory, STATE, state)
                result["scan"] = "published"
                result["snapshot_id"] = report["snapshot_id"]
            except (
                OSError,
                ValueError,
                TypeError,
                KeyError,
                RuntimeError,
                RecursionError,
                send.RunDeadline,
            ):
                result["scan"] = "failed"
        try:
            with send.deadline(120):
                result["reports"] = send.send_reports(
                    directory / "outbox",
                    config["endpoint"],
                    config["credential_file"],
                    retry_now=retry_now,
                    retry_blocked=retry_blocked,
                )
        except (
            OSError,
            ValueError,
            TypeError,
            KeyError,
            RuntimeError,
            RecursionError,
            send.RunDeadline,
        ):
            result["delivery_error"] = "delivery_failed_or_deadline"
        atomic_json(directory, "last-run.json", result)
        return result


class Stopped(BaseException):
    """Unwind probe cleanup and locks when launchd stops a running job."""


def stop(signum, frame):
    raise Stopped()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--collect-now", action="store_true")
    mode.add_argument("--send-only", action="store_true")
    parser.add_argument("--retry-now", action="store_true")
    parser.add_argument("--retry-blocked", action="store_true")
    args = parser.parse_args(argv)
    if (args.retry_now or args.retry_blocked) and not (
        args.collect_now or args.send_only
    ):
        parser.error("retry overrides require an explicit manual mode")
    signal.signal(signal.SIGTERM, stop)
    try:
        config = configuration(args.config)
        if args.check:
            with outbox.locked(config["directory"]):
                read_state(config["directory"], config["policy"]["host"], time.time())
            print('{"configuration":"ok"}')
            return 0
        result = tick(
            config,
            collect_now=args.collect_now,
            send_only=args.send_only,
            retry_now=args.retry_now,
            retry_blocked=args.retry_blocked,
        )
        status = int(
            result["scan"] == "failed"
            or "delivery_error" in result
            or any(item["status"] != "stored" for item in result["reports"])
        )
        print(json.dumps(result))
        return status
    except Stopped:
        print('{"error":"stopped"}')
        return 143
    except outbox.Busy:
        print('{"error":"busy"}')
        return 75
    except (OSError, ValueError, TypeError, KeyError, RuntimeError, RecursionError):
        print('{"error":"local_configuration_or_state_error"}')
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
