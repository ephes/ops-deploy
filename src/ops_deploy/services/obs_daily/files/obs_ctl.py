#!/usr/bin/env python3
"""Hand-over point for the LLM triage on another machine (ops-deploy ``services.obs_daily``), stdlib only.

Run by root over SSH from the machine that runs the triage. It reads its
config as root, then does every file access in the state directory as the
Nyxmon user (``sender.user``, who owns that directory): root never opens a
path there, so a link planted in it cannot reach a privileged file. Only the
sender starts while still root, through ``systemd-run`` as the Nyxmon user,
with the message on standard input.

- ``obs_ctl.py --config FILE pack`` prints the latest evidence pack
  (``packs/latest.json``); exit 3 when there is none;
- ``obs_ctl.py --config FILE deliver`` reads the triage result as JSON on
  standard input (``date``, ``status`` ``ok``/``skipped``/``failed``,
  ``detail``, ``message``, ``new_items``, ``ran_at``), keeps it as
  ``triage/<date>-<ns>-<pid>.json``, sends ``message`` (when not empty) as
  one Telegram message through Nyxmon's notifier as the Nyxmon user, and
  records the outcome in ``triage.json``, which the status endpoint reports
  to Nyxmon. It keeps no queue: it prints ``obs-ctl: delivered`` only once
  Telegram acknowledged the message (or there was nothing to send), and the
  caller keeps the result and sends it again until it sees that line
  (diagnostics go to standard error). Exit 0
  delivered, 1 the send failed, 2 unusable input, 3 another delivery held
  the lock;
- ``obs_ctl.py --config FILE query`` runs the triage's read-only drill-down
  queries, given as JSON on standard input (``{"queries": [{"kind", "query",
  "start", "end", "limit", "step", "fn"}]}``), as the Nyxmon user: ``loki``
  runs LogQL through Loki's ``query_range`` (log lines or metric series);
  ``influx`` and ``influx_series`` take a tag selector (``metric=host.load5
  subject_id=fractal``, ``key=~regex``) from which this script builds the
  Flux itself (no free Flux reaches InfluxDB), run with the read-only token:
  aggregated series, or the newest point of every matching series. Every
  query has a wall-clock limit, a line, point or byte limit and a range of
  at most ``MAX_RANGE``; the answer (JSON on standard output, one result per
  query) is bounded. Raw log records go out unchanged (owner decision
  2026-11-19).
- ``obs_ctl.py --config FILE launchd`` reads that machine's launchd crash-loop
  report as JSON on standard input (``host``, ``checked``, ``loops``) and keeps
  it as ``launchd.json`` with the time it arrived; the status endpoint reports
  its age and loops to Nyxmon.
- ``obs_ctl.py --config FILE timemachine`` reads that machine's Time Machine
  probe report as JSON on standard input (agent-stuff ``tools/tm-guard``:
  whether ``tmutil status`` answered, phase, progress, seconds without
  progress, the cross-check against the bundle's newest band write on the
  backup server) and keeps the validated fields as ``timemachine.json`` with
  the time it arrived; the status endpoint reports them to Nyxmon.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import math
from fractions import Fraction
import os
import pwd
import re
import select
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Iterator
from datetime import datetime, timezone
from typing import Any

MAX_INPUT = 256 * 1024
MAX_MESSAGE = 3800
# The caller's SSH timeout must exceed LOCK_WAIT + SENDER_TIMEOUT.
LOCK_WAIT = 60
MAX_PACK = 4 * 1024 * 1024
READ_TIMEOUT = 20
# A launchd loop stays reported this long after its last sighting, so Nyxmon's polling sees it.
LOOP_HOLD = 1800
MAX_STORED_LOOPS = 500  # each with its own last sighting; the endpoint shows at most 20
MAX_STATE = 1024 * 1024  # as obs_status.py reads it
LOCK = "/run/obs-daily-ctl.lock"
LAUNCHD_LOCK = "/run/obs-daily-launchd.lock"
TIMEMACHINE_LOCK = "/run/obs-daily-timemachine.lock"
TM_STATES = ("ok", "timeout", "hung", "error")
TM_BAND_CHECKS = ("ok", "failed", "skipped")
SENDER_TIMEOUT = 180
STATUSES = ("ok", "skipped", "failed")
# Drill-down queries (``query``).
MAX_QUERIES = 10
MAX_QUERY_CHARS = 4000
MAX_RANGE = 31 * 86400
MAX_LOKI_LINES = 500
QUERY_TIMEOUT = 60
QUERY_DEADLINE = 480  # no new query starts after this many seconds; the caller waits longer
QUERY_BODY = 8 * 1024 * 1024  # largest answer read from Loki or InfluxDB
MAX_RESULT = 24 * 1024  # of each formatted result
LINE_CHARS = 1000
MAX_POINTS = 500  # per Influx series; the aggregation window grows to stay below
FLUX_FUNCTIONS = ("mean", "max", "min", "last", "count", "sum")
# Values: plain characters only, so a Flux string literal can never interpolate (``${``) or escape.
_SELECTOR = re.compile(r"([A-Za-z_][A-Za-z0-9_]{0,63})(?:(=|!=)([A-Za-z0-9_.,:/@%+-]{1,300})|(=~)([^\s/\"]{1,300}))")
_RELATIVE = re.compile(r"(?:now)?\s*-\s*(\d+)\s*([smhd])")


def drop_privileges(user: str) -> None:
    """Become ``user`` (with its groups) when running as root; a no-op otherwise."""

    if os.geteuid() != 0:
        return
    entry = pwd.getpwnam(user)
    os.setgroups(os.getgrouplist(user, entry.pw_gid))
    os.setgid(entry.pw_gid)
    os.setuid(entry.pw_uid)


MISSING = 3  # read_as child: the file does not exist


class Unreadable(Exception):
    """The state file exists but could not be read: nothing may be written over it."""


def read_as(user: str, path: str) -> dict[str, Any]:
    """The JSON object at ``path`` read by a child that dropped to ``user``.

    ``{}`` when the file does not exist; ``Unreadable`` when it exists but is
    empty, larger than ``MAX_STATE``, not a regular file, cannot be read within
    ``READ_TIMEOUT`` or is not a JSON object, so a delivery never overwrites a
    state file it could not read.
    """

    reader, writer = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(reader)
        code = 0
        try:
            drop_privileges(user)
            try:
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            except FileNotFoundError:
                os._exit(MISSING)
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                os._exit(1)
            with os.fdopen(fd, "rb") as handle:
                data = memoryview(handle.read(MAX_STATE + 1))
            while data:
                data = data[os.write(writer, data) :]
        except BaseException:
            code = 1
        finally:
            os._exit(code)
    os.close(writer)
    chunks = []
    deadline = time.monotonic() + READ_TIMEOUT
    while True:
        ready, _, _ = select.select([reader], [], [], max(0.0, deadline - time.monotonic()))
        if not ready:
            os.kill(pid, signal.SIGKILL)  # the child this call forked
            os.close(reader)
            os.waitpid(pid, 0)
            raise Unreadable(f"{os.path.basename(path)}: no answer within {READ_TIMEOUT} s")
        chunk = os.read(reader, 65536)
        if not chunk:
            break
        chunks.append(chunk)
    os.close(reader)
    _, status = os.waitpid(pid, 0)
    code = os.waitstatus_to_exitcode(status)
    if code == MISSING:
        return {}
    if code != 0:
        raise Unreadable(f"{os.path.basename(path)} is not a readable regular file")
    raw = b"".join(chunks)
    if len(raw) > MAX_STATE:
        raise Unreadable(f"{os.path.basename(path)} is larger than {MAX_STATE} bytes")
    if not raw:
        raise Unreadable(f"{os.path.basename(path)} is empty")
    try:
        data = json.loads(raw)
    except ValueError:
        raise Unreadable(f"{os.path.basename(path)} is not JSON") from None
    if not isinstance(data, dict):
        raise Unreadable(f"{os.path.basename(path)} is not a JSON object")
    return data


def wait_child(pid: int, seconds: float, grace: float | None = None) -> int | None:
    """Exit code of child ``pid``, or None after killing it once ``seconds`` passed (it is ours).

    With ``grace``, the killed child is waited for at most that long and then
    left behind (a child stuck in uninterruptible I/O does not die at once),
    so the caller and any lock it holds are never held up.
    """

    deadline = time.monotonic() + seconds
    while True:
        done, status = os.waitpid(pid, os.WNOHANG)
        if done:
            return os.waitstatus_to_exitcode(status)
        if time.monotonic() > deadline:
            os.kill(pid, signal.SIGKILL)
            if grace is None:
                os.waitpid(pid, 0)
                return None
            until = time.monotonic() + grace
            while time.monotonic() < until and not os.waitpid(pid, os.WNOHANG)[0]:
                time.sleep(0.05)
            return None
        time.sleep(0.05)


def write_as(user: str, path: str, data: Any, grace: float | None = None) -> None:
    """``_write_json`` in a child that dropped to ``user`` (creating the parent directory); raises on failure.

    With ``grace`` the child may be left behind (``wait_child``), so it first
    lets go of every inherited descriptor: the caller's lock and the SSH
    session's streams must not stay open in a child that outlives the call.
    """

    pid = os.fork()
    if pid == 0:
        code = 0
        try:
            if grace is not None:
                null = os.open(os.devnull, os.O_RDWR)
                for fd in (0, 1, 2):
                    os.dup2(null, fd)
                os.closerange(3, os.sysconf("SC_OPEN_MAX"))
            drop_privileges(user)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            _write_json(path, data)
        except BaseException:
            code = 1
        finally:
            os._exit(code)
    code = wait_child(pid, READ_TIMEOUT, grace)
    if code != 0:
        why = f"no result within {READ_TIMEOUT} s" if code is None else "failed"
        raise Unreadable(f"writing {os.path.basename(path)} as {user} {why}")


class Busy(Exception):
    """Another delivery runs; nothing was sent."""


@contextlib.contextmanager
def exclusive(lock_path: str) -> Iterator[None]:
    """One delivery at a time; the lock lives outside the Nyxmon-writable state directory."""

    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        waited = time.monotonic() + LOCK_WAIT
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() > waited:
                    raise Busy(f"another delivery holds the lock for over {LOCK_WAIT} s") from None
                time.sleep(1)
        yield
    finally:
        os.close(fd)


def _write_json(path: str, data: Any) -> None:
    """Write through a fresh temporary file in the same directory (never an existing path), then rename."""

    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".obs-ctl-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            os.fchmod(handle.fileno(), 0o640)
            json.dump(data, handle, indent=1, sort_keys=True, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        # The rename must survive a power loss too.
        directory = os.open(os.path.dirname(path) or ".", os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        os.unlink(tmp)
        raise


def parse_result(raw: str) -> dict[str, Any]:
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("not an object")
    date = str(data.get("date", ""))
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date):
        raise ValueError("date must be YYYY-MM-DD")
    if data.get("status") not in STATUSES:
        raise ValueError(f"status must be one of {', '.join(STATUSES)}")
    message = str(data.get("message") or "")
    if message.strip() and not any(ch.isalnum() for ch in message):
        raise ValueError("message has no visible text")
    if len(message) > MAX_MESSAGE:
        message = message[: MAX_MESSAGE - 20].rstrip() + "\n... (gekürzt)"
    ran_at = data.get("ran_at")
    valid_run = not isinstance(ran_at, bool) and isinstance(ran_at, int | float) and 0 < ran_at < 4_000_000_000
    if data.get("status") == "ok" and not valid_run:
        raise ValueError("an ok result needs ran_at (finite epoch seconds of the triage run)")
    ran_at = int(ran_at) if valid_run else None  # any other value is dropped, whatever the status
    items = data.get("new_items") or []
    if not isinstance(items, list):
        raise ValueError("new_items must be a list")
    return {
        "date": date,
        "status": data["status"],
        "message": message,
        "new_items": [
            {key: str(item.get(key, ""))[:200] for key in ("slug", "title")} for item in items[:20] if isinstance(item, dict)
        ],
        "detail": str(data.get("detail") or "")[:300],
        "ran_at": ran_at,
    }


def send(config: dict[str, Any], message: str) -> tuple[bool, str]:
    sender = config["sender"]
    argv = [
        "systemd-run", "--quiet", "--wait", "--pipe", "--collect",
        f"--uid={sender['user']}", f"--gid={sender['user']}", f"--working-directory={sender['cwd']}",
        f"--property=RuntimeMaxSec={SENDER_TIMEOUT - 10}",
        sender["python"], "-I", sender["script"], "--env-file", sender["env_file"],
    ]  # fmt: skip
    try:
        done = subprocess.run(
            argv, input=message, capture_output=True, text=True, timeout=SENDER_TIMEOUT, check=False
        )
    except (OSError, subprocess.SubprocessError) as error:
        return False, f"sender did not run: {type(error).__name__}"
    if done.returncode == 0:
        return True, "delivered"
    last = done.stderr.strip().splitlines()[-1:] or [""]
    return False, f"sender exit {done.returncode}: {last[0][:160]}"


def _ok_epoch(before: Any, result: dict[str, Any], now: float) -> Any:
    """When the newest triage that ran (status ok) and reached the owner ran: a delivered ok
    result counts with its own run time, so a replayed old result never moves it forward."""

    best = before if isinstance(before, int) else None
    ran = result.get("ran_at")
    if result["status"] == "ok" and isinstance(ran, int) and not isinstance(ran, bool) and 0 < ran < 4_000_000_000:
        ran = min(ran, int(now))
        best = ran if best is None or ran > best else best
    return best


def deliver(config: dict[str, Any], raw: str, now: float) -> int:
    """Record the result and send its digest now; one delivery at a time (``LOCK``)."""

    try:
        result = parse_result(raw)
    except ValueError as error:
        print(f"obs-ctl: unusable triage result: {error}", file=sys.stderr)
        return 2
    ran_at = result.get("ran_at")
    if isinstance(ran_at, int | float) and ran_at > now + 300:
        print("obs-ctl: unusable triage result: ran_at lies in the future", file=sys.stderr)
        return 2
    user = config["sender"]["user"]
    state = config["state_dir"]
    try:
        with exclusive(LOCK):
            return _deliver_locked(config, result, now, user, state)
    except Busy as busy:
        print(f"obs-ctl: not delivered: {busy}", file=sys.stderr)
        return 3
    except Unreadable as error:
        print(f"obs-ctl: not delivered: {error}", file=sys.stderr)
        return 1


def _deliver_locked(config: dict[str, Any], result: dict[str, Any], now: float, user: str, state: str) -> int:
    path = os.path.join(state, "triage.json")
    # Read and written by children that dropped to the Nyxmon user: root opens nothing there.
    previous = read_as(user, path)
    # One record per received result: a rerun of the day never overwrites an earlier one.
    archive = f"{result['date']}-{time.time_ns()}-{os.getpid()}.json"
    write_as(user, os.path.join(state, "triage", archive), result)
    message = result["message"].strip()
    delivered, detail = send(config, message) if message else (True, "nothing to send")
    status = {
        "date": result["date"],
        "status": result["status"],
        "detail": result["detail"],
        "new_items": len(result["new_items"]),
        "received_at": datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "delivered": delivered,
        "delivery": detail,
        # ``epoch``: the last result that reached the owner (or had nothing to say); ``ok_epoch``:
        # the run time of the newest ok triage that did, which Nyxmon's freshness rule reads.
        "epoch": int(now) if delivered else previous.get("epoch"),
        "ok_epoch": _ok_epoch(previous.get("ok_epoch"), result, now) if delivered else previous.get("ok_epoch"),
    }
    write_as(user, path, status)
    # Diagnostics (which may quote the sender) go to stderr; stdout carries only the receipt, which
    # the caller requires as a whole line together with exit 0 before it lets the result go.
    print(f"obs-ctl: triage {result['date']} {result['status']}: {detail}", file=sys.stderr)
    if delivered:
        print("obs-ctl: delivered", flush=True)
    return 0 if delivered else 1


def launchd_report(config: dict[str, Any], raw: str, now: float) -> int:
    try:
        data = json.loads(raw)
        if not isinstance(data, dict) or not isinstance(data.get("loops"), list):
            raise ValueError("needs an object with a loops list")
        host = str(data.get("host", ""))
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,62}", host):
            raise ValueError("bad host")
        def count(value: Any) -> int:
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 10**9:
                raise ValueError("counts must be integers from 0 to 999999999")
            return value

        loops = []
        for loop in data["loops"]:
            if not isinstance(loop, dict) or not isinstance(loop.get("label"), str) or not loop["label"]:
                raise ValueError("every loop needs a label")
            label = loop["label"]
            if len(label) > 200:  # a stable key for any length; distinct jobs never collapse
                label = label[:180] + "#" + hashlib.sha256(label.encode()).hexdigest()[:16]
            loops.append(
                {
                    "label": label,
                    "runs": count(loop.get("runs_since_last_sample", 0)),
                    "last_exit": str(loop.get("last_exit", ""))[:40],
                    "state": str(loop.get("state", ""))[:40],
                }
            )
        loops = loops[:MAX_STORED_LOOPS]
        checked = count(data.get("checked", 0))
        errors = count(data.get("errors", 0))
        if checked < 1:
            raise ValueError("no launchd job was sampled")
    except (ValueError, TypeError) as error:
        print(f"obs-ctl: unusable launchd report: {error}", file=sys.stderr)
        return 2
    try:
        with exclusive(LAUNCHD_LOCK):
            return _launchd_locked(config, host, checked, errors, loops, now)
    except Busy as busy:
        print(f"obs-ctl: launchd report not kept: {busy}", file=sys.stderr)
        return 3


def _launchd_locked(
    config: dict[str, Any], host: str, checked: int, errors: int, loops: list[dict[str, Any]], now: float
) -> int:
    """Merge one report into ``launchd.json`` as the Nyxmon user, in a child (the lock stays with root)."""

    pid = os.fork()
    if pid == 0:
        code = 0
        try:
            _launchd_merge(config, host, checked, errors, loops, now)
        except BaseException:
            code = 1
        finally:
            os._exit(code)
    code = wait_child(pid, READ_TIMEOUT)  # a stalled child is killed; the lock is released on return
    if code is None:
        print(f"obs-ctl: launchd report not kept: no result within {READ_TIMEOUT} s", file=sys.stderr)
    return 0 if code == 0 else 1


def _launchd_merge(
    config: dict[str, Any], host: str, checked: int, errors: int, loops: list[dict[str, Any]], now: float
) -> None:
    drop_privileges(config["sender"]["user"])
    path = os.path.join(config["state_dir"], "launchd.json")
    previous = _read_regular(path)
    # Each job's loop stays reported LOOP_HOLD seconds after its last sighting, so Nyxmon's polling sees it.
    held = {
        str(loop.get("label")): loop
        for loop in previous.get("loops") or []
        if isinstance(loop, dict) and isinstance(loop.get("last_seen"), int) and now - loop["last_seen"] < LOOP_HOLD
    }
    for loop in loops:
        held[loop["label"]] = {**loop, "last_seen": int(now)}
    # The merged state stays bounded (newest sightings first) and below what the readers accept.
    kept = sorted(held.values(), key=lambda l: (-l["last_seen"], l["label"]))[:MAX_STORED_LOOPS]
    while kept and len(json.dumps(kept)) > MAX_STATE // 2:
        kept = kept[: len(kept) * 3 // 4]
    held = {loop["label"]: loop for loop in kept}
    report = {
        "host": host, "checked": checked, "errors": errors, "loops": sorted(held.values(), key=lambda l: l["label"]),
        "epoch": int(now),
    }  # fmt: skip
    _write_json(path, report)
    return 0


def _tm_text(data: dict[str, Any], key: str, limit: int) -> str:
    """A string or null; printable ASCII only, at most ``limit`` characters (the endpoint passes it on as is)."""

    value = data.get(key)
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValueError(f"{key} must be a string or null")
    return "".join(c if " " <= c <= "~" else "?" for c in value)[:limit]


def _tm_int(data: dict[str, Any], key: str, *, nullable: bool = True, top: int = 10**16) -> int | None:
    value = data.get(key)
    if value is None and nullable:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < top:
        raise ValueError(f"{key} must be an integer from 0 to {top - 1}" + (" or null" if nullable else ""))
    return value


def _tm_bool(data: dict[str, Any], key: str, *, nullable: bool = True) -> bool | None:
    value = data.get(key)
    if value is None and nullable:
        return None
    if not isinstance(value, bool):
        raise ValueError(f"{key} must be true or false" + (" or null" if nullable else ""))
    return value


def parse_timemachine(raw: str) -> dict[str, Any]:
    """The validated fields of one Time Machine probe report; ``ValueError`` when it is unusable."""

    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("needs an object")
    host = data.get("host")
    if not isinstance(host, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,62}", host):
        raise ValueError("bad host")
    tmutil = data.get("tmutil")
    if tmutil not in TM_STATES:
        raise ValueError(f"tmutil must be one of {', '.join(TM_STATES)}")
    band_check = data.get("band_check")
    if band_check not in TM_BAND_CHECKS:
        raise ValueError(f"band_check must be one of {', '.join(TM_BAND_CHECKS)}")
    percent = data.get("percent")
    # Range first: a huge JSON integer must not reach float() or math.isfinite (OverflowError).
    if percent is not None and (
        isinstance(percent, bool) or not isinstance(percent, int | float) or not -1 <= percent <= 100
        or (isinstance(percent, float) and not math.isfinite(percent))
    ):  # fmt: skip
        raise ValueError("percent must be a number from -1 to 100 or null")
    phase = data.get("phase")
    if phase is None:
        phase = ""
    if not isinstance(phase, str) or not re.fullmatch(r"[A-Za-z0-9_. -]{0,60}", phase):
        raise ValueError("bad phase")
    running = _tm_bool(data, "running")
    if tmutil == "ok" and running is None:
        raise ValueError("a report whose tmutil answered needs running")
    return {
        "host": host,
        "tmutil": tmutil,
        "tmutil_detail": _tm_text(data, "tmutil_detail", 200),
        "running": running,
        "stopping": _tm_bool(data, "stopping"),
        "phase": phase,
        "percent": None if percent is None else float(percent),
        "bytes": _tm_int(data, "bytes"),
        "files": _tm_int(data, "files"),
        "total_bytes": _tm_int(data, "total_bytes"),
        "total_files": _tm_int(data, "total_files"),
        "auto_backup": _tm_bool(data, "auto_backup"),
        "stalled_seconds": _tm_int(data, "stalled_seconds", nullable=False, top=10**9),
        "band_check": band_check,
        "band_detail": _tm_text(data, "band_detail", 200),
        "band_newest_epoch": _tm_int(data, "band_newest_epoch", top=10**10),
        "cross_check_ok": _tm_bool(data, "cross_check_ok", nullable=False),
        "probe_epoch": _tm_int(data, "probe_epoch", nullable=False, top=10**10),
    }


def timemachine_report(config: dict[str, Any], raw: str, now: float) -> int:
    """Keep one probe report as ``timemachine.json`` (the newest report replaces the last one)."""

    try:
        report = parse_timemachine(raw)
    except (ValueError, TypeError) as error:
        print(f"obs-ctl: unusable timemachine report: {error}", file=sys.stderr)
        return 2
    report["epoch"] = int(now)
    try:
        with exclusive(TIMEMACHINE_LOCK):
            # A writer stuck in I/O is killed and left behind after 5 s: the lock never waits for it.
            path = os.path.join(config["state_dir"], "timemachine.json")
            write_as(config["sender"]["user"], path, report, grace=5.0)
    except Busy as busy:
        print(f"obs-ctl: timemachine report not kept: {busy}", file=sys.stderr)
        return 3
    except Unreadable as error:
        print(f"obs-ctl: timemachine report not kept: {error}", file=sys.stderr)
        return 1
    return 0


def read_pack(state_dir: str) -> bytes | None:
    """``packs/latest.json`` without following a link anywhere below ``state_dir``: regular files only, bounded."""

    fds: list[int] = []
    try:
        fds.append(os.open(state_dir, os.O_RDONLY | os.O_DIRECTORY))
        fds.append(os.open("packs", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fds[-1]))
        fds.append(os.open("latest.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fds[-1]))
        if not stat.S_ISREG(os.fstat(fds[-1]).st_mode):
            return None
        data = os.read(fds[-1], MAX_PACK + 1)
        return None if len(data) > MAX_PACK else data
    except OSError:
        return None
    finally:
        for fd in fds:
            os.close(fd)


def _read_regular(path: str) -> dict[str, Any]:
    """A JSON object from a regular file; ``{}`` when it does not exist.

    One that exists but is a link, FIFO, too large or not a JSON object raises
    ``Unreadable``: whoever writes after reading must not erase state it could
    not see (held launchd loops).
    """

    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return {}
    except OSError as error:
        raise Unreadable(f"{os.path.basename(path)}: {error.strerror}") from None
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise Unreadable(f"{os.path.basename(path)} is not a regular file")
        raw = handle.read(MAX_STATE + 1)
    if len(raw) > MAX_STATE:
        raise Unreadable(f"{os.path.basename(path)} is larger than {MAX_STATE} bytes")
    try:
        data = json.loads(raw)
    except ValueError:
        raise Unreadable(f"{os.path.basename(path)} is not JSON") from None
    if not isinstance(data, dict):
        raise Unreadable(f"{os.path.basename(path)} is not a JSON object")
    return data


# -- drill-down queries ------------------------------------------------------------------------


class BadQuery(ValueError):
    """A query refused before it ran."""


def parse_time(value: Any, now_us: int, default_us: int) -> int:
    """Whole microseconds (floored, exact) from ``now``, ``-24h``/``now-90m`` (s, m, h, d), an RFC 3339
    time or epoch seconds."""

    if value is None or value == "":
        return default_us
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return _micros(value)
    text = str(value).strip()
    if text == "now":
        return now_us
    relative = _RELATIVE.fullmatch(text)
    if relative:
        return now_us - int(relative.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[relative.group(2)] * 1_000_000
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raise BadQuery(f"unreadable time {text[:40]!r}") from None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    # Integer arithmetic from the parsed fields: no float step can shift a microsecond.
    delta = parsed - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def flux_filter(selector: str) -> str:
    """``key=value``, ``key!=value`` and ``key=~regex`` terms (space-separated) as one Flux predicate.

    Values are written as Flux string literals and regexes are checked by Python first, so a
    selector can only ever filter: the Flux around it is fixed.
    """

    terms = selector.split()
    if not terms or len(terms) > 12:
        raise BadQuery("a selector needs 1..12 terms such as metric=host.load5 subject_id=fractal")
    parts = []
    for term in terms:
        found = _SELECTOR.fullmatch(term)
        if found is None:
            raise BadQuery(f"unreadable selector term {term[:60]!r} (key=value, key!=value or key=~regex)")
        key, op, value = found.group(1), found.group(2) or found.group(4), found.group(3) or found.group(5)
        if op == "=~":
            try:
                re.compile(value)
            except re.error:
                raise BadQuery(f"bad regex in {term[:60]!r}") from None
            # One pass, each backslash with the character it escapes.
            if any(escape not in ("\\.", "\\d", "\\w") for escape in re.findall(r"\\.?", value)):
                raise BadQuery("regexes may not contain backslashes other than \\. \\d \\w")
            parts.append(f"r[{json.dumps(key)}] =~ /{value}/")
        else:
            parts.append(f"r[{json.dumps(key)}] {'==' if op == '=' else '!='} {json.dumps(value)}")
    return " and ".join(parts)


def _micros(epoch: float) -> int:
    """Whole microseconds at or before ``epoch``, exactly (no float rounding into the future)."""

    return math.floor(Fraction(epoch) * 1_000_000)


def _flux_time(micros: int) -> str:
    """A Flux time literal from whole microseconds, so the range is exactly the validated one."""

    seconds, fraction = divmod(micros, 1_000_000)
    return datetime.fromtimestamp(seconds, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S") + f".{fraction:06d}Z"


def influx_flux(kind: str, selector: str, start_us: int, end_us: int, step: int | None, fn: str, bucket: str) -> str:
    head = (
        f"from(bucket: {json.dumps(bucket)}) |> range(start: {_flux_time(start_us)}, stop: {_flux_time(end_us)})"
        f' |> filter(fn: (r) => r["_measurement"] == "graphyard_metrics" and r["_field"] == "value")'
        f" |> filter(fn: (r) => {flux_filter(selector)})"
    )
    if kind == "influx_series":
        return head + " |> last() |> group()"
    window = max(step or 0, (end_us - start_us) // (MAX_POINTS * 1_000_000) + 1, 1)
    return head + f" |> aggregateWindow(every: {window}s, fn: {fn}, createEmpty: false)"


class Bounded:
    """Formatted result lines up to ``MAX_RESULT`` bytes; the rest is counted as cut."""

    def __init__(self) -> None:
        self.items: list[Any] = []
        self.size = 0
        self.cut = 0

    def add(self, item: Any) -> None:
        size = len(json.dumps(item, ensure_ascii=False).encode()) + 2  # with the list separator
        if self.size + size > MAX_RESULT:
            self.cut += 1
            return
        self.items.append(item)
        self.size += size


def _clean(text: str) -> str:
    """Lone surrogates (from escaped JSON) as visible escapes, so the answer always encodes."""

    return text.encode("utf-8", "backslashreplace").decode("utf-8")


def _loki_result(data: dict[str, Any]) -> dict[str, Any]:
    out = Bounded()
    if data.get("resultType") == "streams":
        lines = []
        for stream in data.get("result", []):
            labels = dict(stream.get("stream", {}))
            where = f"{labels.get('host', '?')}/{labels.get('service', '?')}"
            for ts, raw in stream.get("values", []):
                message, level, rest = raw, str(labels.get("level") or labels.get("detected_level") or "-"), ""
                try:
                    parsed = json.loads(raw)
                except ValueError:
                    parsed = None
                if isinstance(parsed, dict):
                    message, level = str(parsed.pop("message", raw)), str(parsed.pop("level", None) or level)
                    # The other fields of the record (unit, pid, boot id, ...) follow the message.
                    others = {k: v for k, v in parsed.items() if not (k in ("host", "service") and k in labels and v == labels[k])}
                    rest = " | " + json.dumps(others, ensure_ascii=False, separators=(",", ":")) if others else ""
                line = f"{_iso(int(ts) / 1e9)} {where} {level} {message}{rest}"
                lines.append((int(ts), _clean(line[:LINE_CHARS])))
        for _ts, line in sorted(lines):
            out.add(line)
        return {"lines": out.items, "cut": out.cut}
    points_cut = 0
    for series in data.get("result", []):
        values = series.get("values") or [series.get("value")]
        points = [[_iso(float(t)), v] for t, v in (p for p in values if p) if t is not None]
        entry = {"metric": series.get("metric", {}), "values": points}
        # A series that does not fit keeps its newest points that do (halving until it fits).
        while points and len(json.dumps(entry, ensure_ascii=False).encode()) + 2 > MAX_RESULT - out.size:
            dropped = max(1, len(points) // 2)
            points_cut += dropped
            points = points[dropped:]
            entry["values"] = points
        if points:
            out.add(entry)
        else:
            out.cut += 1
    return {"series": out.items, "cut": out.cut, "points_cut": points_cut}


def _flux_result(rows: list[dict[str, str]]) -> dict[str, Any]:
    out = Bounded()
    for row in rows:
        out.add({k: _clean(v) for k, v in row.items() if k not in ("", "result", "table", "_start", "_stop", "_field",
                                                                    "_measurement")})  # fmt: skip
    return {"rows": out.items, "cut": out.cut}


def run_query(spec: Any, config: dict[str, Any], clients: dict[str, Any], now: float) -> dict[str, Any]:
    if not isinstance(spec, dict) or spec.get("kind") not in ("loki", "influx", "influx_series"):
        raise BadQuery('each query needs "kind": "loki", "influx" or "influx_series"')
    query = spec.get("query")
    if not isinstance(query, str) or not query.strip() or len(query) > MAX_QUERY_CHARS:
        raise BadQuery(f"query must be a non-empty string of at most {MAX_QUERY_CHARS} characters")
    # Whole microseconds, quantized once: what is checked is exactly what is sent.
    now_us = _micros(now)
    end_us = min(parse_time(spec.get("end"), now_us, now_us), now_us)
    start_us = parse_time(spec.get("start"), now_us, end_us - 3600 * 1_000_000)
    if not 0 < end_us - start_us <= MAX_RANGE * 1_000_000:
        raise BadQuery(f"start must lie before end, at most {MAX_RANGE // 86400} days")
    step = spec.get("step")
    if step is not None and (isinstance(step, bool) or not isinstance(step, int) or step < 1):
        raise BadQuery("step must be whole seconds")
    start, end = start_us / 1e6, end_us / 1e6
    window = {"start": _iso(start), "end": _iso(end)}
    if spec["kind"] != "loki":
        fn = spec.get("fn") or "mean"
        if fn not in FLUX_FUNCTIONS:
            raise BadQuery(f"fn must be one of {', '.join(FLUX_FUNCTIONS)}")
        flux = influx_flux(spec["kind"], query, start_us, end_us, step, fn, config["influx"]["bucket"])
        return {**window, **_flux_result(clients["flux"](flux))}
    limit = spec.get("limit", 200)
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_LOKI_LINES:
        raise BadQuery(f"limit must be 1..{MAX_LOKI_LINES}")
    params = {"query": query, "start": str(start_us * 1000), "end": str(end_us * 1000), "limit": str(limit),
              "direction": "backward" if spec.get("direction") != "forward" else "forward"}  # fmt: skip
    if step is not None:
        params["step"] = str(max(step, int((end - start) / 1000) + 1))
    return {**window, **_loki_result(clients["loki"]("query_range", params))}


def _pack_module() -> Any:
    """``obs_pack.py`` from this directory (``-I`` keeps it off ``sys.path``): its Loki and InfluxDB clients."""

    import importlib.util

    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "obs_pack.py")
    spec = importlib.util.spec_from_file_location("obs_pack", path)
    if spec is None or spec.loader is None:
        raise ImportError(path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["obs_pack"] = module
    spec.loader.exec_module(module)
    return module


def bounded_query(spec: Any, config: dict[str, Any], clients: dict[str, Any], now: float) -> dict[str, Any]:
    """``run_query`` in a daemon thread with a hard wall-clock limit (``QUERY_TIMEOUT`` + 5 s): a server
    that trickles its answer cannot hold the batch. A query still running then is abandoned (the
    process exits after the batch) and reported."""

    box: dict[str, Any] = {}

    def work() -> None:
        try:
            box["result"] = run_query(spec, config, clients, now)
        except BadQuery as error:
            box["result"] = {"error": f"refused: {error}"}
        except Exception as error:  # noqa: BLE001 - one failing query must not cost the others
            box["result"] = {"error": f"{type(error).__name__}: {str(error)[:300]}"}

    thread = threading.Thread(target=work, daemon=True)
    thread.start()
    thread.join(QUERY_TIMEOUT + 5)
    return dict(box.get("result") or {"error": f"no answer within {QUERY_TIMEOUT + 5} s; abandoned"})


def queries(config: dict[str, Any], raw: str, now: float, clients: dict[str, Any] | None = None) -> int:
    """Run the drill-down queries of ``raw``; print one JSON object with a result per query."""

    try:
        request = json.loads(raw)
    except ValueError:
        print("obs-ctl: queries are not JSON", file=sys.stderr)
        return 2
    specs = request.get("queries") if isinstance(request, dict) else None
    if not isinstance(specs, list) or not 1 <= len(specs) <= MAX_QUERIES:
        print(f"obs-ctl: expected 1..{MAX_QUERIES} queries", file=sys.stderr)
        return 2
    if clients is None:
        module = _pack_module()
        influx = config["influx"]
        clients = {
            "loki": module.loki_client(config["loki_url"], QUERY_TIMEOUT, QUERY_BODY),
            "flux": module.flux_client(influx["url"], influx["org"], influx["token_file"], QUERY_TIMEOUT, QUERY_BODY),
        }
    started = time.monotonic()
    results = []
    for number, spec in enumerate(specs, 1):
        result: dict[str, Any] = {"id": number}
        if time.monotonic() - started > QUERY_DEADLINE:
            result["error"] = f"not run: the {QUERY_DEADLINE} s budget of this call is used up"
        else:
            result.update(bounded_query(spec, config, clients, now))
        results.append(result)
    json.dump({"results": results}, sys.stdout, ensure_ascii=False)
    sys.stdout.write("\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Hand-over point for the observability triage")
    parser.add_argument("--config", required=True)
    parser.add_argument("action", choices=("pack", "deliver", "launchd", "query", "timemachine"))
    args = parser.parse_args(argv)
    with open(args.config, encoding="utf-8") as handle:
        config = json.load(handle)
    if args.action == "pack":
        drop_privileges(config["sender"]["user"])
        data = read_pack(config["state_dir"])
        if data is None:
            print("obs-ctl: no evidence pack yet (or not a regular file)", file=sys.stderr)
            return 3
        sys.stdout.write(data.decode("utf-8", "replace"))
        return 0
    if args.action == "query":
        # The Nyxmon user can read the InfluxDB token; nothing here needs root.
        drop_privileges(config["sender"]["user"])
    raw = sys.stdin.read(MAX_INPUT + 1)
    if len(raw) > MAX_INPUT:
        print("obs-ctl: input too large", file=sys.stderr)
        return 2
    if args.action == "query":
        return queries(config, raw, time.time())
    if args.action == "launchd":
        return launchd_report(config, raw, time.time())
    if args.action == "timemachine":
        return timemachine_report(config, raw, time.time())
    return deliver(config, raw, time.time())


if __name__ == "__main__":
    sys.exit(main())
