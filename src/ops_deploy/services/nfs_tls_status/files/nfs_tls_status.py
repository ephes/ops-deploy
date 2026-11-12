#!/usr/bin/env python3
"""NFS-over-TLS status report (ops-deploy ``services.nfs_tls_status``), Python stdlib only.

``nfs_tls_status.py --config FILE --out FILE [--mountinfo FILE]`` reads its
configuration (JSON: ``units``, ``mounts``, ``certificates``, each entry with
its ``id``, plus ``warn_days`` and ``state_group``) and writes one JSON report
atomically (temporary file and rename, ``<owner>:<state_group> 0640``):

- ``units.<id>``: ``systemctl show`` of the unit; ``ok`` when ``ActiveState``
  is ``active``;
- ``mounts.<id>``: the topmost mount at ``where`` in the mount table (default
  ``/proc/1/mountinfo``: the host's view, not the sandboxed one of this
  process); ``ok`` when it is mounted with the expected file system type and
  source, carries every required option (mount and superblock options) and,
  with a ``unit``, that unit is active;
- ``certificates.<id>``: ``openssl x509 -noout -enddate`` of the first
  certificate in the file; ``days_left`` are whole days, rounded down
  (negative once expired); ``ok`` when ``days_left >= warn_days``.

Every entry keeps its unit or path, carries ``problems`` (empty when ``ok``)
and is checked on its own: a missing unit, mount or file, or a failing tool,
is ``ok: false``, never a crash. The exit status is non-zero only when the
configuration cannot be read or the report cannot be written.
"""

from __future__ import annotations

import argparse
import calendar
import grp
import json
import math
import os
import re
import subprocess
import sys
import time
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

TIMEOUT = 20
SCHEMA = 1
# mountinfo escapes space, tab, newline and backslash as a backslash and three octal digits
# (written without a backslash pair, which fish would read differently in a quoted -c source).
_ESCAPE = re.compile(re.escape(chr(92)) + "([0-7]{3})")


def run(argv: list[str]) -> tuple[int, str, str]:
    """Exit status, stdout and the first line of stderr of ``argv`` (127 when it cannot run)."""

    try:
        done = subprocess.run(argv, capture_output=True, text=True, timeout=TIMEOUT, check=False)
    except (OSError, subprocess.SubprocessError) as error:
        return 127, "", str(error)[:200]
    lines = done.stderr.strip().splitlines()
    return done.returncode, done.stdout, (lines[0][:200] if lines else "")


def unit_status(unit: str) -> dict[str, Any]:
    code, out, err = run(["systemctl", "show", "--property=LoadState,ActiveState,SubState", unit])
    values = {key: value for key, _, value in (line.partition("=") for line in out.splitlines())}
    entry: dict[str, Any] = {
        "unit": unit,
        "load_state": values.get("LoadState"),
        "active_state": values.get("ActiveState"),
        "sub_state": values.get("SubState"),
    }
    problems = []
    if code != 0:
        problems.append(f"systemctl show failed: {err or code}")
    elif entry["active_state"] != "active":
        problems.append(f"{entry['active_state'] or 'unknown'} (load state {entry['load_state'] or 'unknown'})")
    return {**entry, "ok": not problems, "problems": problems}


def _unescape(text: str) -> str:
    return _ESCAPE.sub(lambda match: chr(int(match.group(1), 8)), text)


def parse_mountinfo(text: str) -> list[dict[str, Any]]:
    """The mounts of a ``mountinfo`` table in order: where, fstype, source and options (mount + superblock)."""

    mounts = []
    for line in text.splitlines():
        fields = line.split(" ")
        if "-" not in fields[6:]:
            continue
        sep = fields.index("-", 6)
        if len(fields) < sep + 3:
            continue
        options = fields[5].split(",") + (fields[sep + 3].split(",") if len(fields) > sep + 3 else [])
        mounts.append(
            {
                "where": _unescape(fields[4]),
                "fstype": fields[sep + 1],
                "source": _unescape(fields[sep + 2]),
                "options": list(dict.fromkeys(option for option in options if option)),
            }
        )
    return mounts


def mount_status(spec: dict[str, Any], mounts: list[dict[str, Any]] | None, table_error: str) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "where": spec["where"],
        "expected_fstype": spec["fstype"],
        "expected_source": spec["source"],
        "required_options": spec["required_options"],
        "present": False,
        "fstype": None,
        "source": None,
        "options": [],
        "missing_options": [],
        "unit": spec.get("unit"),
        "unit_active_state": None,
    }
    problems = []
    found = [mount for mount in mounts or () if mount["where"] == spec["where"]]
    if mounts is None:
        problems.append(f"cannot read the mount table: {table_error}")
    elif not found:
        problems.append("not mounted")
    else:
        top = found[-1]
        missing = [option for option in spec["required_options"] if option not in top["options"]]
        entry.update(present=True, fstype=top["fstype"], source=top["source"], options=top["options"])
        entry["missing_options"] = missing
        if top["fstype"] != spec["fstype"]:
            problems.append(f"file system type {top['fstype']}, expected {spec['fstype']}")
        if top["source"] != spec["source"]:
            problems.append(f"source {top['source']}, expected {spec['source']}")
        if missing:
            problems.append(f"missing options: {','.join(missing)}")
    if spec.get("unit"):
        unit = unit_status(spec["unit"])
        entry["unit_active_state"] = unit["active_state"]
        problems += [f"{spec['unit']}: {problem}" for problem in unit["problems"]]
    return {**entry, "ok": not problems, "problems": problems}


def certificate_status(path: str, warn_days: int, now: float) -> dict[str, Any]:
    entry: dict[str, Any] = {"path": path, "not_after": None, "not_after_epoch": None, "days_left": None}
    problems = []
    if not os.path.isfile(path):
        problems.append("missing")
    else:
        code, out, err = run(["openssl", "x509", "-noout", "-enddate", "-in", path])
        key, _, value = out.strip().partition("=")
        try:
            if code != 0 or key != "notAfter":
                raise ValueError
            epoch = calendar.timegm(time.strptime(" ".join(value.split()), "%b %d %H:%M:%S %Y GMT"))
        except ValueError:
            problems.append(f"openssl could not read the end date: {err or f'exit status {code}'}")
        else:
            days = math.floor((epoch - now) / 86400)
            entry.update(
                not_after=datetime.fromtimestamp(epoch, timezone.utc).isoformat(), not_after_epoch=epoch, days_left=days
            )
            if days <= 0:
                problems.append("expired" if epoch <= now else "expires within a day")
            elif days < warn_days:
                problems.append(f"expires in {days} days (warning below {warn_days})")
    return {**entry, "ok": not problems, "problems": problems}


def _guarded(build: Callable[[], dict[str, Any]], keep: dict[str, Any]) -> dict[str, Any]:
    """One entry; an unexpected error becomes ``ok: false`` instead of losing the report."""

    try:
        return build()
    except Exception as error:  # noqa: BLE001 - the report must survive any single check
        return {**keep, "ok": False, "problems": [f"internal error: {type(error).__name__}: {str(error)[:200]}"]}


def build_report(config: dict[str, Any], mountinfo_path: str, now: float) -> dict[str, Any]:
    warn_days = int(config["warn_days"])
    mounts: list[dict[str, Any]] | None = None
    table_error = ""
    if config["mounts"]:
        try:
            with open(mountinfo_path, encoding="utf-8", errors="replace") as handle:
                mounts = parse_mountinfo(handle.read())
        except OSError as error:
            table_error = str(error)[:200]
    report: dict[str, Any] = {
        "schema": SCHEMA,
        "collected_at": datetime.fromtimestamp(int(now), timezone.utc).isoformat(),
        "collected_at_epoch": int(now),
        "warn_days": warn_days,
        "units": {
            spec["id"]: _guarded(lambda spec=spec: unit_status(spec["unit"]), {"unit": spec["unit"]})
            for spec in config["units"]
        },
        "mounts": {
            spec["id"]: _guarded(lambda spec=spec: mount_status(spec, mounts, table_error), {"where": spec["where"]})
            for spec in config["mounts"]
        },
        "certificates": {
            spec["id"]: _guarded(lambda spec=spec: certificate_status(spec["path"], warn_days, now), {"path": spec["path"]})
            for spec in config["certificates"]
        },
    }
    sections = ("units", "mounts", "certificates")
    report["ok"] = all(entry["ok"] for section in sections for entry in report[section].values())
    return report


def write_atomic(path: str, text: str, group: str | None) -> None:
    tmp = os.path.join(os.path.dirname(path) or ".", f".{os.path.basename(path)}.tmp")
    descriptor = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    if group:
        os.chown(tmp, -1, grp.getgrnam(group).gr_gid)
    os.chmod(tmp, 0o640)
    os.replace(tmp, path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Write the NFS-over-TLS status report")
    parser.add_argument("--config", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--mountinfo", default="/proc/1/mountinfo")
    args = parser.parse_args(argv)
    try:
        with open(args.config, encoding="utf-8") as handle:
            config = json.load(handle)
        report = build_report(config, args.mountinfo, time.time())
        write_atomic(args.out, json.dumps(report, indent=2, sort_keys=True) + "\n", config.get("state_group"))
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"nfs-tls-status: {type(error).__name__}: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
