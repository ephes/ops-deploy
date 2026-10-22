#!/usr/bin/env python3
"""OS lifecycle status of this host as one JSON report (ops-deploy ``services.os_lifecycle``).

Two modes, both run with ``python3 -I`` and only the standard library:

``collect --policy FILE --state-dir DIR``
    Run as root by ``os-lifecycle-collector.service``. Builds the report and
    writes ``DIR/state.json`` atomically (``root:<state_group> 0640``). It also
    keeps ``DIR/pending-security-seen.json`` (root only): when each pending
    security update (package and version) was first seen, so the report can
    say how old the oldest one is. Nothing else on the host is changed:
    ``apt-get`` only simulates, without locks and without writing its caches.

``show --state-dir DIR``
    Prints ``DIR/state.json``. This is the forced command of the collector's
    SSH key (``restrict,command="..."``): it reads that one file, takes no
    input from the client (``SSH_ORIGINAL_COMMAND`` is ignored) and runs
    nothing.

The report (``schema_version`` 1) carries ages and remaining days as numbers,
computed when it is written, because Nyxmon's json-metrics rules only compare
values. An unknown value is ``null``; a rule on it fails, so "unknown" is
visible rather than green.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import glob
import grp
import io
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable

SCHEMA_VERSION = 1
STATE_FILE = "state.json"
SEEN_FILE = "pending-security-seen.json"
DISABLED = {"", "0", "false", "no", "off", "never"}
APT_SIMULATE = [
    "apt-get",
    "-s",
    "-o",
    "Debug::NoLocking=1",
    "-o",
    "Dir::Cache::pkgcache=",
    "-o",
    "Dir::Cache::srcpkgcache=",
    "dist-upgrade",
]
# "Inst <pkg> [<old>] (<new> <origin>, <origin> [<arch>])", sometimes followed by " []".
_INST = re.compile(r"^Inst (\S+)(?: \[[^\]]*\])? \((\S+) ([^()]*)\)(?: \[[^\]]*\])?\s*$")
_ARCH = re.compile(r"\s*\[[^\]]*\]\s*$")
_KERNEL = re.compile(r"(\d+\.\d+\.\d+-\d+)")
_UU_START = "Starting unattended upgrades script"
_LOG_TIME = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")

Run = Callable[[list[str]], tuple[int, str]]


def run_command(argv: list[str], timeout: int = 300) -> tuple[int, str]:
    """``argv`` in the C locale; (return code, stdout). A missing tool or a timeout is code 127/124."""

    env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "LANG": "C"}
    try:
        done = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout, env=env, stdin=subprocess.DEVNULL, check=False
        )
    except FileNotFoundError:
        return 127, ""
    except subprocess.TimeoutExpired:
        return 124, ""
    return done.returncode, done.stdout


# -- lifecycle data ---------------------------------------------------------------------


def parse_os_release(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip():
            values[key.strip()] = value.strip().strip("\"'")
    return values


def _date(value: Any) -> dt.date | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return dt.date.fromisoformat(value[:10])
    except ValueError:
        return None


def _version_tuple(cycle: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", cycle))


def parse_distro_info(text: str, distro: str) -> list[dict[str, Any]]:
    """Cycles of ``/usr/share/distro-info/<distro>.csv``: cycle, codename, release, support end, final EOL, LTS.

    Debian: ``eol`` is the end of regular support, ``eol-lts`` the end of
    Debian LTS. Ubuntu: ``eol``/``eol-server`` is the end of standard support,
    which is also the end without paid ESM.
    """

    cycles = []
    for row in csv.DictReader(io.StringIO(text)):
        version = (row.get("version") or "").strip()
        if not version:
            continue
        release = _date(row.get("release"))
        if distro == "debian":
            support = _date(row.get("eol"))
            final = _date(row.get("eol-lts")) or support
            lts = False
        else:
            ends = [d for d in (_date(row.get("eol")), _date(row.get("eol-server"))) if d]
            support = max(ends) if ends else None
            final = support
            lts = "LTS" in version
        cycles.append(
            {
                "cycle": version.split()[0],
                "codename": (row.get("series") or "").strip().lower(),
                "release": release,
                "support_end": support,
                "eol": final,
                "lts": lts,
            }
        )
    return cycles


def parse_snapshot(entries: Any) -> list[dict[str, Any]]:
    """Cycles of an endoflife.date product list (``support`` and ``eol`` as above)."""

    cycles = []
    for entry in entries if isinstance(entries, list) else []:
        if not isinstance(entry, dict) or not isinstance(entry.get("cycle"), str):
            continue
        support = _date(entry.get("support")) or _date(entry.get("eol"))
        codename = entry.get("codename")
        cycles.append(
            {
                "cycle": entry["cycle"],
                "codename": codename.split()[0].lower() if isinstance(codename, str) and codename else "",
                "release": _date(entry.get("releaseDate")),
                "support_end": support,
                "eol": _date(entry.get("eol")) or support,
                "lts": entry.get("lts") is True,
            }
        )
    return cycles


def _match(cycles: list[dict[str, Any]], cycle: str, codename: str) -> dict[str, Any] | None:
    for entry in cycles:
        if cycle and entry["cycle"] == cycle:
            return entry
    for entry in cycles:
        if codename and entry["codename"] == codename:
            return entry
    return None


def _days(until: dt.date | None, today: dt.date) -> int | None:
    return None if until is None else (until - today).days


def lifecycle(
    os_release: dict[str, str],
    distro_info: list[dict[str, Any]],
    snapshot: list[dict[str, Any]],
    *,
    today: dt.date,
    horizon_days: int,
    tolerance_days: int,
    snapshot_fetched: dt.date | None,
) -> dict[str, Any]:
    """The ``os`` section: cycle, support horizon, the newest stable cycle, whether an upgrade is due."""

    os_id = os_release.get("ID", "")
    cycle = os_release.get("VERSION_ID", "")
    codename = os_release.get("VERSION_CODENAME", "")
    local = _match(distro_info, cycle, codename)
    remote = _match(snapshot, cycle, codename)
    primary = local or remote
    support_end = primary["support_end"] if primary else None
    eol = primary["eol"] if primary else None
    agree = False
    if local and remote:
        pairs = [(local[key], remote[key]) for key in ("support_end", "eol")]
        agree = all(a is not None and b is not None and abs((a - b).days) <= tolerance_days for a, b in pairs)
    stable = {
        entry["cycle"]: entry
        for entry in [*snapshot, *distro_info]
        if entry["release"] is not None and entry["release"] <= today and (os_id != "ubuntu" or entry["lts"])
    }
    latest = max(stable, key=_version_tuple) if stable else None
    current = _version_tuple(cycle) if cycle else ()
    behind = sum(1 for name in stable if current and _version_tuple(name) > current) if current else None
    support_days = _days(support_end, today)
    eol_days = _days(eol, today)
    if support_days is None or eol_days is None:
        phase, due = "unknown", None
    else:
        phase = "standard" if support_days >= 0 else ("extended" if eol_days >= 0 else "eol")
        due = support_days < 0 if os_id == "debian" else support_days < horizon_days
    return {
        "id": os_id,
        "cycle": cycle,
        "codename": codename,
        "pretty_name": os_release.get("PRETTY_NAME", ""),
        "support_end": support_end.isoformat() if support_end else None,
        "eol": eol.isoformat() if eol else None,
        "support_days_remaining": support_days,
        "eol_days_remaining": eol_days,
        "phase": phase,
        "latest_stable_cycle": latest,
        "releases_behind": behind,
        "upgrade_due": due,
        "release_upgrade_available": bool(behind) if behind is not None else None,
        "lifecycle_source": "distro-info" if local else ("endoflife-snapshot" if remote else None),
        "lifecycle_sources_agree": agree,
        "lifecycle_data_age_days": (today - snapshot_fetched).days if snapshot_fetched else None,
    }


# -- apt ----------------------------------------------------------------------------------


def parse_simulation(text: str) -> list[dict[str, Any]]:
    """``Inst`` lines of ``apt-get -s dist-upgrade``: package, new version, origins, security or not."""

    found = []
    for line in text.splitlines():
        match = _INST.match(line)
        if not match:
            continue
        origins = [part.strip() for part in _ARCH.sub("", match.group(3)).split(",") if part.strip()]
        security = any("-security" in origin or origin.startswith("Debian-Security:") for origin in origins)
        found.append({"package": match.group(1), "version": match.group(2), "origins": origins, "security": security})
    return found


def _newest_mtime(pattern: str) -> float | None:
    times = []
    for path in glob.glob(pattern):
        try:
            times.append(os.stat(path).st_mtime)
        except OSError:
            continue
    return max(times) if times else None


def _hours(since: float | None, now: float) -> float | None:
    return None if since is None else round(max(0.0, now - since) / 3600, 1)


def apt_status(root: Path, run: Run, now: float, seen: dict[str, float]) -> tuple[dict[str, Any], dict[str, float]]:
    """The ``apt`` section and the updated first-seen map of pending security updates."""

    lists = root / "var/lib/apt/lists"
    index = _newest_mtime(str(lists / "*security*InRelease")) or _newest_mtime(str(lists / "*security*_Release"))
    code, output = run(APT_SIMULATE)
    if code != 0:
        raise RuntimeError(f"apt-get -s dist-upgrade exited {code}")
    pending = parse_simulation(output)
    security = [item for item in pending if item["security"]]
    current = {f"{item['package']} {item['version']}": seen.get(f"{item['package']} {item['version']}", now) for item in security}
    oldest = min(current.values()) if current else None
    code, held = run(["apt-mark", "showhold"])
    return (
        {
            "security_index_age_hours": _hours(index, now),
            "pending_total": len(pending),
            "pending_security_count": len(security),
            "pending_security_max_age_hours": _hours(oldest, now) if oldest is not None else 0,
            "pending_security": sorted(current)[:50],
            "held": sorted(line.strip() for line in held.splitlines() if line.strip()) if code == 0 else None,
        },
        current,
    )


# -- unattended-upgrades --------------------------------------------------------------------


def apt_config_value(dump: str, key: str) -> str | None:
    found = None
    for line in dump.splitlines():
        match = re.match(rf'^{re.escape(key)} "([^"]*)";\s*$', line.strip())
        if match:
            found = match.group(1)
    return found


def last_uu_run(log: str) -> tuple[float | None, str | None]:
    """Start time (local) and result (``ok``/``error``) of the last run in the unattended-upgrades log."""

    blocks: list[list[str]] = []
    for line in log.splitlines():
        if _UU_START in line:
            blocks.append([line])
        elif blocks:
            blocks[-1].append(line)
    if not blocks:
        return None, None
    last = blocks[-1]
    match = _LOG_TIME.match(last[0])
    started = time.mktime(time.strptime(match.group(1), "%Y-%m-%d %H:%M:%S")) if match else None
    return started, "error" if any(" ERROR " in line for line in last) else "ok"


def uu_status(root: Path, run: Run, now: float) -> dict[str, Any]:
    """The ``uu`` section. The stamp is only touched after a successful run (``apt.systemd.daily``)."""

    installed = (root / "usr/bin/unattended-upgrade").exists()
    code, dump = run(["apt-config", "dump"])
    value = apt_config_value(dump, "APT::Periodic::Unattended-Upgrade") if code == 0 else None
    stamp = root / "var/lib/apt/periodic/unattended-upgrades-stamp"
    try:
        success: float | None = stamp.stat().st_mtime
    except OSError:
        success = None
    log = root / "var/log/unattended-upgrades/unattended-upgrades.log"
    try:
        started, result = last_uu_run(log.read_text(errors="replace"))
    except OSError:
        started, result = None, None
    code, service = run(["systemctl", "show", "--property=Result", "--value", "apt-daily-upgrade.service"])
    return {
        "installed": installed,
        "enabled": installed and value is not None and value.strip().lower() not in DISABLED,
        "periodic_value": value,
        "last_success_epoch": int(success) if success is not None else None,
        "last_success_age_hours": _hours(success, now),
        "last_run_epoch": int(started) if started is not None else None,
        "last_result": result,
        "service_result": (service.strip() or None) if code == 0 else None,
    }


# -- reboot ---------------------------------------------------------------------------------


def kernel_versions(dpkg_output: str) -> list[str]:
    """Versions of installed ``linux-image-*`` packages, oldest first (as ``os_apt_maintenance``)."""

    versions = set()
    for line in dpkg_output.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[-1] != "installed":
            continue
        match = _KERNEL.search(parts[0])
        if match:
            versions.add(match.group(1))
    return sorted(versions, key=_version_tuple)


def reboot_status(root: Path, run: Run, now: float, release: str, reboot_class: str) -> dict[str, Any]:
    """The ``reboot`` section: marker and stale kernel, since when, and the uptime."""

    reasons, since = [], []
    marker = root / "var/run/reboot-required"
    if marker.exists():
        reasons.append("reboot_required_flag")
        since.append(marker.stat().st_mtime)
    running_match = _KERNEL.search(release)
    newest = None
    code, output = run(["dpkg-query", "-W", "-f", "${Package} ${Status}\n", "linux-image-*"])
    # dpkg-query exits 1 when no package matches (a kernel installed outside
    # dpkg): no kernel signal, reported as such. Any other failure (dpkg
    # broken, timeout, missing) makes the section unknown instead of "no reboot".
    if code not in (0, 1):
        raise RuntimeError(f"dpkg-query exited {code}")
    installed = kernel_versions(output) if code == 0 else []
    kernel_check = "no-version"
    if running_match:
        kernel_check = "compared" if installed else "no-dpkg-kernels"
        if installed and _version_tuple(installed[-1]) > _version_tuple(running_match.group(1)):
            newest = installed[-1]
            reasons.append("stale_kernel")
            listed = _newest_mtime(str(root / f"var/lib/dpkg/info/linux-image-*{newest}*.list"))
            if listed is not None:
                since.append(listed)
    try:
        uptime = float((root / "proc/uptime").read_text().split()[0])
    except (OSError, ValueError, IndexError):
        uptime = None
    pkgs_file = root / "var/run/reboot-required.pkgs"
    pkgs = sorted(set(pkgs_file.read_text().split()))[:20] if pkgs_file.exists() else []
    required = bool(reasons)
    age = (_hours(min(since), now) if since else None) if required else 0
    return {
        "required": required,
        "reasons": reasons,
        "required_age_hours": age,
        "packages": pkgs,
        "running_kernel": release,
        "newest_installed_kernel": newest,
        # "compared", or why the kernel signal is absent: no dpkg kernel
        # packages, or a running kernel release without a version to compare.
        "kernel_check": kernel_check,
        "uptime_days": round(uptime / 86400, 1) if uptime is not None else None,
        "boot_epoch": int(now - uptime) if uptime is not None else None,
        "reboot_class": reboot_class,
    }


# -- the report -----------------------------------------------------------------------------


def build_report(
    policy: dict[str, Any], seen: dict[str, float], *, root: Path, run: Run, now: float
) -> tuple[dict[str, Any], dict[str, float]]:
    """The whole report; a failing section becomes ``null`` plus an entry in ``errors``."""

    errors: list[str] = []
    today = dt.datetime.fromtimestamp(now, tz=dt.timezone.utc).date()
    snapshot = policy.get("endoflife") or {}

    def section(name: str, build: Callable[[], Any]) -> Any:
        try:
            return build()
        except Exception as error:  # noqa: BLE001 - one broken probe must not hide the rest
            errors.append(f"{name}: {type(error).__name__}: {error}")
            return None

    def os_section() -> dict[str, Any]:
        release = parse_os_release((root / "etc/os-release").read_text())
        distro = release.get("ID", "")
        info_path = root / f"usr/share/distro-info/{distro}.csv"
        info = parse_distro_info(info_path.read_text(), distro) if info_path.exists() else []
        return lifecycle(
            release,
            info,
            parse_snapshot(snapshot.get(distro)),
            today=today,
            horizon_days=int(policy.get("upgrade_horizon_days", 365)),
            tolerance_days=int(policy.get("lifecycle_tolerance_days", 31)),
            snapshot_fetched=_date(snapshot.get("fetched_at")),
        )

    apt_result = section("apt", lambda: apt_status(root, run, now, seen))
    apt_section, new_seen = apt_result if apt_result else (None, seen)
    report = {
        "schema_version": SCHEMA_VERSION,
        "host": policy.get("host") or os.uname().nodename,
        "generated_at_epoch": int(now),
        "generated_at": dt.datetime.fromtimestamp(int(now), tz=dt.timezone.utc).isoformat(),
        "os": section("os", os_section),
        "apt": apt_section,
        "uu": section("uu", lambda: uu_status(root, run, now)),
        "reboot": section(
            "reboot",
            lambda: reboot_status(root, run, now, os.uname().release, str(policy.get("reboot_class", ""))),
        ),
        "errors": errors,
    }
    return report, new_seen


def write_atomic(path: Path, text: str, *, mode: int, group: str | None = None) -> None:
    tmp = path.with_name(f".{path.name}.tmp")
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(tmp, mode)
    if group is not None:
        os.chown(tmp, 0, grp.getgrnam(group).gr_gid)
    os.replace(tmp, path)


def collect(policy_path: Path, state_dir: Path) -> int:
    policy = json.loads(policy_path.read_text())
    seen_path = state_dir / SEEN_FILE
    try:
        seen = {str(k): float(v) for k, v in json.loads(seen_path.read_text()).items()}
    except (OSError, ValueError, AttributeError):
        seen = {}
    report, seen = build_report(policy, seen, root=Path("/"), run=run_command, now=time.time())
    write_atomic(seen_path, json.dumps(seen, sort_keys=True) + "\n", mode=0o600)
    group = policy.get("state_group") or "root"
    write_atomic(state_dir / STATE_FILE, json.dumps(report, sort_keys=True) + "\n", mode=0o640, group=group)
    return 0


def show(state_dir: Path) -> int:
    try:
        report = json.loads((state_dir / STATE_FILE).read_text())
        if not isinstance(report, dict):
            raise ValueError("the report is not a JSON object")
    except (OSError, ValueError) as error:
        print(json.dumps({"error": f"no readable report: {type(error).__name__}"}))
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="OS lifecycle status report")
    sub = parser.add_subparsers(dest="mode", required=True)
    collect_parser = sub.add_parser("collect")
    collect_parser.add_argument("--policy", type=Path, required=True)
    collect_parser.add_argument("--state-dir", type=Path, required=True)
    show_parser = sub.add_parser("show")
    show_parser.add_argument("--state-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.mode == "collect":
        return collect(args.policy, args.state_dir)
    return show(args.state_dir)


if __name__ == "__main__":
    sys.exit(main())
