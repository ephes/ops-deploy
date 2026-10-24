"""Restart allowlisted units whose running executable a package update replaced.

Host side of ``ops_deploy.base.stale_exe_restart``, installed as
``/usr/local/libexec/ops-deploy/stale-exe-restart`` and run as root by the
system ``/usr/bin/python3 -I`` (standard library only, Python 3.11 or newer)::

    stale-exe-restart run       # stale-exe-restart.service (hourly timer, apt hook)
    stale-exe-restart report    # read-only: what ``run`` would do, as JSON on stdout

A reload never loads a new executable (nginx's SIGHUP forks new workers from
the old image), and a package's maintainer scripts only restart the units the
package itself ships. A unit that runs a packaged binary under its own name
keeps the old, deleted image after an upgrade. ``run`` restarts such a unit
only when it is on the allowlist (``/etc/ops-deploy/stale-exe-restart.json``)
and every check passes, in this order:

1. dpkg is idle: no process holds ``/var/lib/dpkg/lock-frontend`` or
   ``/var/lib/dpkg/lock``, no apt/dpkg process runs and no package is
   half-installed, unpacked, half-configured or waiting for triggers (waits up
   to 30 minutes, then defers to the next timer run);
2. the unit is loaded and active (a unit that is activating, reloading, ... is
   left for the next run), and every process in its cgroup runs the
   configured binary in the host's mount namespace and root directory; it is
   stale when one of them runs a deleted or replaced image (``/proc/PID/exe``
   is ``(deleted)`` or another device/inode than the file on disk);
3. the binary on disk is a regular file owned by root and writable only by
   root, belongs to the configured package, which is installed (``ii``), and
   ``dpkg --verify`` reports no change of it;
4. the unit's ``ExecStart`` (read over D-Bus, exact argument boundaries) is
   exactly the configured argv, every ``ExecStartPre`` is a ``-t`` run of the
   same binary, there is no ``ExecStartPost`` and ``NeedDaemonReload`` is
   ``no``;
5. no restart was attempted before for this binary (device, inode, sha256):
   at most one restart per installed binary, never a loop;
6. the configuration test passes as the unit's user and group: the binary with
   ``-t`` and the real start arguments, then each ``ExecStartPre``;
7. right before the restart, again: dpkg idle, the same main process still on a
   stale image, the unit and the binary still the approved, verified ones and
   the binary the tested one (otherwise ``deferred``: nothing done, the next run
   starts over);

then one ``systemctl try-restart`` (a unit stopped meanwhile stays stopped)
and post checks: active with a new main PID,
every process on the disk binary, the main image's sha256 equal to the file's,
and the optional local HTTP probe. For an allowlisted unit that is current or
inactive, checks 3 and 4 run too (``ready``), so an allowlist entry that does not
fit the unit shows before the next upgrade. Every other unit is only reported (replaced
executables, deleted libraries); processes in another mount namespace or root
directory are only checked for the kernel's ``(deleted)`` marks. ``run`` writes the result to
``/var/lib/ops-deploy/stale-exe-restart/state.json`` (it records every attempt
before the restart; a state file that exists but cannot be read blocks every
action and is left as it is) and exits 1 when an allowlisted unit needs
attention (also when it is not ``ready``), 2 on a configuration, state or
internal error.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import datetime
import fcntl
import hashlib
import http.client
import json
import os
import re
import stat
import subprocess
import sys
import time
import urllib.parse
from collections.abc import Callable, Iterator
from typing import Any

CONFIG_PATH = "/etc/ops-deploy/stale-exe-restart.json"
STATE_PATH = "/var/lib/ops-deploy/stale-exe-restart/state.json"
LOCK_PATH = "/run/ops-deploy-stale-exe-restart.lock"
DPKG_LOCKS = ("/var/lib/dpkg/lock-frontend", "/var/lib/dpkg/lock")
# Process names (``/proc/PID/comm``, at most 15 characters) of package managers.
PACKAGE_MANAGERS = frozenset({"apt", "apt-get", "aptitude", "dpkg", "unattended-upgr"})
SCHEMA = 1
DELETED = " (deleted)"
DPKG_WAIT_S = 1800
DPKG_POLL_S = 10
TEST_TIMEOUT_S = 60
RESTART_TIMEOUT_S = 300
POST_WAIT_S = 30
HTTP_WAIT_S = 30
COMMAND_TIMEOUT_S = 60
LIB_PREFIXES = ("/usr/", "/lib", "/bin/", "/sbin/", "/opt/")
MAX_LIBS = 20
TESTS = ("nginx",)
# dpkg-query ``db:Status-Abbrev``: second letter = status, third = error flag.
TRANSITIONAL = frozenset("HUFWt")
# Statuses of an allowlisted unit that make ``run`` exit 1.
ATTENTION = frozenset(
    {"not_loaded", "refused", "stale_no_retry", "test_failed", "restart_failed", "post_failed", "error"}
)
ENV = {"LC_ALL": "C", "LANG": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "SYSTEMD_PAGER": "", "SYSTEMD_COLORS": "0"}

_UNIT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@:-]*\.service")
_PACKAGE = re.compile(r"[a-z0-9][a-z0-9+.-]+")
_PATH = re.compile(r"/[A-Za-z0-9._/+-]+")
_HEADER = re.compile(r"[A-Za-z0-9-]+")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_LOCK_ID = re.compile(r"([0-9a-f]+):([0-9a-f]+):([0-9]+)")
_SEVERE = re.compile(r"\[(emerg|crit|alert)\]")
_LOOPBACK = ("127.0.0.1", "::1", "localhost")


class ConfigError(Exception):
    """The allowlist file is not what the deploy writes."""


class Refused(Exception):
    """A check failed: the unit is not restarted."""


def now() -> str:
    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(message: str) -> None:
    print(message, flush=True)


# -- configuration -------------------------------------------------------------


def _text(value: object, what: str) -> str:
    if not isinstance(value, str) or not value or _CONTROL.search(value):
        raise ConfigError(f"{what} must be a non-empty single-line string")
    return value


def _path(value: object, what: str) -> str:
    text = _text(value, what)
    if not _PATH.fullmatch(text) or os.path.normpath(text) != text:
        raise ConfigError(f"{what} must be a normalized absolute path")
    return text


def _http_probe(value: object, unit: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not {"url"} <= set(value) <= {"url", "headers", "status"}:
        raise ConfigError(f"{unit}: http_probe needs url and may have headers and status")
    url = _text(value["url"], f"{unit}: http_probe.url")
    parts = urllib.parse.urlsplit(url)
    try:
        port = parts.port
    except ValueError:
        port = None
    if parts.scheme != "http" or parts.hostname not in _LOOPBACK or port is None or parts.fragment:
        raise ConfigError(f"{unit}: http_probe.url must be http:// to a loopback address with a port")
    headers = value.get("headers", {})
    if not isinstance(headers, dict) or not all(
        isinstance(k, str) and _HEADER.fullmatch(k) and isinstance(v, str) and not _CONTROL.search(v)
        for k, v in headers.items()
    ):
        raise ConfigError(f"{unit}: http_probe.headers must map header names to single-line strings")
    status = value.get("status", 200)
    if isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599:
        raise ConfigError(f"{unit}: http_probe.status must be an HTTP status code")
    return {"url": url, "headers": dict(headers), "status": status}


def validate_entry(entry: object) -> dict[str, Any]:
    required = {"unit", "binary", "package", "test", "expected_argv"}
    if not isinstance(entry, dict) or not required <= set(entry) <= required | {"http_probe"}:
        raise ConfigError(f"each unit needs exactly {sorted(required)} and an optional http_probe")
    unit = _text(entry["unit"], "unit")
    if not _UNIT.fullmatch(unit):
        raise ConfigError(f"{unit!r} is not a .service unit name")
    binary = _path(entry["binary"], f"{unit}: binary")
    package = _text(entry["package"], f"{unit}: package")
    if not _PACKAGE.fullmatch(package):
        raise ConfigError(f"{unit}: {package!r} is not a Debian package name")
    if not isinstance(entry["test"], str) or entry["test"] not in TESTS:
        raise ConfigError(f"{unit}: test must be one of {', '.join(TESTS)}")
    argv = entry["expected_argv"]
    if not isinstance(argv, list) or not argv or argv[0] != binary:
        raise ConfigError(f"{unit}: expected_argv must be a list starting with the binary")
    for index, item in enumerate(argv):
        if not isinstance(item, str) or "\x00" in item or "\n" in item:
            raise ConfigError(f"{unit}: expected_argv[{index}] must be a string without NUL or newline")
    result: dict[str, Any] = {
        "unit": unit,
        "binary": binary,
        "package": package,
        "test": entry["test"],
        "expected_argv": list(argv),
    }
    if "http_probe" in entry:
        result["http_probe"] = _http_probe(entry["http_probe"], unit)
    return result


def parse_config(text: str) -> list[dict[str, Any]]:
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise ConfigError(f"not JSON: {exc}") from None
    if not isinstance(data, dict) or set(data) != {"schema", "units"} or data["schema"] != SCHEMA:
        raise ConfigError(f"expected an object with schema {SCHEMA} and units")
    if not isinstance(data["units"], list):
        raise ConfigError("units must be a list")
    entries = [validate_entry(entry) for entry in data["units"]]
    names = [entry["unit"] for entry in entries]
    if len(set(names)) != len(names):
        raise ConfigError("a unit is listed twice")
    return entries


# -- host access (one seam, so the decisions can be tested without a host) -------


class Host:
    """Reads and commands on the real host."""

    def run(self, argv: list[str], timeout: float = COMMAND_TIMEOUT_S) -> tuple[int, str, str]:
        try:
            done = subprocess.run(argv, capture_output=True, text=True, env=ENV, timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            return 124, "", f"timed out after {timeout:g}s"
        except OSError as exc:
            return 127, "", f"{type(exc).__name__}: {exc.strerror or exc}"
        return done.returncode, done.stdout, done.stderr

    def read(self, path: str) -> str:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read()

    def readlink(self, path: str) -> str:
        return os.readlink(path)

    def stat(self, path: str) -> os.stat_result:
        return os.stat(path)

    def lstat(self, path: str) -> os.stat_result:
        return os.lstat(path)

    def realpath(self, path: str) -> str:
        return os.path.realpath(path)

    def cgroup_root(self) -> str:
        # The unified hierarchy (cgroup v2), else systemd's own v1 hierarchy.
        return "/sys/fs/cgroup" if os.path.exists("/sys/fs/cgroup/cgroup.controllers") else "/sys/fs/cgroup/systemd"

    def pids(self) -> list[int]:
        return sorted(int(name) for name in os.listdir("/proc") if name.isdigit())

    def cgroup_pids(self, cgroup_dir: str) -> list[int]:
        """Every PID in ``cgroup_dir`` and the cgroups below it.

        A cgroup that vanished meanwhile is skipped; any other error (an unreadable
        directory or ``cgroup.procs``) propagates, so no process goes unseen.
        """

        def failed(error: OSError) -> None:
            if not isinstance(error, FileNotFoundError):
                raise error

        found: set[int] = set()
        for root, _dirs, files in os.walk(cgroup_dir, onerror=failed):
            if "cgroup.procs" in files:
                with contextlib.suppress(FileNotFoundError):
                    found |= {int(line) for line in self.read(os.path.join(root, "cgroup.procs")).split()}
        return sorted(found)

    def sha256(self, path: str) -> str:
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)

    def monotonic(self) -> float:
        return time.monotonic()

    def http_status(self, probe: dict[str, Any]) -> int:
        parts = urllib.parse.urlsplit(probe["url"])
        connection = http.client.HTTPConnection(parts.hostname or "", parts.port, timeout=10)
        try:
            target = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
            connection.request("GET", target, headers=probe["headers"])
            return connection.getresponse().status
        finally:
            connection.close()


# -- processes -------------------------------------------------------------------


def exe_of(host: Host, pid: int) -> tuple[str, bool, tuple[int, int]] | None:
    """``(path, deleted, (dev, ino))`` of ``pid``'s image; ``None`` for kernel threads and gone PIDs.

    Any other error (``PermissionError`` without ``CAP_SYS_PTRACE``) propagates:
    a process that cannot be inspected must never pass as "not there".
    """

    try:
        link = host.readlink(f"/proc/{pid}/exe")
        info = host.stat(f"/proc/{pid}/exe")
    except (FileNotFoundError, ProcessLookupError):
        return None
    deleted = link.endswith(DELETED)
    return (link[: -len(DELETED)] if deleted else link), deleted, (info.st_dev, info.st_ino)


def in_host_namespace(host: Host, pid: int, host_mnt: str) -> bool | None:
    """``pid`` sees the host's mounts and ``/`` as its root (its paths are host paths); ``None`` if gone."""

    try:
        return host.readlink(f"/proc/{pid}/ns/mnt") == host_mnt and host.readlink(f"/proc/{pid}/root") == "/"
    except (FileNotFoundError, ProcessLookupError):
        return None


def classify(deleted: bool, running: tuple[int, int], disk: tuple[int, int] | None) -> str:
    """``current``, ``deleted`` (the image was unlinked) or ``replaced`` (the path is another file now)."""

    if deleted:
        return "deleted"
    return "current" if running == disk else "replaced"


def deleted_libs(maps: str, exe: str) -> set[str]:
    """Executable mappings of unlinked files below the system prefixes, except the image itself."""

    found: set[str] = set()
    for line in maps.splitlines():
        parts = line.split(None, 5)
        if len(parts) != 6 or "x" not in parts[1] or not parts[5].endswith(DELETED):
            continue
        path = parts[5][: -len(DELETED)]
        if path != exe and path.startswith(LIB_PREFIXES):
            found.add(path)
    return found


def unit_of_cgroup(text: str) -> str:
    """The unit (``*.service``/``*.scope``) a ``/proc/PID/cgroup`` text names, else its path."""

    path = ""
    for line in text.splitlines():
        if line.startswith("0::"):
            path = line[3:]
            break
        if ":name=systemd:" in line:
            path = line.split(":name=systemd:", 1)[1]
    parts = [part for part in path.split("/") if part]
    for part in reversed(parts):
        if part.endswith((".service", ".scope")):
            return part
    return path or "?"


def disk_identity(host: Host, path: str) -> tuple[int, int] | None:
    try:
        info = host.stat(path)
    except OSError:
        return None
    return info.st_dev, info.st_ino


def report_only(host: Host, skip: set[str], host_mnt: str) -> tuple[list[dict[str, Any]], int, int]:
    """Units (other than ``skip``) with a stale executable or deleted libraries, never acted on;
    the number of processes in another mount namespace or root; and the number that could not be
    inspected (counted, never silently dropped).

    A process in another mount namespace or root (a container, a sandboxed unit) is skipped for
    the path comparison: its executable path is not a host path, so only the kernel's
    ``(deleted)`` marks (its image and its libraries) are reported for it.
    """

    units: dict[str, dict[str, Any]] = {}
    foreign = unreadable = 0
    for pid in host.pids():
        try:
            image = exe_of(host, pid)
            if image is None:
                continue
            unit = unit_of_cgroup(host.read(f"/proc/{pid}/cgroup"))
            if unit in skip:
                continue
            visible = in_host_namespace(host, pid, host_mnt)
        except FileNotFoundError:
            continue
        except OSError:
            unreadable += 1
            continue
        if visible is None:
            continue
        path, deleted, running = image
        entry = units.setdefault(unit, {"stale_exe": set(), "libs": set(), "pids": 0, "foreign": 0})
        entry["pids"] += 1
        if visible:
            stale = classify(deleted, running, disk_identity(host, path)) != "current"
        else:
            foreign += 1
            entry["foreign"] += 1
            stale = deleted
        if stale:
            entry["stale_exe"].add(path)
        with contextlib.suppress(OSError):
            entry["libs"] |= deleted_libs(host.read(f"/proc/{pid}/maps"), path)
    rows = []
    for unit, entry in sorted(units.items()):
        if not entry["stale_exe"] and not entry["libs"]:
            continue
        libs = sorted({os.path.basename(path) for path in entry["libs"]})
        rows.append(
            {
                "unit": unit,
                "pids": entry["pids"],
                "foreign_namespace_pids": entry["foreign"],
                "stale_exe": sorted(entry["stale_exe"]),
                "deleted_libs": libs[:MAX_LIBS],
                "deleted_libs_total": len(libs),
            }
        )
    return rows, foreign, unreadable


# -- dpkg and systemd --------------------------------------------------------------


def lock_holders(host: Host, paths: tuple[str, ...]) -> list[str]:
    """The files among ``paths`` that some process holds a lock on (``/proc/locks``)."""

    wanted: dict[tuple[int, int, int], str] = {}
    for path in paths:
        try:
            info = host.stat(path)
        except FileNotFoundError:
            continue
        wanted[(os.major(info.st_dev), os.minor(info.st_dev), info.st_ino)] = path
    held: set[str] = set()
    for line in host.read("/proc/locks").splitlines():
        for token in line.split():
            match = _LOCK_ID.fullmatch(token)
            if match:
                key = (int(match.group(1), 16), int(match.group(2), 16), int(match.group(3)))
                if key in wanted:
                    held.add(wanted[key])
                break
    return sorted(held)


def package_managers(host: Host) -> list[str]:
    """PIDs of apt/dpkg processes; a process whose name cannot be read counts (it may be one)."""

    found = []
    for pid in host.pids():
        try:
            name = host.read(f"/proc/{pid}/comm").strip()
        except (FileNotFoundError, ProcessLookupError):
            continue
        except OSError:
            found.append(f"{pid} (unreadable)")
            continue
        if name in PACKAGE_MANAGERS:
            found.append(str(pid))
    return found


def transitional_packages(host: Host) -> list[str]:
    code, out, err = host.run(["dpkg-query", "-W", "-f", "${db:Status-Abbrev} ${binary:Package}\n"])
    if code != 0:
        raise RuntimeError(f"dpkg-query -W failed: {err.strip()[:200]}")
    busy = []
    for line in out.splitlines():
        abbrev, name = line[:3], line[3:].strip()
        if len(abbrev) == 3 and (abbrev[1] in TRANSITIONAL or abbrev[2] == "R"):
            busy.append(f"{name} ({abbrev.strip()})")
    return busy


def dpkg_busy(host: Host) -> str | None:
    """Why dpkg is not idle, or ``None``."""

    held = lock_holders(host, DPKG_LOCKS)
    if held:
        return f"lock held: {', '.join(held)}"
    running = package_managers(host)
    if running:
        return f"apt/dpkg running (PID {', '.join(running)})"
    pending = transitional_packages(host)
    if pending:
        return f"{len(pending)} package(s) in transition: {', '.join(pending[:5])}"
    return None


def wait_dpkg_idle(host: Host, limit: float = DPKG_WAIT_S, poll: float = DPKG_POLL_S) -> tuple[str | None, float]:
    """``(None, waited)`` once dpkg is idle, or ``(reason, waited)`` when ``limit`` passed first."""

    start = host.monotonic()
    while True:
        reason = dpkg_busy(host)
        waited = host.monotonic() - start
        if reason is None or waited >= limit:
            return reason, waited
        host.sleep(poll)


UNIT_PROPERTIES = (
    "LoadState",
    "ActiveState",
    "MainPID",
    "ControlGroup",
    "NeedDaemonReload",
    "User",
    "Group",
    "FragmentPath",
    "DropInPaths",
)
ACTIVE_STATES = frozenset(
    {"active", "reloading", "inactive", "failed", "activating", "deactivating", "maintenance", "refreshing"}
)


def unit_properties(host: Host, unit: str) -> dict[str, str]:
    """``systemctl show`` of ``UNIT_PROPERTIES``; refused unless every one is there and well-formed."""

    argv = ["systemctl", "show"]
    for name in UNIT_PROPERTIES:
        argv += ["-p", name]
    code, out, err = host.run([*argv, "--", unit])
    if code != 0:
        raise Refused(f"systemctl show failed: {err.strip()[:200]}")
    props = {}
    for line in out.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            props[key] = value
    missing = [name for name in UNIT_PROPERTIES if name not in props]
    if missing:
        raise Refused(f"systemctl show did not return {', '.join(missing)}")
    if props["ActiveState"] not in ACTIVE_STATES:
        raise Refused(f"unknown ActiveState {props['ActiveState']!r}")
    if not props["MainPID"].isdigit():
        raise Refused(f"unexpected MainPID {props['MainPID']!r}")
    if not all(path.startswith("/") for path in unit_files(props)):
        raise Refused("unexpected FragmentPath or DropInPaths")
    return props


def unit_files(props: dict[str, str]) -> list[str]:
    """The unit file and its drop-ins, as systemd loaded them."""

    return [path for path in [props["FragmentPath"], *props["DropInPaths"].split()] if path]


def definition(host: Host, props: dict[str, str]) -> list[str]:
    """What a restart would load: the unit's user and group and the content of its unit file and drop-ins.

    Compared before the tests and right before the restart: a unit edit (and
    daemon-reload) in between changes it, whatever the edit was.
    """

    parts = [f"User={props['User']}", f"Group={props['Group']}"]
    for path in unit_files(props):
        try:
            digest = host.sha256(path)
        except FileNotFoundError:
            digest = "missing"
        parts.append(f"{path}={digest}")
    return parts


def bus_path(unit: str) -> str:
    """The unit's D-Bus object path (``sd_bus_path_encode``)."""

    encoded = "".join(
        char if char.isascii() and char.isalnum() and not (index == 0 and char.isdigit()) else f"_{ord(char):02x}"
        for index, char in enumerate(unit)
    )
    return "/org/freedesktop/systemd1/unit/" + (encoded or "_")


def parse_exec_json(text: str, name: str) -> list[tuple[str, list[str]]]:
    """``(path, argv)`` per entry of ``busctl --json=short get-property ... Exec*`` output."""

    try:
        data = json.loads(text)
        if data["type"] != "a(sasbttttuii)":
            raise ValueError(data["type"])
        return [(str(item[0]), [str(arg) for arg in item[1]]) for item in data["data"]]
    except (ValueError, KeyError, TypeError, IndexError) as exc:
        raise Refused(f"unexpected {name} over D-Bus: {type(exc).__name__}") from None


def exec_property(host: Host, unit: str, name: str) -> list[tuple[str, list[str]]]:
    """The unit's ``Exec*`` property ``name`` with exact argument boundaries, read over D-Bus."""

    code, out, err = host.run(
        [
            "busctl",
            "--json=short",
            "get-property",
            "org.freedesktop.systemd1",
            bus_path(unit),
            "org.freedesktop.systemd1.Service",
            name,
        ]
    )
    if code != 0:
        raise Refused(f"cannot read {name} over D-Bus: {err.strip()[:200]}")
    return parse_exec_json(out, name)


def dpkg_owners(host: Host, path: str) -> list[str]:
    """Packages owning ``path`` (``dpkg-query -S``); a diversion or another path refuses."""

    code, out, _ = host.run(["dpkg-query", "-S", path])
    if code != 0:
        raise Refused(f"{path} belongs to no package")
    owners: list[str] = []
    for line in out.splitlines():
        packages, sep, owned = line.rpartition(": ")
        if not sep or owned != path or packages.startswith("diversion by"):
            raise Refused(f"dpkg-query -S {path} is not a plain package entry: {line[:200]!r}")
        owners += [name.strip().split(":", 1)[0] for name in packages.split(",")]
    return owners


def check_integrity(host: Host, entry: dict[str, Any]) -> None:
    binary, package = entry["binary"], entry["package"]
    info = host.lstat(binary)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise Refused(f"{binary} is not a regular root-owned file writable only by root")
    owners = dpkg_owners(host, binary)
    if owners != [package]:
        raise Refused(f"{binary} belongs to {', '.join(owners) or 'nothing'}, not {package}")
    code, out, _ = host.run(["dpkg-query", "-W", "-f", "${db:Status-Abbrev}", package])
    if code != 0 or out != "ii ":
        raise Refused(f"package {package} is not installed cleanly ({out.strip() or 'unknown'})")
    code, out, err = host.run(["dpkg", "--verify", package])
    if code not in (0, 1):
        raise Refused(f"dpkg --verify {package} failed: {err.strip()[:200]}")
    if code == 1 and not out.strip():
        raise Refused(f"dpkg --verify {package} failed without naming a file")
    if any(line.split()[-1:] == [binary] for line in out.splitlines()):
        raise Refused(f"dpkg --verify reports {binary} as changed")


def check_unit_definition(host: Host, entry: dict[str, Any], props: dict[str, str]) -> list[list[str]]:
    """Refuse a unit whose start commands are not the approved ones; returns the ExecStartPre argvs."""

    unit, binary = entry["unit"], entry["binary"]
    if props.get("NeedDaemonReload") != "no":
        raise Refused("the unit file changed on disk (NeedDaemonReload); a restart would apply it")
    start = exec_property(host, unit, "ExecStart")
    if start != [(binary, entry["expected_argv"])]:
        raise Refused(f"ExecStart is {start!r}, not the approved argv")
    pre = exec_property(host, unit, "ExecStartPre")
    for path, argv in pre:
        if path != binary or not argv or argv[0] != binary or "-t" not in argv:
            raise Refused(f"ExecStartPre {argv!r} is not a -t run of {binary}")
    if exec_property(host, unit, "ExecStartPost"):
        raise Refused("the unit has ExecStartPost commands")
    return [argv for _path, argv in pre]


# -- one allowlisted unit ----------------------------------------------------------


def survey(host: Host, entry: dict[str, Any], host_mnt: str) -> dict[str, Any]:
    """What the unit runs now: status ``not_loaded``, ``inactive``, ``current`` or ``stale``.

    Raises :class:`Refused` when the unit is not one this tool may judge: a
    process in another mount namespace or root, one running another binary, one
    that cannot be inspected, or a main PID that is not among them.
    """

    unit, binary = entry["unit"], entry["binary"]
    props = unit_properties(host, unit)
    seen: dict[str, Any] = {"props": props, "pids": 0, "running": [], "deleted_libs": []}
    if props["LoadState"] != "loaded":
        seen["status"] = "not_loaded"
        return seen
    active, main = props["ActiveState"], props["MainPID"]
    if active in ("inactive", "failed"):
        seen["status"] = "inactive"
        return seen
    if active != "active":
        # activating, deactivating, reloading, ...: never acted on, the next run looks again.
        seen.update(status="changing", reason=f"the unit is {active}")
        return seen
    if main == "0":
        raise Refused("the unit is active without a main PID")
    if host.realpath(binary) != binary:
        raise Refused(f"{binary} is not its own real path (a symlink in it)")
    disk = disk_identity(host, binary)
    if disk is None:
        raise Refused(f"{binary} is missing")
    group = props.get("ControlGroup", "")
    if not group.startswith("/") or ".." in group.split("/"):
        raise Refused(f"unexpected ControlGroup {group!r}")
    states: set[str] = set()
    running: set[str] = set()
    libs: set[str] = set()
    inspected: set[str] = set()
    try:
        pids = host.cgroup_pids(host.cgroup_root() + group)
    except (OSError, ValueError) as exc:
        raise Refused(f"cannot list the unit's processes: {type(exc).__name__}") from None
    for pid in pids:
        try:
            image = exe_of(host, pid)
            visible = in_host_namespace(host, pid, host_mnt) if image else None
        except OSError as exc:
            raise Refused(f"cannot inspect PID {pid}: {type(exc).__name__}") from None
        if image is None or visible is None:
            continue  # a kernel thread or a process that just exited
        if not visible:
            raise Refused(f"PID {pid} runs in another mount namespace or root directory")
        path, deleted, ident = image
        if path != binary:
            raise Refused(f"PID {pid} runs {path}, not {binary}")
        inspected.add(str(pid))
        states.add(classify(deleted, ident, disk))
        running.add(f"{ident[0]}:{ident[1]}")
        with contextlib.suppress(OSError):
            libs |= deleted_libs(host.read(f"/proc/{pid}/maps"), path)
    if main not in inspected:
        raise Refused(f"the main PID {main} is not among the unit's inspected processes")
    seen.update(
        pids=len(inspected),
        running=sorted(running),
        disk=f"{disk[0]}:{disk[1]}",
        deleted_libs=sorted({os.path.basename(path) for path in libs})[:MAX_LIBS],
    )
    if states == {"current"}:
        seen["status"] = "current"
    else:
        seen["status"] = "stale"
        seen["stale_kinds"] = sorted(states - {"current"})
    return seen


def final_gate(
    host: Host, entry: dict[str, Any], host_mnt: str, main: str, key: str, pre: list[list[str]], loaded: list[str]
) -> str | None:
    """Right before the restart: why to defer, or ``None`` (a refusal raises :class:`Refused`).

    The tests take up to minutes; meanwhile the unit may have been stopped,
    restarted or redefined, and an apt run may have started and finished. So:
    dpkg idle again, the same main process still on a stale image, the unit and
    the binary still the approved, verified ones, the unit's definition (user,
    group, unit file, drop-ins) and the binary the tested ones.
    """

    busy = dpkg_busy(host)
    if busy:
        return f"dpkg became busy: {busy}"
    seen = survey(host, entry, host_mnt)
    if seen["status"] != "stale":
        return f"the unit is {seen['status']} now"
    if seen["props"]["MainPID"] != main:
        return "the main PID changed during the test"
    check_integrity(host, entry)
    if check_unit_definition(host, entry, seen["props"]) != pre:
        return "the unit's ExecStartPre changed during the test"
    if definition(host, seen["props"]) != loaded:
        return "the unit's definition (user, group, unit file or drop-ins) changed during the test"
    if f"{seen['disk']}:{host.sha256(entry['binary'])}" != key:
        return "the binary changed during the test"
    return None


def config_test(host: Host, entry: dict[str, Any], props: dict[str, str], pre: list[list[str]]) -> tuple[bool, str]:
    """The ``-t`` run with the real start arguments, then each ExecStartPre, as the unit's user."""

    user, group = props.get("User", ""), props.get("Group", "")
    wrap: list[str] = []
    if user and user != "root":
        wrap = ["runuser", "-u", user, *(["-g", group] if group else []), "--"]
    runs = [[entry["binary"], "-t", *entry["expected_argv"][1:]], *pre]
    for argv in runs:
        code, out, err = host.run([*wrap, *argv], timeout=TEST_TIMEOUT_S)
        text = out + err
        for line in text.splitlines()[-20:]:
            log(f"  test: {line[:300]}")
        if code != 0 or "test is successful" not in text or _SEVERE.search(text):
            return False, f"{' '.join(argv)[:200]} exited {code}"
    return True, f"{len(runs)} test(s) passed as {user or 'root'}"


def post_check(host: Host, entry: dict[str, Any], old_pid: str, host_mnt: str) -> tuple[bool, str]:
    """Active with a new main PID, every process on the disk binary, main image == file; then HTTP."""

    binary = entry["binary"]
    deadline = host.monotonic() + POST_WAIT_S
    new_pid = ""
    while True:
        try:
            seen = survey(host, entry, host_mnt)
            main = seen["props"].get("MainPID", "0")
            if seen["status"] != "current":
                reason = f"status {seen['status']}"
            elif main == old_pid:
                reason = "the main PID did not change"
            elif host.sha256(f"/proc/{main}/exe") != host.sha256(binary):
                reason = "the main process image differs from the file"
            else:
                new_pid = main
        except (Refused, OSError) as exc:
            reason = str(exc)
        if new_pid:
            break
        if host.monotonic() >= deadline:
            return False, reason
        host.sleep(1)
    probe = entry.get("http_probe")
    if probe:
        deadline = host.monotonic() + HTTP_WAIT_S
        while True:
            try:
                status = host.http_status(probe)
                reason = f"HTTP probe answered {status}, expected {probe['status']}"
            except (OSError, http.client.HTTPException) as exc:
                status, reason = 0, f"HTTP probe failed: {type(exc).__name__}"
            if status == probe["status"]:
                break
            if host.monotonic() >= deadline:
                return False, reason
            host.sleep(1)
    return True, f"main PID {old_pid} -> {new_pid}, image current"


def evaluate_unit(
    host: Host,
    entry: dict[str, Any],
    attempts: dict[str, Any],
    host_mnt: str,
    act: bool,
    save_attempt: Callable[[str, dict[str, Any]], None],
) -> dict[str, Any]:
    unit = entry["unit"]
    row: dict[str, Any] = {"unit": unit, "binary": entry["binary"], "package": entry["package"]}
    try:
        seen = survey(host, entry, host_mnt)
        row.update(
            {key: seen[key] for key in ("status", "reason", "pids", "running", "disk", "deleted_libs") if key in seen}
        )
        if seen["status"] in ("current", "inactive"):
            # Would the next update be restarted? An allowlist that does not fit the
            # unit (argv, package, pending edit) shows now, not at the next upgrade.
            try:
                check_integrity(host, entry)
                check_unit_definition(host, entry, seen["props"])
                row["ready"] = True
            except Refused as exc:
                row.update(ready=False, reason=f"a restart would be refused: {exc}")
            return row
        if seen["status"] != "stale":
            return row
        row["stale_kinds"] = seen["stale_kinds"]
        props = seen["props"]
        check_integrity(host, entry)
        pre = check_unit_definition(host, entry, props)
        key = f"{row['disk']}:{host.sha256(entry['binary'])}"
        previous = attempts.get(unit) or {}
        if previous.get("binary_key") == key:
            row.update(status="stale_no_retry", reason=f"one restart already attempted at {previous.get('at')}")
            return row
        if not act:
            row["action"] = "test_and_restart"
            return row
        loaded = definition(host, props)
        passed, detail = config_test(host, entry, props, pre)
        if not passed:
            row.update(status="test_failed", reason=detail)
            return row
        old_pid = props["MainPID"]
        why = final_gate(host, entry, host_mnt, old_pid, key, pre, loaded)
        if why:
            row.update(status="deferred", reason=why)
            return row
        attempt = {"binary_key": key, "at": now(), "result": "started", "old_main_pid": old_pid}
        save_attempt(unit, attempt)
        log(f"{unit}: restarting (stale: {', '.join(seen['stale_kinds'])}; {detail})")
        # try-restart: a unit stopped in the last moment stays stopped.
        code, out, err = host.run(["systemctl", "try-restart", "--", unit], timeout=RESTART_TIMEOUT_S)
        if code != 0:
            row.update(
                status="restart_failed", reason=f"systemctl try-restart exited {code}: {(err or out).strip()[:200]}"
            )
        else:
            ok, why = post_check(host, entry, old_pid, host_mnt)
            row.update(status="restarted" if ok else "post_failed", reason=why)
        save_attempt(unit, {**attempt, "result": row["status"], "detail": row["reason"], "finished_at": now()})
        return row
    except Refused as exc:
        row.update(status="refused", reason=str(exc))
    except Exception as exc:  # one unit's failure must not stop the others
        row.update(status="error", reason=f"{type(exc).__name__}: {exc}"[:300])
    return row


# -- state and main ----------------------------------------------------------------


class StateError(Exception):
    """The state file exists but cannot be read: earlier attempts are unknown."""


def read_state(host: Host, path: str) -> dict[str, Any]:
    """The previous state; ``{}`` only when there is none yet. Anything else unreadable raises.

    The state holds the restart attempts; reading a damaged one as "no attempts"
    could restart the same binary again, so it blocks every action instead.
    """

    try:
        text = host.read(path)
    except FileNotFoundError:
        return {}
    except OSError as exc:
        raise StateError(f"cannot read {path}: {type(exc).__name__}") from None
    try:
        data = json.loads(text)
    except ValueError:
        raise StateError(f"{path} is not JSON") from None
    attempts = data.get("attempts", {}) if isinstance(data, dict) else None
    if not isinstance(attempts, dict) or not all(valid_attempt(item) for item in attempts.values()):
        raise StateError(f"{path} is not a state document")
    return dict(data)


_BINARY_KEY = re.compile(r"[0-9]+:[0-9]+:[0-9a-f]{64}")


def valid_attempt(item: object) -> bool:
    """A recorded attempt: the binary key it was made for, when, and its result."""

    return (
        isinstance(item, dict)
        and isinstance(item.get("binary_key"), str)
        and _BINARY_KEY.fullmatch(item["binary_key"]) is not None
        and isinstance(item.get("at"), str)
        and isinstance(item.get("result"), str)
    )


def write_state(path: str, data: dict[str, Any]) -> None:
    """Replace ``path`` atomically (``0644``: no secrets, read by monitoring)."""

    temporary = os.path.join(os.path.dirname(path), f".{os.path.basename(path)}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temporary)
        raise


@contextlib.contextmanager
def run_lock(path: str) -> Iterator[bool]:
    """Exclusive, non-blocking: ``False`` when another ``run`` holds it."""

    descriptor = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            yield False
            return
        yield True
    finally:
        os.close(descriptor)


def evaluate(
    host: Host, entries: list[dict[str, Any]], state: dict[str, Any], act: bool, state_path: str | None
) -> dict[str, Any]:
    host_mnt = host.readlink("/proc/1/ns/mnt")
    attempts = dict(state.get("attempts") or {})

    def save_attempt(unit: str, attempt: dict[str, Any]) -> None:
        # Persisted before the restart, so a crash cannot turn into a loop.
        attempts[unit] = dict(attempt)
        if state_path:
            write_state(state_path, {**state, "attempts": attempts})

    rows = [evaluate_unit(host, entry, attempts, host_mnt, act, save_attempt) for entry in entries]
    others, foreign, unreadable = report_only(host, {entry["unit"] for entry in entries}, host_mnt)
    attention = [row["unit"] for row in rows if row["status"] in ATTENTION or row.get("ready") is False]
    return {
        "schema": SCHEMA,
        "mode": "run" if act else "report",
        "checked_at": now(),
        "result": "attention" if attention else "ok",
        "attention": attention,
        "units": rows,
        "report_only": others,
        "foreign_namespace_pids": foreign,
        "unreadable_pids": unreadable,
        "attempts": attempts,
    }


def summary_lines(result: dict[str, Any]) -> list[str]:
    lines = [
        f"{row['unit']}: {row['status']}" + (f" ({row['reason']})" if row.get("reason") else "")
        for row in result.get("units", [])
    ]
    stale = [row["unit"] for row in result.get("report_only", []) if row["stale_exe"]]
    libs = [row["unit"] for row in result.get("report_only", []) if row["deleted_libs"]]
    lines.append(
        f"report only: {len(stale)} unit(s) with a replaced executable"
        + (f" ({', '.join(stale)})" if stale else "")
        + f", {len(libs)} with deleted libraries;"
        + f" {result.get('foreign_namespace_pids', 0)} process(es) in other mount namespaces (path comparison skipped),"
        + f" {result.get('unreadable_pids', 0)} not readable"
    )
    return lines


def run(host: Host, config_path: str, state_path: str) -> int:
    try:
        state = read_state(host, state_path)
    except StateError as exc:
        # Left as it is for inspection; nothing acts until it is repaired or removed.
        log(f"state error: {exc}; nothing done")
        return 2
    try:
        entries = parse_config(host.read(config_path))
    except (OSError, ConfigError) as exc:
        log(f"configuration error: {exc}")
        write_state(state_path, {**state, "checked_at": now(), "result": "config_error", "reason": str(exc)[:300]})
        return 2
    try:
        reason, waited = wait_dpkg_idle(host)
        if reason is not None:
            log(f"dpkg is not idle after {waited:.0f}s ({reason}); deferred to the next run")
            write_state(state_path, {**state, "checked_at": now(), "result": "deferred", "reason": reason})
            return 0
        result = evaluate(host, entries, state, act=True, state_path=state_path)
    except Exception as exc:
        log(f"internal error: {type(exc).__name__}: {exc}")
        with contextlib.suppress(StateError):
            latest = read_state(host, state_path)
            write_state(
                state_path,
                {**latest, "checked_at": now(), "result": "error", "reason": f"{type(exc).__name__}: {exc}"},
            )
        return 2
    result["dpkg_waited_s"] = round(waited)
    write_state(state_path, result)
    for line in summary_lines(result):
        log(line)
    return 1 if result["attention"] else 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="stale-exe-restart")
    parser.add_argument("mode", choices=("run", "report"))
    parser.add_argument("--config", default=CONFIG_PATH)
    parser.add_argument("--config-b64", help="the allowlist JSON, base64 (report mode, while planning)")
    parser.add_argument("--state", default=STATE_PATH)
    args = parser.parse_args(argv)
    host = Host()
    if args.mode == "report":
        text = base64.b64decode(args.config_b64).decode() if args.config_b64 else host.read(args.config)
        try:
            state, state_error = read_state(host, args.state), None
        except StateError as exc:
            state, state_error = {}, str(exc)
        result = evaluate(host, parse_config(text), state, act=False, state_path=None)
        if state_error:
            result.update(state_error=state_error, result="attention")
        print(json.dumps(result, sort_keys=True))
        return 0
    with run_lock(LOCK_PATH) as acquired:
        if not acquired:
            log("another run holds the lock; nothing to do")
            return 0
        return run(host, args.config, args.state)


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except ConfigError as exc:
        print(f"stale-exe-restart: configuration error: {exc}", file=sys.stderr)
        sys.exit(2)
