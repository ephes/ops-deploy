"""``base/files/stale_exe_restart.py``: parsing and the restart decisions, against a fake host.

The program reaches the host only through its ``Host`` class; ``FakeHost``
replaces it with an in-memory nginx unit, so every branch of the decision table
runs without root, ``/proc`` or systemd. The real host is covered by
``tests/test_base_stale_exe_restart_docker.py``.
"""

from __future__ import annotations

import importlib.util
import json
import os
import stat
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

SCRIPT = Path(__file__).parents[1] / "src" / "ops_deploy" / "base" / "files" / "stale_exe_restart.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("stale_exe_restart_host", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


host_script = _load()

BINARY = "/usr/sbin/nginx"
UNIT = "web-nginx.service"
GROUP = "/system.slice/web-nginx.service"
ARGV = [BINARY, "-c", "/etc/web/nginx.conf", "-g", "daemon off;"]
PRE = [BINARY, "-t", "-c", "/etc/web/nginx.conf"]
DEV = 2306
OLD_INO, NEW_INO = 50, 100
OLD_SHA, NEW_SHA = "a" * 64, "b" * 64
HOST_MNT = "mnt:[4026531841]"
FRAGMENT = "/etc/systemd/system/web-nginx.service"
OK_TEST = (0, "", "nginx: the configuration file /etc/web/nginx.conf syntax is ok\n"
           "nginx: configuration file /etc/web/nginx.conf test is successful\n")  # fmt: skip
ENTRY: dict[str, Any] = {
    "unit": UNIT,
    "binary": BINARY,
    "package": "nginx",
    "test": "nginx",
    "expected_argv": ARGV,
}

Response = tuple[int, str, str] | Callable[["FakeHost", list[str]], tuple[int, str, str]]


def stat_result(*, dev: int = DEV, ino: int = 1, mode: int = stat.S_IFREG | 0o755, uid: int = 0) -> os.stat_result:
    return os.stat_result((mode, ino, dev, 1, uid, 0, 1000, 0, 0, 0))


def exec_json(*entries: list[str]) -> str:
    data = [[argv[0], argv, False, 0, 0, 0, 0, 0, 0, 0] for argv in entries]
    return json.dumps({"type": "a(sasbttttuii)", "data": data})


class FakeHost(host_script.Host):  # type: ignore[name-defined,misc]
    """An nginx unit (master + worker) on an in-memory host."""

    def __init__(self, *, stale: bool = True) -> None:
        self.files: dict[str, str] = {"/proc/locks": ""}
        self.links: dict[str, str] = {"/proc/1/ns/mnt": HOST_MNT}
        self.denied: set[str] = set()
        self.stats: dict[str, os.stat_result] = {BINARY: stat_result(ino=NEW_INO)}
        self.digests: dict[str, str] = {BINARY: NEW_SHA}
        self.cgroups: dict[str, list[int]] = {}
        self.all_pids: list[int] = []
        self.calls: list[list[str]] = []
        self.clock = 0.0
        self.http = 200
        self.main_pid = 10
        image_ino, image_sha = (OLD_INO, OLD_SHA) if stale else (NEW_INO, NEW_SHA)
        self.processes(10, 11, ino=image_ino, sha=image_sha, deleted=stale)
        self.props = {
            "LoadState": "loaded",
            "ActiveState": "active",
            "MainPID": "10",
            "ControlGroup": GROUP,
            "NeedDaemonReload": "no",
            "User": "www",
            "Group": "www",
            "FragmentPath": FRAGMENT,
            "DropInPaths": "",
        }
        self.digests[FRAGMENT] = "f" * 64
        self.responses: dict[tuple[str, ...], Response] = {
            ("dpkg-query", "-S", BINARY): (0, f"nginx: {BINARY}\n", ""),
            ("dpkg-query", "-W", "-f", "${db:Status-Abbrev}", "nginx"): (0, "ii ", ""),
            ("dpkg", "--verify", "nginx"): (0, "", ""),
            ("dpkg-query", "-W", "-f", "${db:Status-Abbrev} ${binary:Package}\n"): (0, "ii  nginx\nrc  old\n", ""),
            self.busctl("ExecStart"): (0, exec_json(ARGV), ""),
            self.busctl("ExecStartPre"): (0, exec_json(PRE), ""),
            self.busctl("ExecStartPost"): (0, exec_json(), ""),
            ("runuser", "-u", "www", "-g", "www", "--", BINARY, "-t", *ARGV[1:]): OK_TEST,
            ("runuser", "-u", "www", "-g", "www", "--", *PRE): OK_TEST,
            ("systemctl", "try-restart", "--", UNIT): FakeHost.restart,
        }

    @staticmethod
    def busctl(name: str) -> tuple[str, ...]:
        path = "/org/freedesktop/systemd1/unit/web_2dnginx_2eservice"
        return ("busctl", "--json=short", "get-property", "org.freedesktop.systemd1", path,
                "org.freedesktop.systemd1.Service", name)  # fmt: skip

    def processes(self, *pids: int, ino: int, sha: str, deleted: bool, path: str = BINARY) -> None:
        self.cgroups["/sys/fs/cgroup" + GROUP] = list(pids)
        for pid in pids:
            self.links[f"/proc/{pid}/exe"] = path + (" (deleted)" if deleted else "")
            self.links[f"/proc/{pid}/ns/mnt"] = HOST_MNT
            self.links[f"/proc/{pid}/root"] = "/"
            self.stats[f"/proc/{pid}/exe"] = stat_result(ino=ino)
            self.digests[f"/proc/{pid}/exe"] = sha
            self.files[f"/proc/{pid}/cgroup"] = f"0::{GROUP}\n"
            self.files[f"/proc/{pid}/maps"] = ""
            self.files[f"/proc/{pid}/comm"] = "nginx\n"

    def restart(self, _argv: list[str]) -> tuple[int, str, str]:
        self.main_pid = 20
        self.props["MainPID"] = "20"
        self.processes(20, 21, ino=NEW_INO, sha=NEW_SHA, deleted=False)
        return 0, "", ""

    # -- Host -----------------------------------------------------------------------
    def run(self, argv: list[str], timeout: float = 60) -> tuple[int, str, str]:
        self.calls.append(list(argv))
        if argv[:2] == ["systemctl", "show"]:
            return 0, "".join(f"{key}={value}\n" for key, value in self.props.items()), ""
        response = self.responses.get(tuple(argv))
        if response is None:
            raise AssertionError(f"unexpected command {argv}")
        return response(self, argv) if callable(response) else response

    def read(self, path: str) -> str:
        if path not in self.files:
            raise FileNotFoundError(path)
        return self.files[path]

    def readlink(self, path: str) -> str:
        if path in self.denied:
            raise PermissionError(path)
        if path not in self.links:
            raise FileNotFoundError(path)
        return self.links[path]

    def stat(self, path: str) -> os.stat_result:
        if path in self.denied:
            raise PermissionError(path)
        if path not in self.stats:
            raise FileNotFoundError(path)
        return self.stats[path]

    def lstat(self, path: str) -> os.stat_result:
        return self.stat(path)

    def realpath(self, path: str) -> str:
        return path

    def cgroup_root(self) -> str:
        return "/sys/fs/cgroup"

    def pids(self) -> list[int]:
        return sorted({pid for group in self.cgroups.values() for pid in group} | set(self.all_pids))

    def cgroup_pids(self, cgroup_dir: str) -> list[int]:
        return list(self.cgroups.get(cgroup_dir, []))

    def sha256(self, path: str) -> str:
        return self.digests[path]

    def sleep(self, seconds: float) -> None:
        self.clock += seconds

    def monotonic(self) -> float:
        return self.clock

    def http_status(self, probe: dict[str, Any]) -> int:
        return self.http

    # -- helpers ----------------------------------------------------------------------
    def ran(self, *prefix: str) -> list[list[str]]:
        return [call for call in self.calls if call[: len(prefix)] == list(prefix)]


def restarts(fake: FakeHost) -> list[list[str]]:
    """Every restart command sent, whatever the verb."""

    return [call for call in fake.calls if call[:2] in (["systemctl", "restart"], ["systemctl", "try-restart"])]


def evaluate(fake: FakeHost, *, act: bool = True, attempts: dict[str, Any] | None = None, **entry: Any) -> Any:
    saved: dict[str, Any] = {}

    def save(unit: str, attempt: dict[str, Any]) -> None:
        saved[unit] = dict(attempt)

    row = host_script.evaluate_unit(fake, {**ENTRY, **entry}, attempts or {}, HOST_MNT, act, save)
    return row, saved


# -- configuration ----------------------------------------------------------------------


def config(*units: dict[str, Any]) -> str:
    return json.dumps({"schema": 1, "units": list(units)})


def test_parse_config_accepts_the_allowlist_and_probe() -> None:
    probe = {"url": "http://127.0.0.1:10044/health", "headers": {"Host": "a.example"}, "status": 200}
    entries = host_script.parse_config(config({**ENTRY, "http_probe": probe}))

    assert entries == [{**ENTRY, "http_probe": probe}]
    assert host_script.parse_config(config()) == []


@pytest.mark.parametrize(
    "change",
    [
        {"extra": 1},
        {"unit": "web-nginx"},
        {"unit": "web-nginx.timer"},
        {"binary": "/usr/sbin/../sbin/nginx"},
        {"binary": "usr/sbin/nginx"},
        {"package": "Nginx"},
        {"test": "apache"},
        {"test": ["nginx"]},
        {"expected_argv": " ".join(ARGV)},
        {"expected_argv": []},
        {"expected_argv": ["/usr/bin/nginx", "-c", "x"]},
        {"expected_argv": [BINARY, "a\nb"]},
        {"expected_argv": [BINARY, 1]},
        {"http_probe": {"url": "https://127.0.0.1:443/"}},
        {"http_probe": {"url": "http://10.0.0.1:80/"}},
        {"http_probe": {"url": "http://127.0.0.1/"}},
        {"http_probe": {"url": "http://127.0.0.1:x/"}},
        {"http_probe": {"url": "http://127.0.0.1:80/", "status": True}},
        {"http_probe": {"url": "http://127.0.0.1:80/", "headers": {"X Bad": "1"}}},
        {"http_probe": {"url": "http://127.0.0.1:80/", "headers": {"Host": "a\r\nb"}}},
        {"http_probe": {"url": "http://127.0.0.1:80/", "other": 1}},
    ],
)
def test_parse_config_refuses_anything_else(change: dict[str, Any]) -> None:
    with pytest.raises(host_script.ConfigError):
        host_script.parse_config(config({**ENTRY, **change}))


@pytest.mark.parametrize(
    "text",
    ["", "[]", json.dumps({"schema": 2, "units": []}), json.dumps({"schema": 1}), config(ENTRY, ENTRY)],
)
def test_parse_config_refuses_other_documents(text: str) -> None:
    with pytest.raises(host_script.ConfigError):
        host_script.parse_config(text)


# -- parsing helpers ---------------------------------------------------------------------


def test_classify() -> None:
    assert host_script.classify(True, (1, 2), (1, 2)) == "deleted"
    assert host_script.classify(False, (1, 2), (1, 3)) == "replaced"
    assert host_script.classify(False, (1, 2), None) == "replaced"
    assert host_script.classify(False, (1, 2), (1, 2)) == "current"


def test_deleted_libs_keeps_executable_system_mappings_only() -> None:
    maps = "\n".join(
        [
            "55d0-55e0 r-xp 00000000 09:02 50 /usr/sbin/nginx (deleted)",
            "7f00-7f10 r-xp 00000000 09:02 60 /usr/lib/x86_64-linux-gnu/libssl.so.3 (deleted)",
            "7f10-7f20 r--p 00000000 09:02 61 /usr/lib/x86_64-linux-gnu/libz.so.1 (deleted)",
            "7f20-7f30 r-xp 00000000 09:02 62 /usr/lib/x86_64-linux-gnu/libc.so.6",
            "7f30-7f40 r-xp 00000000 00:01 63 /memfd:jit (deleted)",
            "7f40-7f50 r-xp 00000000 09:02 64 /opt/tool/libx.so (deleted)",
            "7f50-7f60 rw-p 00000000 00:00 0",
        ]
    )

    assert host_script.deleted_libs(maps, BINARY) == {
        "/usr/lib/x86_64-linux-gnu/libssl.so.3",
        "/opt/tool/libx.so",
    }


@pytest.mark.parametrize(
    ("text", "unit"),
    [
        ("0::/system.slice/web-nginx.service\n", "web-nginx.service"),
        ("0::/system.slice/docker-abc.scope\n", "docker-abc.scope"),
        ("0::/system.slice/svc.service/payload\n", "svc.service"),
        ("0::/user.slice/user-1000.slice/session-3.scope\n", "session-3.scope"),
        ("12:pids:/x\n1:name=systemd:/system.slice/cron.service\n", "cron.service"),
        ("0::/init.scope\n", "init.scope"),
        ("0::/\n", "/"),
    ],
)
def test_unit_of_cgroup(text: str, unit: str) -> None:
    assert host_script.unit_of_cgroup(text) == unit


@pytest.mark.parametrize(
    ("unit", "path"),
    [
        ("web-nginx.service", "web_2dnginx_2eservice"),
        ("1x.service", "_31x_2eservice"),
        ("a_b@c.service", "a_5fb_40c_2eservice"),
    ],
)
def test_bus_path_encodes_like_sd_bus(unit: str, path: str) -> None:
    assert host_script.bus_path(unit) == "/org/freedesktop/systemd1/unit/" + path


def test_parse_exec_json_keeps_argument_boundaries() -> None:
    assert host_script.parse_exec_json(exec_json(ARGV), "ExecStart") == [(BINARY, ARGV)]
    with pytest.raises(host_script.Refused):
        host_script.parse_exec_json(json.dumps({"type": "a(sasasttttuii)", "data": []}), "ExecStartEx")
    with pytest.raises(host_script.Refused):
        host_script.parse_exec_json("not json", "ExecStart")


def test_lock_holders_reads_hex_device_numbers() -> None:
    fake = FakeHost()
    fake.stats["/var/lib/dpkg/lock-frontend"] = stat_result(dev=os.makedev(9, 2), ino=3145875)
    fake.stats["/var/lib/dpkg/lock"] = stat_result(dev=os.makedev(9, 2), ino=3145877)
    fake.files["/proc/locks"] = (
        "1: FLOCK  ADVISORY  WRITE 738 00:19:1861 0 EOF\n2: POSIX  ADVISORY  WRITE 4242 09:02:3145875 0 EOF\n"
    )

    assert host_script.lock_holders(fake, host_script.DPKG_LOCKS) == ["/var/lib/dpkg/lock-frontend"]
    fake.files["/proc/locks"] = "1: POSIX  ADVISORY  WRITE 4242 09:20:3145875 0 EOF\n"
    assert host_script.lock_holders(fake, host_script.DPKG_LOCKS) == []


def test_transitional_packages_and_dpkg_busy() -> None:
    fake = FakeHost()
    status = ("dpkg-query", "-W", "-f", "${db:Status-Abbrev} ${binary:Package}\n")
    fake.responses[status] = (0, "ii  nginx\niU  half\niF  conf\niiR broken\nrc  gone\nun  never\n", "")

    assert host_script.transitional_packages(fake) == ["half (iU)", "conf (iF)", "broken (iiR)"]
    assert host_script.dpkg_busy(fake) == "3 package(s) in transition: half (iU), conf (iF), broken (iiR)"

    fake.all_pids = [99]
    fake.files["/proc/99/comm"] = "apt-get\n"
    assert host_script.dpkg_busy(fake) == "apt/dpkg running (PID 99)"


def test_wait_dpkg_idle_waits_then_gives_up() -> None:
    fake = FakeHost()
    fake.all_pids = [99]
    fake.files["/proc/99/comm"] = "dpkg\n"

    reason, waited = host_script.wait_dpkg_idle(fake, limit=60, poll=10)
    assert reason == "apt/dpkg running (PID 99)"
    assert waited >= 60

    calls: list[int] = []

    def finish(seconds: float) -> None:
        calls.append(1)
        fake.clock += seconds
        if len(calls) == 2:
            del fake.files["/proc/99/comm"]

    fake.sleep = finish  # type: ignore[method-assign]
    fake.clock = 0
    assert host_script.wait_dpkg_idle(fake, limit=60, poll=10) == (None, 20)


# -- the decision table ------------------------------------------------------------------


def test_current_unit_is_left_alone() -> None:
    fake = FakeHost(stale=False)

    row, saved = evaluate(fake)

    assert row["status"] == "current"
    assert row["ready"] is True
    assert row["pids"] == 2
    assert row["running"] == [f"{DEV}:{NEW_INO}"]
    assert row["disk"] == f"{DEV}:{NEW_INO}"
    assert not fake.ran("runuser")
    assert not restarts(fake)
    # Readiness reads dpkg and D-Bus, read-only.
    assert fake.ran("dpkg", "--verify", "nginx")
    assert saved == {}


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        (
            lambda f: f.responses.update(
                {FakeHost.busctl("ExecStart"): (0, exec_json([BINARY, "-c", "/etc/other.conf"]), "")}
            ),
            "not the approved argv",
        ),
        (
            lambda f: f.responses.update({("dpkg-query", "-S", BINARY): (0, f"nginx-extras: {BINARY}\n", "")}),
            "not nginx",
        ),
        (lambda f: f.props.update({"NeedDaemonReload": "yes"}), "NeedDaemonReload"),
    ],
    ids=["argv", "owner", "pending-edit"],
)
def test_a_current_unit_the_allowlist_does_not_fit_needs_attention(
    change: Callable[[FakeHost], object], reason: str
) -> None:
    fake = FakeHost(stale=False)
    change(fake)

    row, _ = evaluate(fake)

    assert row["status"] == "current"
    assert row["ready"] is False
    assert reason in row["reason"]
    assert row["reason"].startswith("a restart would be refused: ")
    result = host_script.evaluate(fake, [ENTRY], {}, act=True, state_path=None)
    assert result["attention"] == [UNIT]
    assert not restarts(fake)


def test_an_inactive_unit_is_checked_for_readiness_too() -> None:
    fake = FakeHost()
    fake.props.update({"ActiveState": "inactive", "MainPID": "0"})

    row, _ = evaluate(fake)

    assert (row["status"], row["ready"]) == ("inactive", True)


def test_stale_unit_is_tested_restarted_once_and_checked() -> None:
    fake = FakeHost()

    row, saved = evaluate(fake)

    assert row["status"] == "restarted", row
    assert row["stale_kinds"] == ["deleted"]
    assert row["reason"] == "main PID 10 -> 20, image current"
    assert restarts(fake) == [["systemctl", "try-restart", "--", UNIT]]
    # Both tests ran as the unit's user before the restart.
    tests = fake.ran("runuser")
    assert tests == [
        ["runuser", "-u", "www", "-g", "www", "--", BINARY, "-t", *ARGV[1:]],
        ["runuser", "-u", "www", "-g", "www", "--", *PRE],
    ]
    assert fake.calls.index(tests[-1]) < fake.calls.index(["systemctl", "try-restart", "--", UNIT])
    assert saved[UNIT]["binary_key"] == f"{DEV}:{NEW_INO}:{NEW_SHA}"
    assert saved[UNIT]["result"] == "restarted"
    assert saved[UNIT]["old_main_pid"] == "10"


def test_the_attempt_is_persisted_before_the_restart() -> None:
    fake = FakeHost()
    saved: dict[str, Any] = {}
    at_restart: dict[str, Any] = {}

    def save(unit: str, attempt: dict[str, Any]) -> None:
        saved[unit] = dict(attempt)

    def restart(host: FakeHost, argv: list[str]) -> tuple[int, str, str]:
        at_restart.update(saved)
        return FakeHost.restart(host, argv)

    fake.responses[("systemctl", "try-restart", "--", UNIT)] = restart

    host_script.evaluate_unit(fake, ENTRY, {}, HOST_MNT, True, save)

    assert at_restart[UNIT]["result"] == "started"
    assert at_restart[UNIT]["binary_key"] == f"{DEV}:{NEW_INO}:{NEW_SHA}"
    assert saved[UNIT]["result"] == "restarted"


def test_replaced_image_counts_as_stale() -> None:
    fake = FakeHost(stale=False)
    fake.processes(10, 11, ino=OLD_INO, sha=OLD_SHA, deleted=False)

    row, _ = evaluate(fake, act=False)

    assert row["status"] == "stale"
    assert row["stale_kinds"] == ["replaced"]
    assert row["action"] == "test_and_restart"


def test_report_mode_never_tests_or_restarts() -> None:
    fake = FakeHost()

    row, saved = evaluate(fake, act=False)

    assert (row["status"], row["action"]) == ("stale", "test_and_restart")
    assert not fake.ran("runuser")
    assert not restarts(fake)
    assert saved == {}


def test_failed_test_blocks_the_restart() -> None:
    fake = FakeHost()
    fake.responses[("runuser", "-u", "www", "-g", "www", "--", *PRE)] = (
        1,
        "",
        'nginx: [emerg] unknown directive "x" in /etc/web/nginx.conf:3\n',
    )

    row, saved = evaluate(fake)

    assert row["status"] == "test_failed"
    assert not restarts(fake)
    assert saved == {}


def test_a_test_without_the_success_line_fails() -> None:
    fake = FakeHost()
    fake.responses[("runuser", "-u", "www", "-g", "www", "--", BINARY, "-t", *ARGV[1:])] = (0, "", "")

    row, _ = evaluate(fake)

    assert row["status"] == "test_failed"
    assert not restarts(fake)


def test_root_unit_is_tested_without_runuser() -> None:
    fake = FakeHost()
    fake.props["User"] = ""
    fake.props["Group"] = ""
    fake.responses[(BINARY, "-t", *ARGV[1:])] = OK_TEST
    fake.responses[tuple(PRE)] = OK_TEST

    row, _ = evaluate(fake)

    assert row["status"] == "restarted"
    assert not fake.ran("runuser")


def test_same_binary_is_never_restarted_twice() -> None:
    fake = FakeHost()
    attempts = {UNIT: {"binary_key": f"{DEV}:{NEW_INO}:{NEW_SHA}", "at": "2026-10-24T07:00:00Z"}}

    row, saved = evaluate(fake, attempts=attempts)

    assert row["status"] == "stale_no_retry"
    assert not fake.ran("runuser")
    assert not restarts(fake)
    assert saved == {}


def test_a_newer_binary_gets_its_own_restart() -> None:
    fake = FakeHost()
    attempts = {UNIT: {"binary_key": f"{DEV}:{OLD_INO}:{OLD_SHA}", "at": "2026-10-20T07:00:00Z"}}

    row, _ = evaluate(fake, attempts=attempts)

    assert row["status"] == "restarted"


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        (lambda f: f.responses.update({("dpkg-query", "-S", BINARY): (1, "", "not found")}), "belongs to no package"),
        (
            lambda f: f.responses.update({("dpkg-query", "-S", BINARY): (0, f"nginx-extras: {BINARY}\n", "")}),
            "belongs to nginx-extras, not nginx",
        ),
        (
            lambda f: f.responses.update(
                {("dpkg-query", "-S", BINARY): (0, f"diversion by local from: {BINARY}\nnginx: {BINARY}\n", "")}
            ),
            "not a plain package entry",
        ),
        (
            lambda f: f.responses.update({("dpkg-query", "-W", "-f", "${db:Status-Abbrev}", "nginx"): (0, "iU ", "")}),
            "not installed cleanly",
        ),
        (
            lambda f: f.responses.update({("dpkg", "--verify", "nginx"): (1, f"??5??????   {BINARY}\n", "")}),
            "reports /usr/sbin/nginx as changed",
        ),
        (
            lambda f: f.responses.update({("dpkg", "--verify", "nginx"): (1, "", "")}),
            "failed without naming a file",
        ),
        (lambda f: f.stats.update({BINARY: stat_result(ino=NEW_INO, mode=stat.S_IFREG | 0o775)}), "writable only"),
        (lambda f: f.stats.update({BINARY: stat_result(ino=NEW_INO, uid=1000)}), "root-owned"),
        (lambda f: f.props.update({"NeedDaemonReload": "yes"}), "NeedDaemonReload"),
        (
            lambda f: f.responses.update(
                {FakeHost.busctl("ExecStart"): (0, exec_json([*ARGV[:4], "daemon off; "]), "")}
            ),
            "not the approved argv",
        ),
        (
            lambda f: f.responses.update({FakeHost.busctl("ExecStart"): (0, exec_json(ARGV, ARGV), "")}),
            "not the approved argv",
        ),
        (
            lambda f: f.responses.update(
                {FakeHost.busctl("ExecStartPre"): (0, exec_json(["/bin/mkdir", "-p", "/x"]), "")}
            ),
            "is not a -t run",
        ),
        (
            lambda f: f.responses.update({FakeHost.busctl("ExecStartPre"): (0, exec_json([BINARY, "-s", "stop"]), "")}),
            "is not a -t run",
        ),
        (
            lambda f: f.responses.update({FakeHost.busctl("ExecStartPost"): (0, exec_json(["/bin/true"]), "")}),
            "ExecStartPost",
        ),
        (lambda f: f.responses.update({FakeHost.busctl("ExecStart"): (1, "", "Unknown object")}), "over D-Bus"),
    ],
    ids=[
        "no-owner",
        "other-owner",
        "diversion",
        "half-installed",
        "binary-modified",
        "verify-error",
        "group-writable",
        "not-root",
        "daemon-reload-pending",
        "argv-differs",
        "two-execstarts",
        "pre-not-a-test",
        "pre-other-verb",
        "start-post",
        "dbus-error",
    ],
)
def test_refusals_never_test_or_restart(change: Callable[[FakeHost], object], reason: str) -> None:
    fake = FakeHost()
    change(fake)

    row, saved = evaluate(fake)

    assert row["status"] == "refused", row
    assert reason in row["reason"]
    assert not fake.ran("runuser")
    assert not restarts(fake)
    assert saved == {}


def test_a_process_in_another_namespace_is_refused() -> None:
    fake = FakeHost()
    fake.links["/proc/11/ns/mnt"] = "mnt:[4026532000]"

    row, _ = evaluate(fake)

    assert row["status"] == "refused"
    assert "another mount namespace" in row["reason"]
    assert not restarts(fake)


def test_a_process_with_another_root_is_refused() -> None:
    fake = FakeHost()
    fake.links["/proc/10/root"] = "/srv/chroot"

    row, _ = evaluate(fake)

    assert row["status"] == "refused"


def test_a_process_running_another_binary_is_refused() -> None:
    fake = FakeHost()
    fake.links["/proc/11/exe"] = "/usr/bin/python3"

    row, _ = evaluate(fake)

    assert row["status"] == "refused"
    assert "runs /usr/bin/python3" in row["reason"]


@pytest.mark.parametrize("path", ["/proc/11/exe", "/proc/11/ns/mnt"])
def test_a_process_that_cannot_be_inspected_is_refused_not_skipped(path: str) -> None:
    fake = FakeHost()
    fake.denied.add(path)

    row, _ = evaluate(fake)

    assert row["status"] == "refused"
    assert row["reason"] == "cannot inspect PID 11: PermissionError"
    assert not restarts(fake)


def test_main_pid_must_be_among_the_inspected_processes() -> None:
    fake = FakeHost()
    fake.props["MainPID"] = "12"

    row, _ = evaluate(fake)

    assert row["status"] == "refused"
    assert row["reason"] == "the main PID 12 is not among the unit's inspected processes"


def test_processes_that_exit_meanwhile_are_skipped() -> None:
    fake = FakeHost()
    fake.cgroups["/sys/fs/cgroup" + GROUP] = [10, 11, 12]  # 12 is gone: no /proc entries

    row, _ = evaluate(fake, act=False)

    assert (row["status"], row["pids"]) == ("stale", 2)


def test_symlinked_binary_path_is_refused() -> None:
    fake = FakeHost()
    fake.realpath = lambda path: "/usr/sbin/nginx-real"  # type: ignore[method-assign]

    row, _ = evaluate(fake)

    assert row["status"] == "refused"


@pytest.mark.parametrize(
    ("props", "status"),
    [
        ({"LoadState": "not-found"}, "not_loaded"),
        ({"ActiveState": "inactive", "MainPID": "0"}, "inactive"),
        ({"ActiveState": "failed"}, "inactive"),
    ],
)
def test_units_that_do_not_run_are_left_alone(props: dict[str, str], status: str) -> None:
    fake = FakeHost()
    fake.props.update(props)

    row, _ = evaluate(fake)

    assert row["status"] == status
    assert not restarts(fake)


def test_no_restart_when_dpkg_starts_right_before_it() -> None:
    fake = FakeHost()
    original = fake.responses[("runuser", "-u", "www", "-g", "www", "--", *PRE)]

    def test_then_apt(host: FakeHost, argv: list[str]) -> tuple[int, str, str]:
        host.all_pids = [99]
        host.files["/proc/99/comm"] = "apt\n"
        assert not callable(original)
        return original

    fake.responses[("runuser", "-u", "www", "-g", "www", "--", *PRE)] = test_then_apt

    row, saved = evaluate(fake)

    assert row["status"] == "deferred"
    assert not restarts(fake)
    assert saved == {}


def test_failed_restart_is_recorded_and_not_retried() -> None:
    fake = FakeHost()
    fake.responses[("systemctl", "try-restart", "--", UNIT)] = (1, "", "Job failed")

    row, saved = evaluate(fake)

    assert row["status"] == "restart_failed"
    assert "Job failed" in row["reason"]
    assert saved[UNIT]["result"] == "restart_failed"

    again, _ = evaluate(fake, attempts=saved)
    assert again["status"] == "stale_no_retry"


def test_post_check_waits_and_reports_an_unchanged_main_pid() -> None:
    fake = FakeHost()
    fake.responses[("systemctl", "try-restart", "--", UNIT)] = (0, "", "")

    row, saved = evaluate(fake)

    assert row["status"] == "post_failed"
    assert row["reason"] == "status stale"
    assert fake.clock >= host_script.POST_WAIT_S
    assert saved[UNIT]["result"] == "post_failed"


def test_post_check_compares_the_running_image_with_the_file() -> None:
    fake = FakeHost()

    def restart_wrong_image(host: FakeHost, argv: list[str]) -> tuple[int, str, str]:
        FakeHost.restart(host, argv)
        host.digests["/proc/20/exe"] = OLD_SHA
        return 0, "", ""

    fake.responses[("systemctl", "try-restart", "--", UNIT)] = restart_wrong_image

    row, _ = evaluate(fake)

    assert row["status"] == "post_failed"
    assert "image differs" in row["reason"]


def test_http_probe_must_answer_its_status() -> None:
    probe = {"url": "http://127.0.0.1:10044/health", "headers": {"Host": "a.example"}, "status": 200}
    fake = FakeHost()
    fake.http = 502

    row, _ = evaluate(fake, http_probe=probe)
    assert row["status"] == "post_failed"
    assert row["reason"] == "HTTP probe answered 502, expected 200"

    fine = FakeHost()
    row, _ = evaluate(fine, http_probe=probe)
    assert row["status"] == "restarted"


# -- the whole run --------------------------------------------------------------------------


def report_host() -> FakeHost:
    fake = FakeHost(stale=False)
    # A unit with a deleted library, one with a replaced executable, one in a container.
    fake.all_pids = [30, 40, 50]
    for pid, group, exe in ((30, "ssh.service", "/usr/sbin/sshd"), (40, "tool.service", "/usr/local/bin/tool")):
        fake.links[f"/proc/{pid}/exe"] = exe
        fake.links[f"/proc/{pid}/ns/mnt"] = HOST_MNT
        fake.links[f"/proc/{pid}/root"] = "/"
        fake.stats[f"/proc/{pid}/exe"] = stat_result(ino=pid)
        fake.files[f"/proc/{pid}/cgroup"] = f"0::/system.slice/{group}\n"
        fake.files[f"/proc/{pid}/comm"] = "x\n"
    fake.stats["/usr/sbin/sshd"] = stat_result(ino=30)
    fake.files["/proc/30/maps"] = "7f00-7f10 r-xp 0 09:02 1 /usr/lib/x86_64-linux-gnu/libcrypto.so.3 (deleted)\n"
    fake.stats["/usr/local/bin/tool"] = stat_result(ino=41)
    fake.files["/proc/40/maps"] = ""
    fake.links["/proc/50/exe"] = "/bin/busybox"
    fake.links["/proc/50/ns/mnt"] = "mnt:[4026532999]"
    fake.links["/proc/50/root"] = "/"
    fake.stats["/proc/50/exe"] = stat_result(ino=7)
    fake.files["/proc/50/cgroup"] = "0::/system.slice/docker-abc.scope\n"
    fake.files["/proc/50/comm"] = "busybox\n"
    return fake


def test_report_lists_other_units_but_never_acts_on_them() -> None:
    fake = report_host()

    rows, foreign, unreadable = host_script.report_only(fake, {UNIT}, HOST_MNT)

    assert rows == [
        {
            "unit": "ssh.service",
            "pids": 1,
            "foreign_namespace_pids": 0,
            "stale_exe": [],
            "deleted_libs": ["libcrypto.so.3"],
            "deleted_libs_total": 1,
        },
        {"unit": "tool.service", "pids": 1, "foreign_namespace_pids": 0, "stale_exe": ["/usr/local/bin/tool"],
         "deleted_libs": [], "deleted_libs_total": 0},
    ]  # fmt: skip
    # The container's busybox has another inode than the host's path: not compared, not reported.
    assert foreign == 1
    assert unreadable == 0

    fake.denied.add("/proc/40/exe")
    rows, foreign, unreadable = host_script.report_only(fake, {UNIT}, HOST_MNT)
    assert [row["unit"] for row in rows] == ["ssh.service"]
    assert unreadable == 1


def test_processes_in_other_namespaces_report_only_kernel_deleted_marks() -> None:
    fake = report_host()
    # A sandboxed unit (own mount namespace) runs a deleted image and maps a deleted library.
    fake.all_pids.append(60)
    fake.links["/proc/60/exe"] = "/usr/lib/systemd/systemd-logind (deleted)"
    fake.links["/proc/60/ns/mnt"] = "mnt:[4026532111]"
    fake.links["/proc/60/root"] = "/"
    fake.stats["/proc/60/exe"] = stat_result(ino=600)
    fake.files["/proc/60/cgroup"] = "0::/system.slice/systemd-logind.service\n"
    fake.files["/proc/60/maps"] = "7f00-7f10 r-xp 0 09:02 1 /usr/lib/x86_64-linux-gnu/libsystemd.so.0 (deleted)\n"
    fake.files["/proc/60/comm"] = "systemd-logind\n"

    rows, foreign, _ = host_script.report_only(fake, {UNIT}, HOST_MNT)

    logind = [row for row in rows if row["unit"] == "systemd-logind.service"]
    assert logind == [
        {
            "unit": "systemd-logind.service",
            "pids": 1,
            "foreign_namespace_pids": 1,
            "stale_exe": ["/usr/lib/systemd/systemd-logind"],
            "deleted_libs": ["libsystemd.so.0"],
            "deleted_libs_total": 1,
        }
    ]
    assert foreign == 2
    assert "docker-abc.scope" not in {row["unit"] for row in rows}


def test_evaluate_reports_and_flags_attention() -> None:
    fake = report_host()

    result = host_script.evaluate(fake, [ENTRY], {}, act=True, state_path=None)

    assert result["result"] == "ok"
    assert [row["status"] for row in result["units"]] == ["current"]
    assert [row["unit"] for row in result["report_only"]] == ["ssh.service", "tool.service"]
    assert not restarts(fake)

    fake.props["NeedDaemonReload"] = "yes"
    fake.processes(10, 11, ino=OLD_INO, sha=OLD_SHA, deleted=True)
    flagged = host_script.evaluate(fake, [ENTRY], {}, act=True, state_path=None)
    assert flagged["result"] == "attention"
    assert flagged["attention"] == [UNIT]


def test_run_writes_state_and_exit_codes(tmp_path: Path) -> None:
    state = tmp_path / "state.json"
    good = tmp_path / "config.json"
    good.write_text(config(ENTRY))

    class LocalHost(FakeHost):
        def read(self, path: str) -> str:
            if path.startswith(str(tmp_path)):
                return Path(path).read_text()
            return super().read(path)

    fake = LocalHost()
    assert host_script.run(fake, str(good), str(state)) == 0
    written = json.loads(state.read_text())
    assert written["result"] == "ok"
    assert written["units"][0]["status"] == "restarted"
    assert written["attempts"][UNIT]["result"] == "restarted"
    assert stat.S_IMODE(state.stat().st_mode) == 0o644

    # The same binary stale again (the restart did not stick): attention, no second restart.
    fake.processes(20, 21, ino=OLD_INO, sha=OLD_SHA, deleted=True)
    count = len(restarts(fake))
    assert host_script.run(fake, str(good), str(state)) == 1
    assert len(restarts(fake)) == count
    assert json.loads(state.read_text())["units"][0]["status"] == "stale_no_retry"

    bad = tmp_path / "bad.json"
    bad.write_text("{}")
    assert host_script.run(fake, str(bad), str(state)) == 2
    assert json.loads(state.read_text())["result"] == "config_error"


def test_run_defers_while_dpkg_stays_busy(tmp_path: Path) -> None:
    state = tmp_path / "state.json"
    path = tmp_path / "config.json"
    path.write_text(config(ENTRY))

    class BusyHost(FakeHost):
        def read(self, name: str) -> str:
            if name.startswith(str(tmp_path)):
                return Path(name).read_text()
            return super().read(name)

    fake = BusyHost()
    fake.all_pids = [99]
    fake.files["/proc/99/comm"] = "unattended-upgr\n"

    assert host_script.run(fake, str(path), str(state)) == 0
    written = json.loads(state.read_text())
    assert written["result"] == "deferred"
    assert written["reason"] == "apt/dpkg running (PID 99)"
    assert fake.clock >= host_script.DPKG_WAIT_S
    assert not restarts(fake)


def test_summary_lines() -> None:
    result = host_script.evaluate(report_host(), [ENTRY], {}, act=False, state_path=None)

    assert host_script.summary_lines(result) == [
        f"{UNIT}: current",
        "report only: 1 unit(s) with a replaced executable (tool.service), 1 with deleted libraries;"
        " 1 process(es) in other mount namespaces (path comparison skipped), 0 not readable",
    ]


# -- round-1 review repairs: the final gate, state, traversal, process names, properties -----


def during_the_test(fake: FakeHost, change: Callable[[FakeHost], None]) -> None:
    """Run ``change`` while the last configuration test runs (after the first checks passed)."""

    key = ("runuser", "-u", "www", "-g", "www", "--", *PRE)

    def test_then_change(host: FakeHost, argv: list[str]) -> tuple[int, str, str]:
        change(host)
        return OK_TEST

    fake.responses[key] = test_then_change


def stop(host: FakeHost) -> None:
    host.props.update({"ActiveState": "inactive", "MainPID": "0"})


def restarted_by_someone_else(host: FakeHost) -> None:
    host.props["MainPID"] = "30"
    host.processes(30, 31, ino=OLD_INO, sha=OLD_SHA, deleted=True)


def upgraded_again(host: FakeHost) -> None:
    host.stats[BINARY] = stat_result(ino=NEW_INO + 1)
    host.digests[BINARY] = "c" * 64


def pre_changed(host: FakeHost) -> None:
    other = [BINARY, "-t", "-q", "-c", "/etc/web/nginx.conf"]
    host.responses[FakeHost.busctl("ExecStartPre")] = (0, exec_json(other), "")


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        (stop, "the unit is inactive now"),
        (restarted_by_someone_else, "the main PID changed during the test"),
        (upgraded_again, "the binary changed during the test"),
        (pre_changed, "the unit's ExecStartPre changed during the test"),
        (
            lambda host: host.files.update({"/proc/99/comm": "apt-get\n"}) or host.all_pids.append(99),
            "dpkg became busy",
        ),
    ],
    ids=["stopped", "restarted-elsewhere", "binary-replaced", "pre-changed", "apt-started"],
)
def test_the_final_gate_defers_when_anything_changed_during_the_test(
    change: Callable[[FakeHost], None], reason: str
) -> None:
    fake = FakeHost()
    during_the_test(fake, change)

    row, saved = evaluate(fake)

    assert row["status"] == "deferred", row
    assert reason in row["reason"]
    assert restarts(fake) == []
    assert saved == {}


def test_the_final_gate_refuses_a_unit_redefined_during_the_test() -> None:
    fake = FakeHost()
    during_the_test(fake, lambda host: host.props.update({"NeedDaemonReload": "yes"}))

    row, saved = evaluate(fake)

    assert row["status"] == "refused"
    assert "NeedDaemonReload" in row["reason"]
    assert restarts(fake) == []
    assert saved == {}


def test_the_final_gate_rechecks_the_package() -> None:
    fake = FakeHost()
    during_the_test(
        fake,
        lambda host: host.responses.update({("dpkg", "--verify", "nginx"): (0, f"??5??????   {BINARY}\n", "")}),
    )

    row, _ = evaluate(fake)

    assert row["status"] == "refused"
    assert restarts(fake) == []


def test_the_restart_cannot_start_a_stopped_unit() -> None:
    fake = FakeHost()

    evaluate(fake)

    assert restarts(fake) == [["systemctl", "try-restart", "--", UNIT]]


@pytest.mark.parametrize(
    "content",
    ['{"attempts": {"web-nginx.service": {"binary_key"', "[]", '{"attempts": []}', '{"attempts": {"u": 1}}'],
    ids=["truncated", "list", "attempts-list", "attempt-not-object"],
)
def test_a_damaged_state_blocks_every_action(tmp_path: Path, content: str) -> None:
    state = tmp_path / "state.json"
    state.write_text(content)
    config_path = tmp_path / "config.json"
    config_path.write_text(config(ENTRY))

    class LocalHost(FakeHost):
        def read(self, path: str) -> str:
            if path.startswith(str(tmp_path)):
                return Path(path).read_text()
            return super().read(path)

    fake = LocalHost()
    assert host_script.run(fake, str(config_path), str(state)) == 2
    assert restarts(fake) == []
    assert not fake.ran("runuser")
    assert state.read_text() == content  # left for inspection

    with pytest.raises(host_script.StateError):
        host_script.read_state(fake, str(state))


def test_an_unreadable_state_blocks_every_action(tmp_path: Path) -> None:
    class DeniedHost(FakeHost):
        def read(self, path: str) -> str:
            if path == "/state.json":
                raise PermissionError(path)
            if path.startswith(str(tmp_path)):
                return Path(path).read_text()
            return super().read(path)

    config_path = tmp_path / "config.json"
    config_path.write_text(config(ENTRY))
    fake = DeniedHost()

    assert host_script.run(fake, str(config_path), "/state.json") == 2
    assert restarts(fake) == []


def test_a_missing_state_means_no_attempts_yet() -> None:
    assert host_script.read_state(FakeHost(), "/no/such/state.json") == {}


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads unreadable directories")
def test_cgroup_traversal_errors_propagate(tmp_path: Path) -> None:
    unit = tmp_path / "web-nginx.service"
    child = unit / "payload"
    child.mkdir(parents=True)
    (unit / "cgroup.procs").write_text("10\n11\n")
    (child / "cgroup.procs").write_text("12\n")
    host = host_script.Host()

    assert host.cgroup_pids(str(unit)) == [10, 11, 12]
    assert host.cgroup_pids(str(tmp_path / "gone")) == []

    child.chmod(0)
    try:
        with pytest.raises(PermissionError):
            host.cgroup_pids(str(unit))
    finally:
        child.chmod(0o755)


def test_a_cgroup_that_cannot_be_listed_refuses() -> None:
    fake = FakeHost()

    def denied(cgroup_dir: str) -> list[int]:
        raise PermissionError(cgroup_dir)

    fake.cgroup_pids = denied  # type: ignore[method-assign]

    row, _ = evaluate(fake)

    assert row["status"] == "refused"
    assert row["reason"] == "cannot list the unit's processes: PermissionError"


def test_a_process_name_that_cannot_be_read_counts_as_busy() -> None:
    fake = FakeHost(stale=False)

    class DeniedComm(FakeHost):
        def read(self, path: str) -> str:
            if path == "/proc/11/comm":
                raise PermissionError(path)
            return super().read(path)

    denied = DeniedComm(stale=False)
    assert host_script.dpkg_busy(fake) is None
    assert host_script.dpkg_busy(denied) == "apt/dpkg running (PID 11 (unreadable))"


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        (lambda props: props.pop("MainPID"), "did not return MainPID"),
        (lambda props: props.pop("ActiveState"), "did not return ActiveState"),
        (lambda props: props.pop("User"), "did not return User"),
        (lambda props: props.update({"ActiveState": "weird"}), "unknown ActiveState"),
        (lambda props: props.update({"MainPID": "x"}), "unexpected MainPID"),
        (lambda props: props.update({"MainPID": "0"}), "active without a main PID"),
    ],
    ids=["no-mainpid", "no-activestate", "no-user", "unknown-state", "bad-mainpid", "active-no-main"],
)
def test_incomplete_unit_properties_refuse(change: Callable[[dict[str, str]], object], reason: str) -> None:
    fake = FakeHost()
    change(fake.props)

    row, _ = evaluate(fake)

    assert row["status"] == "refused", row
    assert reason in row["reason"]
    assert restarts(fake) == []


@pytest.mark.parametrize("state", ["activating", "deactivating", "reloading"])
def test_a_unit_in_transition_is_left_for_the_next_run(state: str) -> None:
    fake = FakeHost()
    fake.props["ActiveState"] = state

    row, _ = evaluate(fake)

    assert row["status"] == "changing"
    assert row["reason"] == f"the unit is {state}"
    assert restarts(fake) == []
    result = host_script.evaluate(fake, [ENTRY], {}, act=True, state_path=None)
    assert result["attention"] == []


# -- round-2 review repairs: the whole loaded definition, well-formed attempts -----------------


def user_changed(host: FakeHost) -> None:
    host.props["User"] = "nobody"


def group_changed(host: FakeHost) -> None:
    host.props["Group"] = "nogroup"


def unit_file_edited(host: FakeHost) -> None:
    # Edited and reloaded: NeedDaemonReload stays "no", the content differs.
    host.digests[FRAGMENT] = "e" * 64


def drop_in_added(host: FakeHost) -> None:
    host.props["DropInPaths"] = "/etc/systemd/system/web-nginx.service.d/override.conf"
    host.digests["/etc/systemd/system/web-nginx.service.d/override.conf"] = "d" * 64


@pytest.mark.parametrize(
    "change",
    [user_changed, group_changed, unit_file_edited, drop_in_added],
    ids=["user", "group", "unit-file", "drop-in"],
)
def test_a_definition_changed_during_the_test_defers(change: Callable[[FakeHost], None]) -> None:
    fake = FakeHost()
    during_the_test(fake, change)

    row, saved = evaluate(fake)

    assert row["status"] == "deferred", row
    assert row["reason"] == "the unit's definition (user, group, unit file or drop-ins) changed during the test"
    assert restarts(fake) == []
    assert saved == {}


def test_unit_files_must_be_absolute_paths() -> None:
    fake = FakeHost()
    fake.props["DropInPaths"] = "override.conf"

    row, _ = evaluate(fake)

    assert row["status"] == "refused"
    assert row["reason"] == "unexpected FragmentPath or DropInPaths"


@pytest.mark.parametrize(
    "attempt",
    [
        {},
        {"binary_key": None, "at": "2026-10-24T07:00:00Z", "result": "restarted"},
        {"binary_key": "", "at": "2026-10-24T07:00:00Z", "result": "restarted"},
        {"binary_key": "2306:1:abc", "at": "2026-10-24T07:00:00Z", "result": "restarted"},
        {"binary_key": f"{DEV}:{NEW_INO}:{NEW_SHA}", "result": "restarted"},
        {"binary_key": f"{DEV}:{NEW_INO}:{NEW_SHA}", "at": "2026-10-24T07:00:00Z"},
    ],
    ids=["empty", "null-key", "empty-key", "short-key", "no-time", "no-result"],
)
def test_a_malformed_attempt_blocks_every_action(tmp_path: Path, attempt: dict[str, Any]) -> None:
    state = tmp_path / "state.json"
    content = json.dumps({"attempts": {UNIT: attempt}})
    state.write_text(content)
    config_path = tmp_path / "config.json"
    config_path.write_text(config(ENTRY))

    class LocalHost(FakeHost):
        def read(self, path: str) -> str:
            if path.startswith(str(tmp_path)):
                return Path(path).read_text()
            return super().read(path)

    fake = LocalHost()
    assert host_script.run(fake, str(config_path), str(state)) == 2
    assert restarts(fake) == []
    assert state.read_text() == content


def test_a_well_formed_attempt_is_read() -> None:
    fake = FakeHost()
    good = {"binary_key": f"{DEV}:{NEW_INO}:{NEW_SHA}", "at": "2026-10-24T07:00:00Z", "result": "restarted"}
    fake.files["/state.json"] = json.dumps({"attempts": {UNIT: good}})

    assert host_script.read_state(fake, "/state.json")["attempts"] == {UNIT: good}
