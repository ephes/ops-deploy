"""The Traefik route guard: route writers refuse while a Traefik transaction holds its host lock.

The guard script runs for real under bash against a fake ``/proc/locks`` table, with a
``stat`` stand-in on ``PATH`` that reports the lock file's device and inode (so the test
runs on any system and pins the kernel's device notation).
"""

from __future__ import annotations

import re
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
from pyinfra.api import deploy

from ops_deploy.helpers import TraefikRoute, traefik_route
from ops_deploy.helpers.traefik import (
    ROUTE_GUARD_SCRIPT,
    TRANSACTION_LOCK,
    guarded,
    render_route,
    route_guard_command,
)
from ops_deploy.infra.traefik_tx import engine
from ops_deploy.services._lifecycle import remove_path
from ops_deploy.services._traefik_routes import route_absent, route_put
from ops_deploy.services.fastdeploy import FastdeployRestoreConfig, deploy_fastdeploy_restore
from ops_deploy.services.work_app.restore import _install_config
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests import fakehost
from tests.test_fastdeploy_lifecycle import SECRETS, TIME, body

BASH = shutil.which("bash")
ROUTE = "/etc/traefik/dynamic/extra.yml"
GUARD = route_guard_command()


def dev_t(major: int, minor: int) -> int:
    """``st_dev`` as glibc's ``makedev`` encodes it (on Linux; macOS encodes differently)."""

    return ((major & 0xFFF) << 8) | ((major & ~0xFFF) << 32) | (minor & 0xFF) | ((minor & ~0xFF) << 12)


def run_guard(tmp_path: Path, table: str, *, device: tuple[int, int] = (0, 25), inode: int = 4242) -> int:
    assert BASH is not None
    lock = tmp_path / "traefik-transaction.lock"
    lock.touch()
    tools = tmp_path / "bin"
    tools.mkdir(exist_ok=True)
    fake_stat = tools / "stat"
    fake_stat.write_text(f"#!/bin/sh\necho '{dev_t(*device)} {inode}'\n")
    fake_stat.chmod(0o755)
    locks = tmp_path / "locks"
    locks.write_text(table)
    env = {"PATH": f"{tools}:/usr/bin:/bin"}
    argv = [BASH, "-c", ROUTE_GUARD_SCRIPT, "traefik-route-guard", str(lock), str(locks)]
    return subprocess.run(argv, env=env, capture_output=True, check=False).returncode


@pytest.mark.skipif(BASH is None, reason="needs bash")
@pytest.mark.parametrize(
    ("table", "device", "code"),
    [
        ("", (0, 25), 0),
        ("1: POSIX  ADVISORY  WRITE 812 00:19:4242 0 EOF\n", (0, 25), 0),
        ("1: FLOCK  ADVISORY  WRITE 812 00:19:4242 0 EOF\n", (0, 25), 1),
        ("1: FLOCK  ADVISORY  READ 812 00:19:4242 0 EOF\n", (0, 25), 1),
        # A process waiting for the lock: the transaction is about to start.
        (
            "1: FLOCK  ADVISORY  WRITE 812 00:19:4242 0 EOF\n1: -> FLOCK  ADVISORY  WRITE 900 00:19:4242 0 EOF\n",
            (0, 25),
            1,
        ),
        ("2: -> FLOCK  ADVISORY  WRITE 900 00:19:4242 0 EOF\n", (0, 25), 1),
        # Another file, or the same inode number on another file system.
        ("1: FLOCK  ADVISORY  WRITE 812 00:19:42420 0 EOF\n", (0, 25), 0),
        ("1: FLOCK  ADVISORY  WRITE 812 00:1a:4242 0 EOF\n", (0, 25), 0),
        # Large device numbers, as the kernel prints them (%02x:%02x).
        ("1: FLOCK  ADVISORY  WRITE 812 103:123:4242 0 EOF\n", (259, 0x123), 1),
        ("1: FLOCK  ADVISORY  WRITE 812 103:23:4242 0 EOF\n", (259, 0x123), 0),
    ],
)
def test_the_guard_refuses_only_while_the_lock_is_held(
    table: str, device: tuple[int, int], code: int, tmp_path: Path
) -> None:
    assert run_guard(tmp_path, table, device=device) == code


@pytest.mark.skipif(BASH is None, reason="needs bash")
def test_without_a_lock_file_the_guard_passes(tmp_path: Path) -> None:
    assert BASH is not None
    argv = [BASH, "-c", ROUTE_GUARD_SCRIPT, "traefik-route-guard", str(tmp_path / "absent.lock"), "/nonexistent"]
    assert subprocess.run(argv, capture_output=True, check=False).returncode == 0


def test_the_guard_reads_the_engines_lock_and_survives_shell_wrapping() -> None:
    assert str(engine.LOCK) == TRANSACTION_LOCK
    assert shlex.split(GUARD) == [
        "bash",
        "-c",
        ROUTE_GUARD_SCRIPT,
        "traefik-route-guard",
        TRANSACTION_LOCK,
        "/proc/locks",
    ]
    # pyinfra wraps commands in sh -c '...'; neither quotes nor escapes may need rewriting.
    assert "'" not in ROUTE_GUARD_SCRIPT
    assert "\\" not in ROUTE_GUARD_SCRIPT
    # Never takes the lock itself, never writes a file: the only redirections are stderr and the table.
    code = "\n".join(line for line in ROUTE_GUARD_SCRIPT.splitlines() if not line.startswith("#"))
    assert "flock" not in code
    assert re.findall(r"(?<![>&])>(?![>&])", code) == []
    assert code.count(">&2") == 1
    assert code.count("<") == 3  # "< <(stat ...)" and the lock table


def test_guarded_adds_the_guard_only_in_front_of_changes() -> None:
    assert list(guarded([])) == []
    found = [str(item) for item in guarded(["one", "two"])]
    assert found == [GUARD, "one", "two"]


# -- the writers --------------------------------------------------------------------------------


def put(content: str) -> Any:
    @deploy("Routes")
    def _deploy() -> None:
        route_put(name="Write extra route", src=content, dest=ROUTE)

    return _deploy


def absent() -> Any:
    @deploy("Routes")
    def _deploy() -> None:
        route_absent(name="Remove extra route", path=ROUTE)

    return _deploy


def responses(content: str | None = None) -> dict[str, Any]:
    found = {**fakehost.LINUX, **fakehost.directory("/etc/traefik/dynamic")}
    if content is not None:
        found.update(fakehost.file(ROUTE, content))
    return found


def ok(run: FakeRun) -> FakeRun:
    assert run.succeeded, run.error
    return run


def test_route_put_guards_a_write_and_stays_silent_when_unchanged() -> None:
    written = ok(run_deploy_fake(put("routes: new\n"), responses=responses("routes: old\n")))
    assert written.executed_commands[0] == GUARD
    assert written.uploaded_paths == [ROUTE]

    same = ok(run_deploy_fake(put("routes: same\n"), responses=responses("routes: same\n")))
    assert same.executed_commands == []
    assert same.changed_ops == []


def test_route_absent_guards_a_removal_and_skips_a_missing_file() -> None:
    removed = ok(run_deploy_fake(absent(), responses=responses("routes: old\n")))
    assert removed.executed_commands == [GUARD, f"rm -f {ROUTE}"]

    missing = ok(run_deploy_fake(absent(), responses=responses()))
    assert missing.executed_commands == []


def test_a_held_lock_fails_the_write_before_it() -> None:
    held = {"traefik-route-guard": {"success": False}, **responses("routes: old\n")}
    run = run_deploy_fake(put("routes: new\n"), responses=held)

    assert not run.succeeded
    assert run.uploaded_paths == []


def test_traefik_route_guards_only_a_change() -> None:
    route = TraefikRoute(name="app", host="app.example.com", app_port=8000)
    path = "/etc/traefik/dynamic/app.yml"

    @deploy("Route")
    def _deploy() -> None:
        traefik_route(route)

    base = {**fakehost.LINUX, **fakehost.service("traefik.service"), **fakehost.directory("/etc/traefik/dynamic")}
    changed = ok(run_deploy_fake(_deploy, responses={**base, **fakehost.file(path, "old\n")}))
    assert changed.executed_commands[0] == GUARD
    assert changed.executed_commands.index(GUARD) < changed.executed_commands.index("systemctl restart traefik.service")

    same = ok(run_deploy_fake(_deploy, responses={**base, **fakehost.file(path, render_route(route, None))}))
    assert GUARD not in same.executed_commands
    assert same.changed_ops == []


def test_remove_path_guards_only_below_the_dynamic_directory() -> None:
    @deploy("Remove")
    def _deploy() -> None:
        remove_path("/etc/traefik/dynamic/app.yml")
        remove_path("/etc/systemd/system/app.service")

    present = {
        "test -e /etc/traefik/dynamic/app.yml &&": ["yes"],
        "test -e /etc/systemd/system/app.service &&": ["yes"],
    }
    run = ok(run_deploy_fake(_deploy, responses=present))

    assert run.executed_commands == [
        GUARD,
        "rm -rf /etc/traefik/dynamic/app.yml",
        "rm -rf /etc/systemd/system/app.service",
    ]


def test_a_restored_route_is_guarded_only_when_it_is_written() -> None:
    command = _install_config("/stage/traefik.yml", "/etc/traefik/dynamic/work-app.yml", "true", GUARD)

    head, _, written = command.partition("; then ")
    assert GUARD not in head
    assert written.startswith(f"{GUARD} && install -o root -g root -m 0644 ")
    assert _install_config("a", "b", "true") == _install_config("a", "b", "true", "")


@pytest.mark.parametrize(
    ("dry_run", "route", "guarded_run"), [(False, None, True), (True, None, False), (False, "", False)]
)
def test_the_fastdeploy_restore_checks_the_lock_before_it_changes_anything(
    dry_run: bool, route: str | None, guarded_run: bool
) -> None:
    extra = {} if route is None else {"traefik_config_path": route}
    cfg = FastdeployRestoreConfig(host_name="macmini", dry_run=dry_run, **extra)
    run = ok(run_deploy_fake(deploy_fastdeploy_restore, cfg, SECRETS, responses=TIME))

    script = body(run)[0].rstrip()
    assert script.endswith(f"\n{GUARD}\nfd_restore") is guarded_run
    assert script.endswith("\nfd_restore")
