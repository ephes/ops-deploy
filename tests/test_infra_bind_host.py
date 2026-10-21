"""``infra/bind/files/bind_host.py`` run for real on temp trees.

``named-checkzone`` and ``named-checkconf`` are small stand-ins on ``PATH``
(the Docker test uses the real ones): a zone file is valid unless it contains
``INVALID`` and reports the serial from its ``serial=<n>`` marker; a
configuration is valid unless a file it includes contains ``BOGUS``, which the
stand-in reports with the file name and a quote of the line, as named-checkconf
does.
"""

from __future__ import annotations

import base64
import fcntl
import grp
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

SCRIPT = Path(__file__).parents[1] / "src" / "ops_deploy" / "infra" / "bind" / "files" / "bind_host.py"
USER = os.environ.get("USER") or "root"
GROUP = grp.getgrgid(os.getgid()).gr_name
SECRET = "c2VjcmV0LWtleS1tYXRlcmlhbA=="

CHECKZONE = """#!/usr/bin/env python3
import re, sys
text = open(sys.argv[2]).read()
if "INVALID" in text:
    print(f"{sys.argv[2]}:1: bad record"); sys.exit(1)
m = re.search(r"serial=([0-9]+)", text)
print(f"zone {sys.argv[1]}/IN: loaded serial {m.group(1) if m else 0}"); print("OK")
"""
CHECKCONF = """#!/usr/bin/env python3
import os, re, signal, sys
conf = sys.argv[1]
if os.environ.get("CHECKCONF_SIGTERM"):
    os.kill(os.getppid(), signal.SIGTERM)
if os.environ.get("CHECKCONF_LOCK_DIR"):
    os.chmod(os.environ["CHECKCONF_LOCK_DIR"], 0o500)
    print("stand-in failure"); sys.exit(1)
paths = [conf] + re.findall(r'include "([^"]+)"', open(conf).read())
for path in paths:
    for number, line in enumerate(open(path).read().splitlines(), 1):
        if "BOGUS" in line:
            print(f"{path}:{number}: unknown option near '{line.strip()}'"); sys.exit(1)
"""


def load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("bind_host", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Tree:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.etc = self.root / "etc"
        self.dyn = self.root / "dyn"
        self.etc.mkdir()
        self.dyn.mkdir()
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        for name, source in (("named-checkzone", CHECKZONE), ("named-checkconf", CHECKCONF)):
            (bin_dir / name).write_text(source)
            (bin_dir / name).chmod(0o755)
        self.env = {**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}"}
        self.files: dict[str, tuple[str, bytes, str]] = {}
        self.set_config()

    def set_config(
        self, options: str = "options { };\n", zone: str = "zone serial=2\n", keys: str | None = None
    ) -> None:
        keys_text = keys if keys is not None else f'key "k" {{ secret "{SECRET}"; }};\n'
        self.files = {
            str(self.etc / "named.conf.keys"): ("keys", keys_text.encode(), "0640"),
            str(self.etc / "named.conf.options"): ("config", options.encode(), "0644"),
            str(self.etc / "named.conf.local"): ("config", b'zone "example.org" { };\n', "0644"),
            str(self.etc / "db.example.org"): ("zone", zone.encode(), "0644"),
            str(self.dyn / "db.home"): ("seed", b"seed serial=1\n", "0644"),
            str(self.etc / "named.conf"): (
                "config",
                "".join(
                    f'include "{self.etc}/{name}";\n'
                    for name in ("named.conf.keys", "named.conf.options", "named.conf.local")
                ).encode(),
                "0644",
            ),
        }

    def request(self, remove: tuple[str, ...] = (), skip: tuple[str, ...] = ()) -> str:
        zones = {"zone": "example.org", "seed": "home.example.org"}
        return json.dumps(
            {
                "files": [
                    {
                        "path": path,
                        "kind": kind,
                        "zone": zones.get(kind),
                        "user": USER,
                        "group": GROUP,
                        "mode": mode,
                        "data": base64.b64encode(data).decode(),
                    }
                    for path, (kind, data, mode) in self.files.items()
                    if path not in skip
                ],
                "remove": list(remove),
                "named_conf": str(self.etc / "named.conf"),
                "keys_file": str(self.etc / "named.conf.keys"),
                "lock_dir": str(self.etc),
                "ufw": False,
            }
        )

    def run(
        self, action: str, request: str | None = None, env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-I", "-c", SCRIPT.read_text(), action],
            input=request if request is not None else self.request(),
            capture_output=True,
            text=True,
            env={**self.env, **(env or {})},
            check=False,
            timeout=60,
        )

    def ok(self, action: str, request: str | None = None) -> dict[str, Any]:
        result = self.run(action, request)
        assert result.returncode == 0, result.stderr
        assert SECRET not in result.stdout + result.stderr
        data: dict[str, Any] = json.loads(result.stdout)
        return data

    def snapshot(self) -> dict[str, tuple[bytes, int, int]]:
        found = {}
        for path in sorted([*self.etc.iterdir(), *self.dyn.iterdir()]):
            info = path.lstat()
            found[str(path)] = (path.read_bytes() if path.is_file() else b"", info.st_ino, info.st_mode)
        return found


@pytest.fixture
def tree(tmp_path: Path) -> Tree:
    return Tree(tmp_path)


def test_probe_reports_missing_then_same_and_never_prints_the_key(tree: Tree) -> None:
    fresh = tree.ok("probe")["files"]
    assert {path: state["state"] for path, state in fresh.items()} == {
        **{path: "missing" for path in tree.files},
        str(tree.dyn / "db.home"): "missing",
    }

    result = tree.ok("apply")

    assert result["written"] == list(tree.files)
    assert (tree.etc / "named.conf.keys").stat().st_mode & 0o777 == 0o640
    assert (tree.dyn / "db.home").stat().st_mode & 0o777 == 0o644
    for path, (_, data, _) in tree.files.items():
        assert Path(path).read_bytes() == data
    probe = tree.ok("probe")["files"]
    assert {state["state"] for path, state in probe.items() if path != str(tree.dyn / "db.home")} == {"same"}
    assert all(state["attrs"] for state in probe.values())
    assert probe[str(tree.dyn / "db.home")] == {"state": "present", "attrs": True, "journal": False}
    # Converged: nothing written, no staging directory left.
    assert tree.ok("apply") == {"written": [], "removed": []}
    assert not [p for p in tree.etc.iterdir() if p.name.startswith(".ops-deploy-bind.")]


def test_a_failing_checkconf_restores_every_file(tree: Tree) -> None:
    tree.ok("apply")
    before = tree.snapshot()
    tree.set_config(options="options { BOGUS; };\n", zone="zone serial=3\n", keys='key "k" { secret "bmV3"; };\n')

    result = tree.run("apply")

    assert result.returncode == 1
    assert "named-checkconf failed; the previous files are restored and named is not reloaded" in result.stderr
    assert "named.conf.options:1: unknown option" in result.stderr
    assert tree.snapshot() == before
    assert not [p for p in tree.etc.iterdir() if p.name.startswith(".ops-deploy-bind.")]


def test_a_new_file_is_removed_again_when_checkconf_fails(tree: Tree) -> None:
    tree.set_config(options="options { BOGUS; };\n")

    assert tree.run("apply").returncode == 1

    assert sorted(path.name for path in tree.etc.iterdir()) == []
    assert sorted(path.name for path in tree.dyn.iterdir()) == []


def test_checkconf_output_about_the_key_file_is_withheld(tree: Tree) -> None:
    tree.set_config(keys=f'key "k" {{ secret "{SECRET}"; BOGUS; }};\n')

    result = tree.run("apply")

    assert result.returncode == 1
    assert SECRET not in result.stdout + result.stderr
    assert "named.conf.keys withheld: it holds key material" in result.stderr


def test_an_invalid_zone_changes_nothing(tree: Tree) -> None:
    tree.ok("apply")
    before = tree.snapshot()
    tree.set_config(zone="zone serial=9 INVALID\n", options="options { new; };\n")

    result = tree.run("apply")

    assert result.returncode == 1
    assert "named-checkzone example.org failed" in result.stderr
    assert tree.snapshot() == before


@pytest.mark.parametrize("serial", ["2", "1"])
def test_a_changed_zone_needs_a_greater_serial(tree: Tree, serial: str) -> None:
    tree.ok("apply")
    before = tree.snapshot()
    tree.set_config(zone=f"zone serial={serial} changed\n")

    result = tree.run("apply")

    assert result.returncode == 1
    assert "is not greater than the current 2; bump the serial" in result.stderr
    assert tree.snapshot() == before

    tree.set_config(zone="zone serial=3 changed\n")
    assert tree.ok("apply")["written"] == [str(tree.etc / "db.example.org")]


def test_serial_arithmetic_is_rfc_1982() -> None:
    newer = load().serial_newer
    assert newer(2, 1)
    assert not newer(1, 1)
    assert not newer(1, 2)
    assert newer(1, 4294967295)  # wraps
    assert not newer(2**31 + 1, 1)


def test_an_existing_dynamic_zone_is_never_touched(tree: Tree) -> None:
    (tree.dyn / "db.home").write_text("named's zone serial=77\n")
    (tree.dyn / "db.home.jnl").write_bytes(b"journal")
    os.chmod(tree.dyn / "db.home", 0o600)
    before = tree.snapshot()

    tree.ok("apply")

    after = tree.snapshot()
    for name in ("db.home", "db.home.jnl"):
        assert after[str(tree.dyn / name)] == before[str(tree.dyn / name)]


def test_a_journal_without_its_dynamic_zone_is_refused(tree: Tree) -> None:
    (tree.dyn / "db.home.jnl").write_bytes(b"journal")
    before = tree.snapshot()

    result = tree.run("apply")

    assert result.returncode == 1
    assert "db.home.jnl exists; seeding it would desynchronise the journal" in result.stderr
    assert tree.snapshot() == before
    assert tree.ok("probe")["files"][str(tree.dyn / "db.home")] == {
        "state": "missing",
        "attrs": True,
        "journal": True,
    }


def test_a_static_zone_with_a_journal_is_not_replaced(tree: Tree) -> None:
    tree.ok("apply")
    (tree.etc / "db.example.org.jnl").write_bytes(b"journal")
    before = tree.snapshot()
    tree.set_config(zone="zone serial=5\n")

    result = tree.run("apply")

    assert result.returncode == 1
    assert "refusing to replace a zone file that has a journal" in result.stderr
    assert tree.snapshot() == before


def test_the_key_file_goes_last_and_comes_back_on_failure(tree: Tree) -> None:
    tree.ok("apply")
    keys = str(tree.etc / "named.conf.keys")
    tree.files[str(tree.etc / "named.conf")] = (
        "config",
        f'include "{tree.etc}/named.conf.options";\ninclude "{tree.etc}/named.conf.local";\n'.encode(),
        "0644",
    )
    before = tree.snapshot()
    tree.files[str(tree.etc / "named.conf.local")] = ("config", b"BOGUS\n", "0644")

    assert tree.run("apply", tree.request(remove=(keys,), skip=(keys,))).returncode == 1
    assert tree.snapshot() == before

    tree.files[str(tree.etc / "named.conf.local")] = ("config", b'zone "example.org" { };\n', "0644")
    result = tree.ok("apply", tree.request(remove=(keys,), skip=(keys,)))
    assert result["removed"] == [keys]
    assert not Path(keys).exists()
    assert tree.ok("probe", tree.request(remove=(keys,), skip=(keys,)))["remove"] == {keys: "missing"}


def test_a_symlink_in_place_of_a_config_file_is_refused(tree: Tree) -> None:
    (tree.root / "elsewhere").write_text("x")
    (tree.etc / "named.conf.options").symlink_to(tree.root / "elsewhere")

    result = tree.run("apply")

    assert result.returncode == 1
    assert "named.conf.options is not a regular file" in result.stderr
    assert tree.ok("probe")["files"][str(tree.etc / "named.conf.options")]["state"] == "other"
    assert (tree.root / "elsewhere").read_text() == "x"


def test_wrong_mode_alone_is_rewritten(tree: Tree) -> None:
    tree.ok("apply")
    os.chmod(tree.etc / "named.conf.keys", 0o644)

    assert tree.ok("probe")["files"][str(tree.etc / "named.conf.keys")] == {
        "state": "same",
        "attrs": False,
        "journal": False,
    }
    assert tree.ok("apply")["written"] == [str(tree.etc / "named.conf.keys")]
    assert (tree.etc / "named.conf.keys").stat().st_mode & 0o777 == 0o640


def test_a_second_deploy_waits_for_nobody(tree: Tree) -> None:
    fd = os.open(tree.etc, os.O_RDONLY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        result = tree.run("apply")
    finally:
        os.close(fd)

    assert result.returncode == 1
    assert "another deploy holds the lock" in result.stderr
    assert tree.snapshot() == {}


def test_bad_requests_fail_without_echoing_them(tree: Tree) -> None:
    result = tree.run("apply", "{" + SECRET)

    assert result.returncode == 1
    assert SECRET not in result.stderr
    assert tree.run("other").returncode == 1


@pytest.mark.parametrize("fail", [False, True])
def test_a_signal_waits_until_the_transaction_is_done(tree: Tree, fail: bool) -> None:
    tree.ok("apply")
    (tree.etc / ".ops-deploy-bind-reload-pending").unlink()  # the deploy's reload
    before = tree.snapshot()
    tree.set_config(options="options { BOGUS; };\n" if fail else "options { changed; };\n")

    result = tree.run("apply", env={"CHECKCONF_SIGTERM": "1"})

    # Delivered after the commit or the restore, never in between.
    assert result.returncode == 128 + 15
    after = tree.snapshot()
    marker = tree.etc / ".ops-deploy-bind-reload-pending"
    if fail:
        assert after == before
        assert not marker.exists()
    else:
        assert (tree.etc / "named.conf.options").read_text() == "options { changed; };\n"
        # The deploy's next run sees the reload it still owes.
        assert marker.exists()
        assert tree.ok("probe")["reload_pending"] is True
        assert {path for path in after if ".ops-deploy-bind." in path} == set()


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores the directory permissions this test relies on")
def test_a_failed_restore_keeps_the_backups_and_refuses_the_next_run(tree: Tree) -> None:
    tree.ok("apply")
    original = (tree.etc / "named.conf.options").read_bytes()
    tree.set_config(options="options { changed; };\n")

    result = tree.run("apply", env={"CHECKCONF_LOCK_DIR": str(tree.etc)})
    os.chmod(tree.etc, 0o755)

    assert result.returncode == 1
    assert "could not be restored" in result.stderr
    assert "backups kept in" in result.stderr
    [stage] = [path for path in tree.etc.iterdir() if path.name.startswith(".ops-deploy-bind.")]
    backups = {path.read_bytes() for path in stage.iterdir() if path.name.startswith("old-")}
    assert original in backups

    # The new files match the request now; the leftover backups still stop the run.
    assert tree.ok("probe")["leftovers"] == [str(stage)]
    again = tree.run("apply")
    assert again.returncode == 1
    assert "is left from an interrupted or unrestored run" in again.stderr
    assert stage.exists()


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores the directory permissions this test relies on")
def test_new_files_that_cannot_be_removed_again_refuse_the_next_run(tree: Tree) -> None:
    # A first install whose rollback cannot delete the files it created: no backups exist.
    tree.set_config(options="options { new; };\n")

    result = tree.run("apply", env={"CHECKCONF_LOCK_DIR": str(tree.etc)})
    os.chmod(tree.etc, 0o755)

    assert result.returncode == 1
    assert "could not be restored" in result.stderr
    [stage] = [path for path in tree.etc.iterdir() if path.name.startswith(".ops-deploy-bind.")]
    assert str(stage) in tree.ok("probe")["leftovers"]
    again = tree.run("apply")
    assert again.returncode == 1
    assert "is left from an interrupted or unrestored run" in again.stderr


def test_a_killed_run_leaves_a_stage_that_refuses(tree: Tree) -> None:
    (tree.etc / ".ops-deploy-bind.deadbeef").mkdir(mode=0o700)

    assert tree.ok("probe")["leftovers"] == [str(tree.etc / ".ops-deploy-bind.deadbeef")]
    result = tree.run("apply")
    assert result.returncode == 1
    assert "is left from an interrupted or unrestored run" in result.stderr


def test_success_marks_a_reload_and_a_failure_does_not(tree: Tree) -> None:
    marker = tree.etc / ".ops-deploy-bind-reload-pending"
    tree.set_config(options="options { BOGUS; };\n")
    assert tree.run("apply").returncode == 1
    assert not marker.exists()

    tree.set_config()
    tree.ok("apply")
    assert marker.exists()
    assert tree.ok("probe")["reload_pending"] is True
