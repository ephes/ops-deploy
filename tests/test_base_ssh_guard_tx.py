"""``files/ssh_guard_tx.py`` (the timed revert's host program) against stub ``systemctl``/``systemd-run``/apt.

The program runs as a subprocess on files in a temporary directory, with stub
binaries first on ``PATH`` that keep unit, timer and package state in a
``world`` directory and log every call. A timer is recorded, not started: a
test fires it by running the recorded command, which is how the revert's
ordering against apply, confirm and later transactions is exercised.
``tests/test_base_ssh_guard_docker.py`` runs the same program under real systemd.
"""

from __future__ import annotations

import base64
import json
import os
import shlex
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import pytest

PROGRAM = Path(__file__).parents[1] / "src" / "ops_deploy" / "base" / "files" / "ssh_guard_tx.py"
pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX only")

SYSTEMCTL = r"""#!/bin/sh
echo "systemctl $*" >> "$WORLD/log"
quiet=; cmd=$1; unit=$2
if [ "$1" = "is-active" ] && [ "$2" = "--quiet" ]; then quiet=1; unit=$3; fi
case "$cmd" in show) unit=$5;; esac
unit=${unit%.service}
case "$unit" in
  *.timer) name=${unit%.timer}
    case "$cmd" in
      is-active) [ -f "$WORLD/timers/$name" ] && { [ -n "$quiet" ] || echo active; exit 0; }
                 [ -n "$quiet" ] || echo inactive; exit 3;;
      stop) rm -f "$WORLD/timers/$name"; exit 0;;
    esac; exit 0;;
esac
u="$WORLD/units/$unit"
case "$cmd" in
  is-active) if [ -f "$u.active" ]; then [ -n "$quiet" ] || echo active; exit 0; fi
             if [ -f "$WORLD/running/$unit" ]; then [ -n "$quiet" ] || echo active; exit 0; fi
             [ -n "$quiet" ] || echo inactive; exit 3;;
  is-enabled) if [ -f "$u.enabled" ]; then echo enabled; exit 0; fi
              if [ -f "$u.loaded" ]; then echo disabled; else echo not-found; fi; exit 1;;
  show) if [ -f "$u.loaded" ]; then echo loaded; else echo not-found; fi;;
  enable) touch "$u.enabled";; disable) rm -f "$u.enabled";;
  start|restart) [ -f "$WORLD/fail-$cmd-$unit" ] && exit 1; touch "$u.active";;
  stop) rm -f "$u.active";;
  reload) [ -f "$WORLD/fail-reload-$unit" ] && exit 1; :;;
esac
exit 0
"""

SYSTEMD_RUN = r"""#!/bin/sh
echo "systemd-run $*" >> "$WORLD/log"
unit=; timer=
while [ $# -gt 0 ]; do
  case "$1" in
    --unit=*) unit=${1#--unit=};;
    --on-active=*) timer=1;;
    --*) ;;
    *) break;;
  esac
  shift
done
[ -f "$WORLD/fail-systemd-run" ] && exit 1
if [ -n "$timer" ]; then
  [ -f "$WORLD/fail-timer" ] && exit 1
  shift  # /usr/bin/python3 -> the test's interpreter
  printf '%s\n' "$TEST_PYTHON" "$@" > "$WORLD/timers/$unit"
  exit 0
fi
shift
touch "$WORLD/running/$unit"
"$TEST_PYTHON" "$@" > "$WORLD/apply.out" 2> "$WORLD/apply.err"
echo $? > "$WORLD/apply.exit"
rm -f "$WORLD/running/$unit"
exit 0
"""

DPKG_QUERY = r"""#!/bin/sh
for last; do :; done
[ -f "$WORLD/pkgs/$last" ] && { printf 'install ok installed'; exit 0; }
exit 1
"""

APT_GET = r"""#!/bin/sh
echo "apt-get $*" >> "$WORLD/log"
for last; do :; done
[ -f "$WORLD/fail-apt" ] && exit 100
touch "$WORLD/pkgs/$last"
mkdir -p "$WORLD/units" && touch "$WORLD/units/$last.loaded" "$WORLD/units/$last.enabled" "$WORLD/units/$last.active"
"""


class World:
    """A temporary host: managed files under ``etc``, stub binaries, the program's state dir."""

    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.root = tmp / "world"
        self.etc = tmp / "etc"
        self.state_dir = tmp / "state"
        for sub in ("timers", "units", "pkgs", "running"):
            (self.root / sub).mkdir(parents=True)
        self.bin = tmp / "bin"
        self.bin.mkdir()
        for name, text in (
            ("systemctl", SYSTEMCTL),
            ("systemd-run", SYSTEMD_RUN),
            ("dpkg-query", DPKG_QUERY),
            ("apt-get", APT_GET),
        ):
            path = self.bin / name
            path.write_text(text)
            path.chmod(0o755)
        (self.etc / "ssh").mkdir(parents=True)
        (self.etc / "f2b").mkdir(parents=True)
        self.dropin = str(self.etc / "ssh" / "99-guard.conf")
        self.jail = str(self.etc / "f2b" / "jail.local")
        self.uid, self.gid = os.getuid(), os.getgid()
        self.env = {
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "WORLD": str(self.root),
            "TEST_PYTHON": sys.executable,
        }

    def unit(self, name: str, *, loaded: bool = True, enabled: bool = True, active: bool = True) -> None:
        for flag, on in (("loaded", loaded), ("enabled", enabled), ("active", active)):
            path = self.root / "units" / f"{name}.{flag}"
            if on:
                path.touch()
            else:
                path.unlink(missing_ok=True)

    def unit_flags(self, name: str) -> tuple[bool, bool]:
        units = self.root / "units"
        return ((units / f"{name}.enabled").exists(), (units / f"{name}.active").exists())

    def bundle(self, steps: list[dict[str, Any]], *, generation: int = 0, after: int = 900) -> dict[str, Any]:
        owner = {"uid": self.uid, "gid": self.gid}
        return {
            "schema": 1,
            "revert_after": after,
            "expect_generation": generation,
            "files": [
                {"path": self.dropin, **owner, "mode": 0o644},
                {"path": self.jail, **owner, "mode": 0o644},
            ],
            "dirs": [{"path": str(self.etc / "ssh" / "conf.d"), **owner, "mode": 0o755}],
            "services": [
                {"role": "fail2ban", "unit": "fail2ban", "files": [self.jail]},
                {"role": "ssh", "unit": "ssh", "files": [self.dropin], "check": f"test ! -e {self.root}/bad-check"},
            ],
            "steps": steps,
        }

    def standard(self, dropin: str = "PerSourceMaxStartups 5\n", **kwargs: Any) -> dict[str, Any]:
        return self.bundle(
            [
                {"id": "s1", "kind": "dir", "name": "Ensure conf.d", "path": str(self.etc / "ssh" / "conf.d")},
                {
                    "id": "s2",
                    "kind": "package",
                    "name": "Install fail2ban",
                    "package": "fail2ban",
                    "no_recommends": True,
                },
                {"id": "s3", "kind": "file", "name": "Write jail", "path": self.jail, "content": "[sshd]\n"},
                {
                    "id": "s4",
                    "kind": "shell",
                    "name": "Restart fail2ban",
                    "command": "systemctl restart fail2ban",
                    "when": ["s2", "s3"],
                    "always": False,
                },
                {"id": "s5", "kind": "service", "name": "Ensure fail2ban", "unit": "fail2ban"},
                {"id": "s6", "kind": "file", "name": "Write drop-in", "path": self.dropin, "content": dropin},
                {
                    "id": "s7",
                    "kind": "shell",
                    "name": "Validate",
                    "command": "test ! -e " + shlex.quote(str(self.root / "bad")),
                    "when": ["s6"],
                    "always": False,
                },
                {
                    "id": "s8",
                    "kind": "shell",
                    "name": "Reload ssh",
                    "command": "systemctl reload ssh",
                    "when": ["s6"],
                    "always": False,
                },
            ],
            **kwargs,
        )

    def tx(self, *args: str, caller: str | None = None, stdin: str | None = None) -> subprocess.CompletedProcess[str]:
        env = dict(self.env)
        if caller is not None:
            env["SSH_CONNECTION"] = caller
        return subprocess.run(
            [sys.executable, "-I", str(PROGRAM), "--state-dir", str(self.state_dir), *args],
            capture_output=True,
            text=True,
            env=env,
            input=stdin,
            timeout=120,
            check=False,
        )

    def confirm(
        self, generation: int, *, caller: str | None = None, session: str | None = "new"
    ) -> subprocess.CompletedProcess[str]:
        """``confirm`` as if run in an SSH session: ``new`` (opened now), ``old`` (before the change) or none.

        A fake ``/proc`` holds the test process (the program's parent) as the
        connection's ``sshd-session`` with that start time.
        """

        proc = self.tmp / "proc"
        entry = proc / str(os.getpid())
        entry.mkdir(parents=True, exist_ok=True)
        if session is None:
            (entry / "stat").unlink(missing_ok=True)
        else:
            tick = os.sysconf("SC_CLK_TCK")
            seconds = uptime() + 5 if session == "new" else 1.0
            fields = ["S", "1", *["0"] * 17, str(int(seconds * tick)), "0", "0"]
            (entry / "stat").write_text(f"{os.getpid()} (sshd-session) {' '.join(fields)}\n")
        return self.tx(
            "confirm",
            "--generation",
            str(generation),
            "--proc-root",
            str(proc),
            caller=NEW if caller is None else caller,
        )

    def run(
        self, bundle: dict[str, Any], caller: str = "198.51.100.1 50000 192.0.2.1 22"
    ) -> subprocess.CompletedProcess[str]:
        encoded = base64.b64encode(json.dumps(bundle).encode()).decode()
        return self.tx("run", "--bundle-b64", encoded, "--caller", caller)

    def plan(self, bundle: dict[str, Any]) -> dict[str, Any]:
        encoded = base64.b64encode(json.dumps(bundle).encode()).decode()
        result = self.tx("plan", "--bundle-b64", encoded)
        assert result.returncode == 0, result.stderr
        answer: dict[str, Any] = json.loads(result.stdout)
        return answer

    def state(self) -> dict[str, Any]:
        state: dict[str, Any] = json.loads((self.state_dir / "state.json").read_text())
        return state

    def status_line(self) -> str:
        return (self.state_dir / "status").read_text()

    def timers(self) -> list[str]:
        return sorted(path.name for path in (self.root / "timers").iterdir())

    def fire(self, name: str | None = None) -> subprocess.CompletedProcess[str]:
        """Run a recorded timer's command, as systemd would when it elapses (the timer stays recorded)."""

        name = name or self.timers()[0]
        argv = (self.root / "timers" / name).read_text().splitlines()
        return subprocess.run(argv, capture_output=True, text=True, env=self.env, timeout=120, check=False)

    def log(self) -> list[str]:
        path = self.root / "log"
        return path.read_text().splitlines() if path.exists() else []

    def expire(self) -> None:
        state = self.state()
        state["deadline_monotonic"] = 0
        (self.state_dir / "state.json").write_text(json.dumps(state))


def uptime() -> float:
    return time.clock_gettime(getattr(time, "CLOCK_BOOTTIME", time.CLOCK_MONOTONIC))


def mode(path: str) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


NEW = "198.51.100.2 50001 192.0.2.1 22"


@pytest.fixture
def world(tmp_path: Path) -> World:
    return World(tmp_path)


def test_plan_lists_the_steps_that_would_run(world: World) -> None:
    bundle = world.standard()
    assert world.plan(bundle) == {
        "pending": True,
        "steps": [
            "Ensure conf.d",
            "Install fail2ban",
            "Write jail",
            "Restart fail2ban",
            "Ensure fail2ban",
            "Write drop-in",
            "Validate",
            "Reload ssh",
        ],
    }
    assert not world.state_dir.exists()
    assert all(line.startswith(("systemctl is-", "systemctl show")) for line in world.log())


def test_apply_arms_before_the_first_change_and_the_timer_restores_everything(world: World) -> None:
    Path(world.dropin).write_text("PerSourceMaxStartups 9\n")
    os.chmod(world.dropin, 0o600)
    world.unit("ssh")

    result = world.run(world.standard())

    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["status"] == "armed"
    assert report["generation"] == 1
    state = world.state()
    assert state["changed"] == [
        "Ensure conf.d",
        "Install fail2ban",
        "Write jail",
        "Restart fail2ban",
        "Write drop-in",
        "Validate",
        "Reload ssh",
    ]
    assert world.status_line() == f"armed 1 {state['txid']}\n"
    assert Path(world.dropin).read_text() == "PerSourceMaxStartups 5\n"
    assert mode(world.dropin) == 0o644
    # The timer was armed before the first change (the package install).
    log = world.log()
    armed = next(i for i, line in enumerate(log) if "--on-active=900" in line)
    first_change = next(i for i, line in enumerate(log) if line.startswith("apt-get"))
    assert armed < first_change
    assert world.timers() == [f"ssh-guard-tx-revert-{state['txid'][:12]}"]
    # The timer's command runs the transaction's own copy of the program.
    timer = world.timers()[0]
    argv = (world.root / "timers" / timer).read_text().splitlines()
    assert argv[2] == str(world.state_dir / "tx" / state["txid"] / "ssh-guard-tx.py")
    assert argv[-4:] == ["revert", state["txid"], "--reason", "timer"]

    fired = world.fire()

    assert fired.returncode == 0, fired.stderr
    assert Path(world.dropin).read_text() == "PerSourceMaxStartups 9\n"
    assert mode(world.dropin) == 0o600
    assert not Path(world.jail).exists()
    assert not (world.etc / "ssh" / "conf.d").exists()
    state = world.state()
    assert state["status"] == "reverted"
    assert state["packages_left_installed"] == ["fail2ban"]
    # fail2ban was not there before: stopped and disabled; ssh reloaded onto the old drop-in.
    assert world.unit_flags("fail2ban") == (False, False)
    assert world.log()[-3:] == [
        "systemctl is-active --quiet ssh",
        "systemctl reload ssh",
        f"systemctl stop {timer}.timer",
    ]
    (world.root / "timers" / timer).write_text("\n".join(argv))

    # A revert fires at most once: the timer again, or by hand, changes nothing.
    Path(world.dropin).write_text("later\n")
    again = world.fire()
    assert again.returncode == 0
    assert "nothing to do (reverted)" in again.stdout
    assert Path(world.dropin).read_text() == "later\n"


def test_confirm_needs_a_new_connection_in_time_then_the_timer_does_nothing(world: World) -> None:
    world.unit("ssh")
    assert world.run(world.standard()).returncode == 0
    timer = world.timers()[0]

    assert "new SSH connection" in world.confirm(1, caller="").stderr
    same = world.confirm(1, caller="198.51.100.1 50000 192.0.2.1 22")
    assert same.returncode == 3
    assert "new SSH connection" in same.stderr
    # A multiplexed or kept-open connection from before the change does not count.
    older = world.confirm(1, session="old")
    assert older.returncode == 3
    assert "opened before the change" in older.stderr
    outside = world.confirm(1, session=None)
    assert outside.returncode == 3
    assert "must run in an SSH session" in outside.stderr
    wrong = world.confirm(2)
    assert wrong.returncode == 3
    assert "not armed" in wrong.stderr
    assert world.state()["status"] == "armed"

    ok = world.confirm(1)

    assert ok.returncode == 0, ok.stderr
    assert world.state()["status"] == "confirmed"
    assert world.timers() == []
    # The revert service may already have been waiting for the lock: it finds the transaction confirmed.
    (world.root / "timers" / timer).write_text(
        "\n".join(
            [sys.executable, "-I", str(PROGRAM), "--state-dir", str(world.state_dir), "revert", world.state()["txid"]]
        )
    )
    late = world.fire(timer)
    assert late.returncode == 0
    assert "nothing to do (confirmed)" in late.stdout
    assert Path(world.dropin).read_text() == "PerSourceMaxStartups 5\n"


def test_confirm_after_the_deadline_is_refused(world: World) -> None:
    world.unit("ssh")
    assert world.run(world.standard()).returncode == 0
    world.expire()

    late = world.confirm(1)

    assert late.returncode == 3
    assert "deadline has passed" in late.stderr
    assert world.state()["status"] == "armed"
    assert world.fire().returncode == 0
    assert world.state()["status"] == "reverted"


def test_an_open_transaction_or_a_moved_generation_refuses_a_new_run(world: World) -> None:
    world.unit("ssh")
    assert world.run(world.standard()).returncode == 0

    second = world.run(world.standard(dropin="PerSourceMaxStartups 7\n", generation=1))
    assert second.returncode == 3
    assert "is armed; confirm or revert it" in second.stderr

    assert world.confirm(1).returncode == 0
    stale_plan = world.run(world.standard(dropin="PerSourceMaxStartups 7\n", generation=0))
    assert stale_plan.returncode == 3
    assert "generation changed since planning" in stale_plan.stderr
    assert Path(world.dropin).read_text() == "PerSourceMaxStartups 5\n"


def test_an_old_timer_cannot_touch_a_newer_transaction(world: World) -> None:
    world.unit("ssh")
    assert world.run(world.standard()).returncode == 0
    old_timer = world.timers()[0]
    old_argv = (world.root / "timers" / old_timer).read_text()
    assert world.confirm(1).returncode == 0
    (world.root / "timers" / old_timer).write_text(old_argv)

    newer = world.run(world.standard(dropin="PerSourceMaxStartups 7\n", generation=1))
    assert newer.returncode == 0, newer.stderr
    assert world.state()["generation"] == 2

    stale = world.fire(old_timer)

    assert stale.returncode == 0
    assert "nothing to do (armed)" in stale.stdout
    assert Path(world.dropin).read_text() == "PerSourceMaxStartups 7\n"
    assert world.state()["status"] == "armed"
    # The newer transaction's own timer still restores generation 1's result.
    new_timer = next(name for name in world.timers() if name != old_timer)
    assert world.fire(new_timer).returncode == 0
    assert Path(world.dropin).read_text() == "PerSourceMaxStartups 5\n"


def test_a_file_changed_after_the_transaction_is_not_overwritten(world: World) -> None:
    world.unit("ssh")
    assert world.run(world.standard()).returncode == 0
    Path(world.dropin).write_text("written by someone else\n")

    fired = world.fire()

    assert fired.returncode == 2
    assert world.state()["status"] == "superseded"
    assert Path(world.dropin).read_text() == "written by someone else\n"
    assert Path(world.jail).exists()
    assert world.timers() == []


def test_a_failing_step_reverts_at_once(world: World) -> None:
    Path(world.dropin).write_text("PerSourceMaxStartups 9\n")
    world.unit("ssh")
    world.unit("fail2ban", enabled=False, active=True)
    (world.root / "pkgs" / "fail2ban").touch()
    (world.root / "bad").touch()  # the validate step fails

    result = world.run(world.standard())

    assert result.returncode == 1
    state = world.state()
    assert state["status"] == "reverted"
    assert state["reason"] == "step failed: Validate"
    assert Path(world.dropin).read_text() == "PerSourceMaxStartups 9\n"
    assert not Path(world.jail).exists()
    assert world.timers() == []
    assert state["errors"] == []
    # fail2ban was active and disabled: the enable of "Ensure" is undone, it is restarted onto the old files.
    assert world.unit_flags("fail2ban") == (False, True)
    log = world.log()
    undo = log.index("systemctl disable fail2ban")
    assert "systemctl restart fail2ban" in log[undo:]
    # The drop-in is back, checked and ssh reloaded onto it (the apply never reloaded).
    assert log[-3:] == [
        "systemctl is-active --quiet ssh",
        "systemctl reload ssh",
        f"systemctl stop {state['timer']}.timer",
    ]


def test_a_restored_ssh_configuration_that_fails_its_check_is_not_reloaded(world: World) -> None:
    Path(world.dropin).write_text("PerSourceMaxStartups 9\n")
    world.unit("ssh")
    assert world.run(world.standard()).returncode == 0
    (world.root / "bad-check").touch()

    fired = world.fire()

    assert fired.returncode == 1
    state = world.state()
    assert state["status"] == "revert-failed"
    assert state["errors"] == ["ssh not reloaded: the restored configuration fails its check"]
    assert Path(world.dropin).read_text() == "PerSourceMaxStartups 9\n"
    reverted = world.log()[world.log().index("systemctl stop fail2ban") :]
    assert "systemctl reload ssh" not in reverted


def test_restore_failures_are_reported_and_nothing_is_reloaded_onto_them(world: World) -> None:
    Path(world.dropin).write_text("PerSourceMaxStartups 9\n")
    world.unit("ssh")
    world.unit("fail2ban")
    (world.root / "pkgs" / "fail2ban").touch()
    assert world.run(world.standard()).returncode == 0
    for directory in (world.etc / "ssh", world.etc / "f2b"):
        directory.chmod(0o555)
    try:
        fired = world.fire()
    finally:
        for directory in (world.etc / "ssh", world.etc / "f2b"):
            directory.chmod(0o755)

    assert fired.returncode == 1
    state = world.state()
    assert state["status"] == "revert-failed"
    assert any(error.startswith("restoring ") for error in state["errors"])
    assert "ssh not reloaded: its files were not restored" in state["errors"]
    # fail2ban's file could not be restored: it is stopped (its bans go), not restarted onto it.
    assert world.unit_flags("fail2ban") == (True, False)
    log = world.log()
    reverted = log[log.index("systemctl stop fail2ban") :]
    assert "systemctl restart fail2ban" not in reverted
    assert "systemctl reload ssh" not in reverted
    # Final: a later timer or manual revert does nothing.
    again = world.tx("revert", state["txid"])
    assert "nothing to do (revert-failed)" in again.stdout


def test_a_died_apply_is_reverted_by_the_timer_without_the_digest_check(world: World) -> None:
    world.unit("ssh")
    bundle = world.standard()
    bundle["steps"].insert(
        6,
        {"id": "s9", "kind": "shell", "name": "Die", "command": "kill -9 $PPID", "when": [], "always": True},
    )

    result = world.run(bundle)

    assert result.returncode == 1
    assert "the revert timer restores the snapshot" in result.stderr
    assert world.state()["status"] == "applying"
    assert Path(world.dropin).read_text() == "PerSourceMaxStartups 5\n"
    fired = world.fire()
    assert fired.returncode == 0, fired.stderr
    assert world.state()["status"] == "reverted"
    assert not Path(world.dropin).exists()


def test_the_revert_waits_for_a_running_apply(world: World) -> None:
    world.unit("ssh")
    bundle = world.standard()
    bundle["steps"].insert(
        6,
        {"id": "s9", "kind": "shell", "name": "Slow", "command": "sleep 3", "when": [], "always": True},
    )
    outcome: dict[str, subprocess.CompletedProcess[str]] = {}
    runner = threading.Thread(target=lambda: outcome.setdefault("run", world.run(bundle)))
    runner.start()
    for _ in range(100):
        if world.timers():
            break
        time.sleep(0.05)
    fired = world.fire()  # blocks on the lock until the apply has finished
    runner.join()

    # The run may report "armed" or, if the revert won the race to its poll, "reverted".
    assert outcome["run"].returncode in (0, 1)
    assert fired.returncode == 0
    state = world.state()
    assert state["status"] == "reverted"
    # Every step of the apply ran before the revert restored anything.
    log = world.log()
    assert log.index("systemctl reload ssh") < log.index("systemctl stop fail2ban")
    assert not Path(world.dropin).exists()


def test_a_timer_that_cannot_be_armed_changes_nothing(world: World) -> None:
    (world.root / "fail-timer").touch()

    result = world.run(world.standard())

    assert result.returncode == 1
    assert world.state()["status"] == "aborted"
    assert not Path(world.dropin).exists()
    assert not any(line.startswith("apt-get") for line in world.log())


def test_an_apply_unit_that_does_not_start_changes_nothing(world: World) -> None:
    (world.root / "fail-systemd-run").touch()
    result = world.run(world.standard())
    assert result.returncode == 3
    assert world.state()["status"] == "aborted"
    assert "nothing was changed" in result.stderr
    assert not Path(world.dropin).exists()


def test_a_staged_transaction_is_aborted_by_its_revert(world: World) -> None:
    txid = "0123456789abcdef0123456789abcdef"
    world.state_dir.mkdir()
    (world.state_dir / "state.json").write_text(json.dumps({"status": "staged", "generation": 4, "txid": txid}))

    other = world.tx("revert", "f" * 32)
    assert "nothing to do (staged)" in other.stdout
    result = world.tx("revert", txid)

    assert result.returncode == 0
    assert world.state()["status"] == "aborted"
    assert world.status_line() == f"aborted 4 {txid}\n"


def test_nothing_to_change_arms_nothing(world: World) -> None:
    world.unit("ssh")
    world.unit("fail2ban")
    (world.root / "pkgs" / "fail2ban").touch()
    (world.etc / "ssh" / "conf.d").mkdir()
    (world.etc / "ssh" / "conf.d").chmod(0o755)
    Path(world.jail).write_text("[sshd]\n")
    Path(world.dropin).write_text("PerSourceMaxStartups 5\n")
    for path in (world.jail, world.dropin):
        os.chmod(path, 0o644)

    assert world.plan(world.standard()) == {"pending": False, "steps": []}
    result = world.run(world.standard())

    assert result.returncode == 0
    assert json.loads(result.stdout)["status"] == "unchanged"
    assert not (world.state_dir / "state.json").exists()
    assert world.timers() == []


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda b: b.update(revert_after=59), "revert_after must be"),
        (lambda b: b.update(revert_after=True), "revert_after must be"),
        (lambda b: b["steps"][2].update(path="/etc/passwd"), "outside the managed set"),
        (lambda b: b["steps"][3].update(when=["s8"]), "only depend on earlier steps"),
        (lambda b: b["steps"].append(dict(b["steps"][0])), "unique"),
        (lambda b: b["files"].append(dict(b["files"][0])), "listed twice"),
        (lambda b: b["services"][1].update(files=["/etc/other"]), "not managed"),
        (lambda b: b.update(schema=2), "unknown schema"),
    ],
)
def test_a_malformed_bundle_is_refused_before_anything_runs(world: World, change: Any, message: str) -> None:
    bundle = world.standard()
    change(bundle)

    result = world.run(bundle)

    assert result.returncode == 3
    assert message in result.stderr
    assert not (world.state_dir / "state.json").exists()
    assert world.log() == []


def test_status_hides_the_callers(world: World) -> None:
    world.unit("ssh")
    assert world.run(world.standard()).returncode == 0
    assert world.confirm(1).returncode == 0

    shown = json.loads(world.tx("status").stdout)

    assert shown["status"] == "confirmed"
    assert "caller" not in shown
    assert "confirmed_by" not in shown
    assert "198.51.100" not in json.dumps(shown)
