"""Original hosted-supervisor stop; executor status effects are managed work.

Loaded with the shared observer and guards by the controller. Application status
may open a Journal and expire server authority; this is never a pure verifier.
No application output, launchctl environment or record contents are reported.
"""

import json
import math
import os
import pathlib
import plistlib
import re
import subprocess
import sys
import time
import types

from ops_daybook_guards import (
    RuntimeGuardError, StopState, require_stop_prerequisites, require_stop_ready, require_stop_window,
)
from ops_daybook_observer import NativeProbes, ObservationError, safe_file, store_count


class StopError(RuntimeError):
    pass


class NativeStop(NativeProbes):
    def __init__(self, data):
        super().__init__(data["config"])
        self.policy = data["stop_policy"]
        self.cfg = types.SimpleNamespace(**self.data)
        self.domain = "gui/" + str(self.account.pw_uid)
        self.service = self.domain + "/" + self.data["label"]

    def pids(self):
        result = self.run(["/usr/bin/pgrep", "-u", self.data["user"], "-f", "[o]perations serve"])
        if result.returncode not in {0, 1}:
            raise StopError("runtime_stop_process_probe_failed")
        values = result.stdout.decode().splitlines()
        if result.returncode == 1:
            return []
        if not values or any(not re.fullmatch(r"[1-9][0-9]*", value.strip()) for value in values):
            raise StopError("runtime_stop_process_probe_invalid")
        return [value.strip() for value in values]

    def label(self):
        loaded = self.run(["/bin/launchctl", "print", self.service])
        if loaded.returncode not in {0, 113}:
            raise StopError("runtime_stop_label_probe_failed")
        return loaded

    def snapshot(self):
        aqua = self.run(["/bin/launchctl", "print", self.domain]).returncode == 0
        label = self.label()
        listing = label.stdout.decode("utf-8", "replace")
        host = self.run([self.data["host_tmux"], "-L", self.data["host_socket"], "has-session",
                         "-t", "=" + self.data["host_session"]], user=True,
                        extra={"TMUX_TMPDIR": self.data["host_tmpdir"]})
        store_count(self.data["journal"], self.data["user"], "staff")
        halts = store_count(pathlib.Path(self.data["journal"]) / "halts", self.data["user"], "staff")
        deliveries = self.deliveries()
        return StopState(aqua, label.returncode == 0,
                         re.search(r"(?m)^\s*host-keep\s*$", listing) is not None,
                         bool(self.pids()), host.returncode == 0, True, halts, deliveries, ())

    def deliveries(self):
        return store_count(pathlib.Path(self.data["journal"]) / "deliveries", self.data["user"], "staff")

    def clock(self):
        if not self.policy["windows"]:
            return ""
        result = self.run(["/bin/date", "+%H:%M"], extra={"TZ": self.policy["timezone"]})
        return result.stdout.decode("utf-8", "replace").strip() if result.returncode == 0 else ""

    def window(self, running):
        require_stop_window(self.policy["windows"], self.policy["lead_minutes"], self.clock(), running=running)

    def source(self, binding):
        # Original CLI executes as the GUI account using its existing resources.
        # Its own network/application bounds are retained, without an invented
        # outer whole-command deadline. Raw output is discarded after parsing.
        argv = [self.data["python"], "-I", "-c",
                "from daybook.cli import main; raise SystemExit(main())", "operations", "status",
                "--policy", self.data["policy"], "--policy-owner", self.data["owner"], "--binding", binding]
        if os.geteuid() != self.account.pw_uid:
            argv = ["/usr/bin/sudo", "-H", "-S", "-n", "-i", "-u", self.data["user"], "--", *argv]
        result = subprocess.run(argv, capture_output=True, env={
            **os.environ, "PYTHONDONTWRITEBYTECODE": "1",
        })
        if result.returncode:
            raise StopError("runtime_transition_status_unanswered")
        try:
            body = json.loads(result.stdout)
            active = body["server"]["active_state"]
            if active is not None and active not in {"pending", "assigned", "awaiting_apply", "needs_reconciliation", "failed"}:
                raise ValueError
        except (ValueError, KeyError, TypeError, RecursionError):
            raise StopError("runtime_transition_status_invalid") from None
        return types.SimpleNamespace(binding=binding, active_state=active)

    def bootout(self):
        result = self.run(["/bin/launchctl", "bootout", self.service])
        if result.returncode not in {0, 3, 113}:
            raise StopError("runtime_stop_bootout_failed")

    def unloaded(self):
        return self.label().returncode == 113

    def terminate(self):
        pids = self.pids()
        if pids:
            # Original graceful TERM only, to exactly the observed user PIDs.
            # A process that exits between look and signal is already stopped.
            self.run(["/bin/kill", "-TERM", *pids])

    def gone(self):
        return not self.pids()

    def session_gone(self):
        return self.run([self.data["host_tmux"], "-L", self.data["host_socket"], "has-session",
                         "-t", "=supervisor"], user=True,
                        extra={"TMUX_TMPDIR": self.data["host_tmpdir"]}).returncode != 0

    def drained(self):
        return self.deliveries() == 0 and store_count(
            pathlib.Path(self.data["journal"]) / "halts", self.data["user"], "staff") == 0

    def restore(self):
        # Only restore the keeper from the unchanged plist, never a legacy timer
        # or arbitrary command. Original rescue also applies when a supervisor
        # was serving without a loaded keeper initially; that is managed recovery,
        # not an assertion that the initial label state stays unchanged.
        # No source/profile write happened in this stage.
        resource = safe_file(self.data["plist"])
        try:
            args = plistlib.loads(resource[1])["ProgramArguments"] if resource else []
        except (ValueError, KeyError, TypeError):
            args = []
        if "host-keep" in args:
            self.run(["/bin/launchctl", "enable", self.service])
            self.run(["/bin/launchctl", "bootstrap", self.domain, self.data["plist"]])
        return self.wait(lambda: not self.unloaded(), 6, self.data["poll_delay"])

    def wait(self, predicate, retries, delay):
        for attempt in range(retries + 1):
            if predicate():
                return True
            if attempt < retries:
                time.sleep(delay)
        return False


def stop(driver):
    state = driver.snapshot()
    require_stop_prerequisites(driver.cfg, state)
    driver.window(state.running)
    retries = driver.cfg.quiet_retries if state.running else 0
    if not driver.wait(lambda: driver.deliveries() == 0, retries, driver.cfg.quiet_delay):
        raise StopError("runtime_machine_holds_work")
    sources = []
    for binding in driver.cfg.status_sources:
        latest = None
        def answered_idle():
            nonlocal latest
            latest = driver.source(binding)
            return latest.active_state not in {"assigned", "awaiting_apply"}
        if not driver.wait(answered_idle, retries, driver.cfg.quiet_delay):
            raise StopError("runtime_machine_holds_work")
        sources.append(latest)
    # Observe again after waits and reject newly arrived work/halts or lost host.
    state = driver.snapshot()
    state = StopState(state.aqua, state.label_loaded, state.label_runs_keeper, state.serving,
                      state.capability_host, state.store_readable, state.halts, state.deliveries, tuple(sources))
    require_stop_ready(driver.cfg, state)
    driver.window(state.running)  # original second guard immediately before stop
    if not state.running:
        return {"stopped": True, "restored": False, "keeper_bootout": False}
    try:
        if state.label_loaded:
            driver.bootout()
        if not driver.wait(driver.unloaded, 12, driver.cfg.poll_delay):
            raise StopError("runtime_keeper_did_not_unload")
        driver.terminate()
        if not driver.wait(driver.gone, math.ceil(driver.cfg.stop_timeout / driver.cfg.poll_delay), driver.cfg.poll_delay):
            raise StopError("runtime_supervisor_did_not_exit")
        if not driver.wait(driver.session_gone, 6, driver.cfg.poll_delay):
            raise StopError("runtime_supervisor_session_remains")
        if not driver.drained():
            raise StopError("runtime_stopped_store_not_drained")
    except Exception:
        try:
            restored = driver.restore()
        except Exception:
            restored = False
        raise StopError("runtime_stop_failed_keeper_" + ("restored" if restored else "NOT_restored")) from None
    return {"stopped": True, "restored": False, "keeper_bootout": state.label_loaded}


def main():
    try:
        raw = sys.stdin.buffer.read(8 * 1024 * 1024 + 1)
        if len(raw) > 8 * 1024 * 1024:
            raise StopError("runtime_stop_request_too_large")
        data = json.loads(raw)
        print(json.dumps(stop(NativeStop(data)), sort_keys=True))
    except (RuntimeGuardError, ObservationError, StopError, ValueError, KeyError, TypeError, OSError, RecursionError) as error:
        # Fixed category only. No raw child/profile/store/credential body.
        message = str(error) if isinstance(error, (RuntimeGuardError, ObservationError, StopError)) else "runtime_stop_failed"
        print(message, file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
