#!/usr/bin/env python3
"""Lean measurements of the Rust and the Python guard (PLAN.md 8.3, S7).

Runs as root inside a Layer-3 container (``run-lean.sh``). For each
implementation and case it starts the guard ``--runs`` times (after one
warm-up run) the way sshd starts the forced command, waits for it with
``wait4`` and records

- the wall time from the spawn (``posix_spawn``) to the end of the process:
  for a refusal and ``--check-policy`` that is the guard alone; for the
  allowed command it includes the exec'd ``test -d`` (coreutils, well under
  a millisecond), so it is an upper bound of "start to exec";
- in separate runs, the peak RSS as GNU ``/usr/bin/time -f %M`` prints it
  (``ru_maxrss``), the method of the Python figure in PLAN.md 1.2. Not from
  this script's own ``wait4``: Linux carries the RSS high-water mark of the
  process image that calls ``execve`` into the new one, and a child spawned
  from this Python process starts with the interpreter's (about 12 MiB);
  GNU time is a small C program. For the allowed command the figure is the
  larger of the guard and the exec'd tool.

Every run's outcome is checked (exit status and stderr), so a measurement is
never of a different path. A syslog receiver on ``/dev/log`` takes the log
lines, as journald does on the hosts. The medians are compared with the
budgets of PLAN.md 8.3 for the Rust guard: stripped binary <= 2 MiB, peak RSS
<= 4 MiB (``--check-policy`` and the refusal), wall time <= 5 ms (all three
cases). Any budget exceeded, or any run with an unexpected outcome, exits 1.
Prints a Markdown report on stdout. Stdlib only.
"""

from __future__ import annotations

import argparse
import os
import platform
import socket
import statistics
import sys
import tempfile
import threading
import time

TIME = "/usr/bin/time"
MIB = 1024 * 1024
BUDGET_BINARY = 2 * MIB
BUDGET_RSS_KIB = 4 * 1024
BUDGET_WALL_MS = 5.0
PROGRAM = "echoport-remote-command-guard"
ALLOWED_DIR = "/var/lib/gotosocial/storage"
# A documentation address (RFC 5737), as in the other harnesses.
SSH_CLIENT = "192.0.2.10 50022 22"
BASE_ENV = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "HOME": "/root",
    "USER": "root",
    "LOGNAME": "root",
    "SHELL": "/bin/bash",
}


class SyslogSink:
    """/dev/log as a datagram socket that drops every record."""

    def __init__(self) -> None:
        if os.path.lexists("/dev/log"):
            os.unlink("/dev/log")
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.sock.bind("/dev/log")
        os.chmod("/dev/log", 0o666)
        threading.Thread(target=self.loop, daemon=True).start()

    def loop(self) -> None:
        while True:
            self.sock.recv(65536)


def run_once(argv: list[str], env: dict[str, str]) -> tuple[float, int, bytes]:
    """Spawn, wait; return (wall ms, exit status, stderr)."""
    with tempfile.TemporaryFile() as err, open(os.devnull, "rb") as null_in, open(os.devnull, "wb") as null_out:
        actions = [
            (os.POSIX_SPAWN_DUP2, null_in.fileno(), 0),
            (os.POSIX_SPAWN_DUP2, null_out.fileno(), 1),
            (os.POSIX_SPAWN_DUP2, err.fileno(), 2),
        ]
        start = time.perf_counter()
        pid = os.posix_spawn(argv[0], argv, env, file_actions=actions)
        _, status = os.waitpid(pid, 0)
        wall = (time.perf_counter() - start) * 1000.0
        err.seek(0)
        return wall, os.waitstatus_to_exitcode(status), err.read()


def peak_rss_once(argv: list[str], env: dict[str, str]) -> tuple[int, int, bytes]:
    """Run under GNU time; return (peak RSS KiB, exit status, stderr)."""
    with tempfile.NamedTemporaryFile("r") as report:
        _, status, stderr = run_once([TIME, "--quiet", "-f", "%M", "-o", report.name, *argv], env)
        return int(report.read().split()[-1]), status, stderr


def cases(args: argparse.Namespace) -> list[tuple[str, str, list[str], dict[str, str], int, bytes]]:
    """(impl, case, argv, env, expected exit status, expected stderr)."""
    policy = os.path.join(args.policies, "production.json")
    impls = {
        "python": ["/usr/bin/python3", "-I", args.guard],
        "rust": [args.binary],
    }
    refused = f"{PROGRAM}: command not allowed\n".encode()
    out = []
    for impl, prefix in impls.items():
        out.append((impl, "--check-policy", prefix + ["--check-policy", policy], dict(BASE_ENV), 0, b""))
        for case, command, status, stderr in (
            ("refusal (`id`)", "id", 1, refused),
            (f"allowed (`test -d {ALLOWED_DIR}`)", f"test -d {ALLOWED_DIR}", 0, b""),
        ):
            env = dict(BASE_ENV, SSH_ORIGINAL_COMMAND=command, SSH_CLIENT=SSH_CLIENT,
                       SSH_CONNECTION=f"{SSH_CLIENT.split()[0]} 50022 127.0.0.1 22")
            out.append((impl, case, prefix + [policy], env, status, stderr))
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--guard", required=True, help="the Python guard")
    parser.add_argument("--binary", required=True, help="the Rust guard binary")
    parser.add_argument("--policies", required=True, help="directory with production.json")
    parser.add_argument("--runs", type=int, default=20)
    args = parser.parse_args()
    if os.geteuid() != 0:
        print("lean.py runs as root (the forced command runs as root)", file=sys.stderr)
        return 2

    SyslogSink()
    os.makedirs(ALLOWED_DIR, exist_ok=True)

    failures: list[str] = []
    os_release = dict(
        line.rstrip("\n").split("=", 1) for line in open("/etc/os-release", encoding="utf-8") if "=" in line
    )
    size = os.stat(args.binary).st_size
    print(f"#### {os_release.get('PRETTY_NAME', '?').strip(chr(34))} ({platform.machine()}), "
          f"Python {platform.python_version()}, {args.runs} runs per case (median, min-max)")
    print()
    print(f"Rust binary (this container's release build, stripped): {size:,} bytes "
          f"({size / MIB:.2f} MiB; budget 2 MiB)")
    print()
    if size > BUDGET_BINARY:
        failures.append(f"binary {size} bytes > {BUDGET_BINARY}")
    print("| Guard | Case | Wall time ms | Peak RSS MiB |")
    print("|---|---|---|---|")
    for impl, case, argv, env, want_status, want_stderr in cases(args):
        walls: list[float] = []
        rsss: list[int] = []
        for index in range(args.runs + 1):
            wall, status, stderr = run_once(argv, env)
            rss, rss_status, rss_stderr = peak_rss_once(argv, env)
            if (status, stderr) != (want_status, want_stderr) or (rss_status, rss_stderr) != (want_status, want_stderr):
                failures.append(f"{impl} {case}: exit {status}/{rss_status}, stderr {stderr!r}/{rss_stderr!r}")
                break
            if index:  # the first run warms the page cache
                walls.append(wall)
                rsss.append(rss)
        if len(walls) != args.runs:
            continue
        wall_med = statistics.median(walls)
        rss_med = statistics.median(rsss)
        print(f"| {impl} | {case} | {wall_med:.2f} ({min(walls):.2f}-{max(walls):.2f}) "
              f"| {rss_med / 1024:.2f} ({min(rsss) / 1024:.2f}-{max(rsss) / 1024:.2f}) |")
        if impl == "rust":
            if wall_med > BUDGET_WALL_MS:
                failures.append(f"rust {case}: median wall {wall_med:.2f} ms > {BUDGET_WALL_MS} ms")
            if not case.startswith("allowed") and rss_med > BUDGET_RSS_KIB:
                failures.append(f"rust {case}: median peak RSS {rss_med} KiB > {BUDGET_RSS_KIB} KiB")
    print()
    if failures:
        print("**Over budget or unexpected outcome:**")
        for failure in failures:
            print(f"- {failure}")
        print()
        return 1
    print("Within the PLAN.md 8.3 budgets (Rust: binary <= 2 MiB, peak RSS <= 4 MiB, wall time <= 5 ms).")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
