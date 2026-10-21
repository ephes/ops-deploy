"""Verify one metrics-httpd endpoint unit after its implementation switch.

The host side of ops-library's ``metrics_httpd_switch`` ``tasks_from: verify``
(``rust/metrics-httpd/PLAN.md`` 7.2), run by ops-deploy as root with
``/usr/bin/python3 -I -`` and this script on stdin (standard library only):

1. up to ``--retries`` reads ``--delay`` seconds apart: the unit is active,
   its ``MainPID`` is not 0, and the process runs the selected implementation:
   ``rust``: ``/proc/<pid>/exe`` is ``--binary`` or its ``realpath``;
   ``python``: ``/proc/<pid>/cmdline`` holds ``--python-script`` as a word;
2. unless ``--no-probe``: an unauthenticated ``GET http://<host>:<port><path>``
   (no proxy, no redirect, no credentials), retried the same way, must answer
   ``unauthorized``: 401 with ``WWW-Authenticate: Basic realm="<realm>"``;
   ``logyard-health``: 200 with a JSON object holding ``status``;
   ``static``: 200.

Prints ``ok ...`` and exits 0, or prints what it saw to stderr and exits 1
(the deploy stops before any pin moves or anything is pruned). Reads nothing
secret and sends no credentials.
"""

import argparse
import http.client
import json
import os
import subprocess
import sys
import time


def live(args):
    """The unit's state, MainPID, executable and command line words."""

    def systemctl(*words):
        result = subprocess.run(
            [args.systemctl, *words], capture_output=True, text=True, timeout=30, check=False
        )
        return result.stdout.strip()

    state = systemctl("is-active", args.unit)
    pid = systemctl("show", "--property=MainPID", "--value", args.unit)
    exe, words = "", []
    if pid.isdigit() and int(pid) > 0:
        try:
            exe = os.readlink(os.path.join(args.proc_root, pid, "exe"))
        except OSError:
            pass
        try:
            with open(os.path.join(args.proc_root, pid, "cmdline"), "rb") as handle:
                raw = handle.read()
            words = [w.decode("utf-8", "replace") for w in raw.split(b"\0") if w]
        except OSError:
            pass
    return {"state": state, "pid": pid, "exe": exe, "words": words}


def wanted(args):
    """The executables that count as the selected Rust binary."""

    if not args.binary or not os.path.exists(args.binary):
        return set()
    return {args.binary, os.path.realpath(args.binary)}


def runs_selected(args, seen):
    if seen["state"] != "active":
        return False
    if args.impl == "rust":
        return seen["exe"] in wanted(args)
    return args.python_script in seen["words"]


def answer(args):
    """Status, WWW-Authenticate and body of one unauthenticated GET, or an error text."""

    connection = http.client.HTTPConnection(args.host, args.port, timeout=args.timeout)
    try:
        connection.request("GET", args.path, headers={"Connection": "close"})
        response = connection.getresponse()
        body = response.read()
        return response.status, response.getheader("WWW-Authenticate") or "", body, ""
    except (OSError, http.client.HTTPException) as error:
        return None, "", b"", f"{type(error).__name__}: {error}"
    finally:
        connection.close()


def answer_ok(args, status, authenticate, body):
    if args.expect == "unauthorized":
        return status == 401 and authenticate == f'Basic realm="{args.realm}"'
    if args.expect == "logyard-health":
        if status != 200:
            return False
        try:
            document = json.loads(body)
        except ValueError:
            return False
        return isinstance(document, dict) and "status" in document
    return status == 200


EXPECTED = {
    "unauthorized": '401 with WWW-Authenticate: Basic realm="{realm}"',
    "logyard-health": "200 with a JSON object holding status",
    "static": "200",
}


def main(argv):
    parser = argparse.ArgumentParser(prog="metrics-httpd-verify")
    parser.add_argument("--unit", required=True)
    parser.add_argument("--impl", choices=("python", "rust"), required=True)
    parser.add_argument("--binary", default="")
    parser.add_argument("--python-script", default="")
    parser.add_argument("--no-probe", action="store_true")
    parser.add_argument("--host", default="")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--path", default="/")
    parser.add_argument("--expect", choices=tuple(EXPECTED), default="unauthorized")
    parser.add_argument("--realm", default="")
    parser.add_argument("--timeout", type=float, default=5)
    parser.add_argument("--retries", type=int, default=15)
    parser.add_argument("--delay", type=float, default=2)
    # Test knobs; production keeps the defaults.
    parser.add_argument("--systemctl", default="systemctl")
    parser.add_argument("--proc-root", default="/proc")
    args = parser.parse_args(argv)

    attempts = args.retries + 1
    for attempt in range(attempts):
        seen = live(args)
        if runs_selected(args, seen):
            break
        if attempt + 1 < attempts:
            time.sleep(args.delay)
    else:
        expected = (
            f"/proc/<pid>/exe = {args.binary}"
            if args.impl == "rust"
            else f"a command line with {args.python_script}"
        )
        print(
            f"{args.unit}.service does not run the selected implementation (impl {args.impl}; "
            f"expected {expected}). Nothing was pinned or pruned. Live state: state={seen['state']} "
            f"pid={seen['pid']} exe={seen['exe']} args={' '.join(seen['words'])}",
            file=sys.stderr,
        )
        return 1

    if args.no_probe:
        print(f"ok {args.unit} runs impl {args.impl} (exe {seen['exe']}); probe skipped")
        return 0

    url = f"http://{args.host if ':' not in args.host else '[' + args.host + ']'}:{args.port}{args.path}"
    for attempt in range(attempts):
        status, authenticate, body, error = answer(args)
        if answer_ok(args, status, authenticate, body):
            print(f"ok {args.unit} runs impl {args.impl} (exe {seen['exe']}); GET {url} answered {status}")
            return 0
        if attempt + 1 < attempts:
            time.sleep(args.delay)
    detail = error or f"status {status}"
    if args.expect == "unauthorized" and not error:
        detail += f" with WWW-Authenticate {authenticate or '(none)'}"
    print(
        f"GET {url} (no credentials) answered {detail}; expected "
        f"{EXPECTED[args.expect].format(realm=args.realm)}. Nothing was pinned or pruned.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
