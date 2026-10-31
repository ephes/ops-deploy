"""Check Home Assistant's unit before and after the managed UV_SYSTEM_CERTS=1 drop-in.

Run as root with the system interpreter: ``python3 -I -c <this> <options>``.
Reads systemd's own parsed view of the unit (``systemctl show``: Environment,
PassEnvironment, drop-ins, EnvironmentFiles, reload state), the service
manager environment (``systemctl show-environment``) and the running
service's ``/proc/<pid>/environ`` (NUL separated); it never parses unit files. It prints one
JSON object whose messages name keys and paths only, never values.

Trust settings are left to the operator: the managed drop-in is only allowed
next to no other trust configuration. Anything this script cannot account
for (an EnvironmentFile, another drop-in, a trust variable from any other
source) is a problem, so the caller fails closed.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess

TRUST_KEYS = (
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "UV_SYSTEM_CERTS",
    "UV_NATIVE_TLS",
    "UV_INSECURE_HOST",
)
MANAGED_KEY, MANAGED_VALUE = "UV_SYSTEM_CERTS", "1"
PROPERTIES = (
    "LoadState",
    "ActiveState",
    "NeedDaemonReload",
    "DropInPaths",
    "EnvironmentFiles",
    "Environment",
    "PassEnvironment",
    "MainPID",
)


def systemctl(*args):
    return subprocess.run(["systemctl", *args], check=True, capture_output=True, text=True).stdout


def show(unit):
    output = systemctl("show", unit, *("--property=" + name for name in PROPERTIES))
    values = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
    return {name: values.get(name, "") for name in PROPERTIES}


def assignments(text, separator):
    """Keys of KEY=VALUE items separated by ``separator`` (values never kept)."""
    return {item.split("=", 1)[0] for item in text.split(separator) if "=" in item}


def configured_trust_keys(environment, passed):
    # systemctl show prints Environment as space-separated, possibly quoted
    # KEY=VALUE items and PassEnvironment as names. A key is matched at the
    # start of an item; a value that merely contains one also matches, which
    # only refuses more.
    found = {key for key in TRUST_KEYS if re.search(r'(^|\s)"?' + key + "=", environment)}
    return found | (set(passed.split()) & set(TRUST_KEYS))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--unit", required=True)
    parser.add_argument("--dropin", required=True)
    parser.add_argument("--dropin-sha256", required=True)
    parser.add_argument("--mode", choices=("preflight", "verify"), required=True)
    parser.add_argument("--allow-missing-unit", action="store_true")
    # Drop-ins an operator reviewed as not touching trust (for example
    # distribution-wide service.d files); everything else is refused.
    parser.add_argument("--allow-dropin", action="append", default=[])
    parser.add_argument("--proc", default="/proc")
    args = parser.parse_args()

    problems = []
    state = show(args.unit)
    report = {"load_state": state["LoadState"], "active_state": state["ActiveState"]}

    # Independent of the unit: the managed path and the service manager.
    managed = False
    if os.path.lexists(args.dropin):
        with open(args.dropin, "rb") as handle:
            managed = hashlib.sha256(handle.read()).hexdigest() == args.dropin_sha256
        if not managed:
            problems.append("{} differs from the managed drop-in".format(args.dropin))
    report["managed_dropin"] = managed
    manager = assignments(systemctl("show-environment"), "\n") & set(TRUST_KEYS)
    if manager:
        problems.append("the service manager environment sets {}".format(", ".join(sorted(manager))))

    if state["LoadState"] != "loaded":
        if not (args.allow_missing_unit and state["LoadState"] == "not-found" and args.mode == "preflight"):
            problems.append("{} is {}".format(args.unit, state["LoadState"] or "unknown"))
        report["problems"] = problems
        print(json.dumps(report, sort_keys=True))
        return

    if state["NeedDaemonReload"] == "yes":
        problems.append("{} changed on disk since systemd loaded it; reload first".format(args.unit))
    if state["EnvironmentFiles"].strip():
        problems.append("{} reads an EnvironmentFile; trust precedence is uncertain".format(args.unit))
    unknown = [path for path in state["DropInPaths"].split() if path not in (args.dropin, *args.allow_dropin)]
    if unknown:
        problems.append("{} has other drop-ins: {}".format(args.unit, ", ".join(sorted(unknown))))
    configured = configured_trust_keys(state["Environment"], state["PassEnvironment"])
    if managed and args.dropin in state["DropInPaths"].split():
        # The managed drop-in's own line, as systemd parsed it.
        if re.search(r'(^|\s)"?' + MANAGED_KEY + "=(?!" + MANAGED_VALUE + r'(\s|"|$))', state["Environment"]) is None:
            configured.discard(MANAGED_KEY)
    if configured:
        problems.append("{} sets {}".format(args.unit, ", ".join(sorted(configured))))

    running = False
    pid = state["MainPID"].strip()
    if pid not in ("", "0"):
        try:
            with open(os.path.join(args.proc, pid, "environ"), "rb") as handle:
                items = handle.read().decode("utf-8", "replace").split("\0")
        except OSError as exc:
            problems.append("the running service's environment could not be read ({})".format(type(exc).__name__))
            items = []
        environ = {}
        for item in items:
            if "=" in item:
                key, value = item.split("=", 1)
                if key in TRUST_KEYS:
                    environ[key] = value
        running = environ.get(MANAGED_KEY) == MANAGED_VALUE
        other = sorted(key for key in environ if key != MANAGED_KEY)
        if other:
            problems.append("the running service has {}".format(", ".join(other)))
        if MANAGED_KEY in environ and not (running and managed):
            problems.append("the running service has {} without the managed drop-in".format(MANAGED_KEY))
    report["running_managed_value"] = running

    if args.mode == "verify":
        if state["ActiveState"] != "active" or pid in ("", "0"):
            problems.append("{} is not running".format(args.unit))
        elif not (running and managed):
            problems.append("the running service does not have the managed {}={}".format(MANAGED_KEY, MANAGED_VALUE))
    report["problems"] = problems
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
