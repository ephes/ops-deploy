"""DNS removal metadata and named Ansible cron cleanup; no credential/body output."""

from __future__ import annotations

import json
import os
import pwd
import shutil
import subprocess
import sys

CRON_NAMES = ("Pi-hole gravity update", "Pi-hole flush logs", "Unbound root hints update")
UFW_RULES = ("53/tcp", "53/udp", "4711/tcp", "5335/tcp", "5335/udp")


def run(argv):
    return subprocess.run(argv, capture_output=True, text=True, env={**os.environ, "LC_ALL": "C"}, timeout=40)


def cron():
    if not shutil.which("crontab"):
        return "unavailable", ""
    result = run(["crontab", "-u", "root", "-l"])
    if result.returncode == 0:
        return "ok", result.stdout
    if result.returncode == 1 and not result.stdout and "no crontab for root" in result.stderr.lower():
        return "ok", ""
    return "error", ""


def selected_cron(body):
    return [name for name in CRON_NAMES if "#Ansible: " + name in body.splitlines()]


def without_selected(body):
    lines = body.splitlines(keepends=True)
    answer = []
    skip = False
    for line in lines:
        if skip:
            skip = False
            continue
        if line.rstrip("\r\n") in {"#Ansible: " + name for name in CRON_NAMES}:
            skip = True
            continue
        answer.append(line)
    return "".join(answer)


def snapshot(request):
    paths = {}
    for path in request["paths"]:
        try:
            value = os.lstat(path)
        except FileNotFoundError:
            paths[path] = None
        else:
            paths[path] = {"mode": value.st_mode, "uid": value.st_uid, "gid": value.st_gid}
    units = {}
    for unit in request["units"]:
        result = run(
            [
                "systemctl",
                "show",
                "--property",
                "LoadState",
                "--property",
                "ActiveState",
                "--property",
                "UnitFileState",
                "--",
                unit,
            ]
        )
        values = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
        if (
            (result.returncode and values.get("LoadState") != "not-found")
            or not values.get("LoadState")
            or not values.get("ActiveState")
        ):
            units[unit] = {"metadata_status": "error"}
        else:
            units[unit] = {"metadata_status": "ok", **values}
    try:
        pwd.getpwnam("ddns")
    except KeyError:
        account = "absent"
    except OSError:
        account = "unknown"
    else:
        account = "present"
    package = run(["dpkg-query", "-W", "-f=${db:Status-Status}", "unbound"])
    if package.returncode == 0 and package.stdout.strip() in {
        "installed",
        "config-files",
        "not-installed",
        "unpacked",
        "half-installed",
        "half-configured",
        "triggers-awaited",
        "triggers-pending",
    }:
        package_state = package.stdout.strip()
    elif package.returncode == 1 and not package.stdout and "no packages found matching unbound" in package.stderr:
        package_state = "not-installed"
    else:
        raise RuntimeError("Unbound package state could not be established")
    if shutil.which("ufw"):
        rules = run(["ufw", "show", "added"])
        if rules.returncode:
            ufw = {"status": "error", "selected": []}
        else:
            lines = rules.stdout.splitlines()
            ufw = {"status": "ok", "selected": [rule for rule in UFW_RULES if "ufw allow " + rule in lines]}
    else:
        ufw = {"status": "unavailable", "selected": []}
    cron_status, cron_body = cron()
    return {
        "paths": paths,
        "units": units,
        "account": account,
        "package": package_state,
        "ufw": ufw,
        "cron": {"status": cron_status, "selected": selected_cron(cron_body)},
    }


def clean_cron():
    status, body = cron()
    if status != "ok":
        raise RuntimeError("Optional root cron cleanup unavailable")
    wanted = without_selected(body)
    if wanted != body:
        # Crontab bodies stay inside this short-lived host process and stdin.
        result = subprocess.run(
            ["crontab", "-u", "root", "-"], input=wanted, text=True, capture_output=True, timeout=40
        )
        if result.returncode:
            raise RuntimeError("Optional root cron cleanup failed")
    return {"changed": wanted != body}


def main():
    request = json.load(sys.stdin)
    if sys.argv[1] == "snapshot":
        value = snapshot(request)
    elif sys.argv[1] == "clean-cron":
        value = clean_cron()
    else:
        raise ValueError("Unknown DNS removal action")
    print(json.dumps(value))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # No command output, cron body, credential or traceback is exported.
        print("DNS removal helper failed: " + type(error).__name__, file=sys.stderr)
        raise SystemExit(1) from None
