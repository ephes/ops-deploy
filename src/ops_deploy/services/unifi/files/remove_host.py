"""Host side of the UniFi removal; stdout carries a status or package names only.

``packages NAME...``: the names dpkg knows in any state but not-installed
(the apt module's ``installed or has config files`` with ``purge: true``),
as a JSON list. ``mongo`` (payload on stdin): the role's authenticated
mongosh script for ``drop-database`` or ``drop-user``, through a private
temporary HOME; credentials never reach argv or output.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

STATES = {"installed", "config-files", "half-installed", "unpacked", "half-configured", "triggers-awaited", "triggers-pending"}


def packages(names):
    result = subprocess.run(["dpkg-query", "-W", "-f=${Package}\t${db:Status-Status}\n", "--", *names],
        capture_output=True, text=True, check=False, env={**os.environ, "LC_ALL": "C"}, timeout=60)
    if result.returncode not in (0, 1):
        raise RuntimeError("dpkg-query failed")
    selected, seen, missing = [], set(), set()
    for line in result.stdout.splitlines():
        package, state = line.split("\t")
        if package not in names or package in seen or state not in STATES | {"not-installed"}:
            raise RuntimeError("unexpected package metadata")
        seen.add(package)
        if state in STATES:
            selected.append(package)
    prefix = "dpkg-query: no packages found matching "
    for line in result.stderr.splitlines():
        if not line.startswith(prefix) or line[len(prefix):] not in names:
            raise RuntimeError("unexpected dpkg-query output")
        missing.add(line[len(prefix):])
    if seen & missing or seen | missing != set(names) or bool(missing) != (result.returncode == 1):
        raise RuntimeError("incomplete package metadata")
    return selected


def script(payload):
    # The role's task-mongosh.js.j2 with its task_mongo_script, JSON-encoded.
    auth_db = json.dumps(payload["auth_db"])
    if payload["action"] == "drop-database":
        command = f"printjson(db.getSiblingDB({json.dumps(payload['database'])}).dropDatabase());"
    elif payload["action"] == "drop-user":
        command = f"printjson(db.getSiblingDB({auth_db}).dropUser({json.dumps(payload['user'])}));"
    else:
        raise ValueError("unknown action")
    return (
        f"const authDb = db.getSiblingDB({auth_db});\n"
        f"if (!authDb.auth({json.dumps(payload['user'])}, {json.dumps(payload['password'])})) {{ quit(1); }}\n"
        f"db = db.getSiblingDB({auth_db});\n"
        f"{command}\n"
    )


def mongo(payload):
    with tempfile.TemporaryDirectory(prefix="ops-unifi-remove-") as home:
        directory = Path(home) / ".mongodb" / "mongosh"
        directory.mkdir(parents=True, mode=0o700)
        descriptor = os.open(directory / "config", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            json.dump({"disableLogging": True, "enableTelemetry": False, "updateURL": ""}, stream)
        result = subprocess.run(
            ["mongosh", "--quiet", "--norc", "--host", payload["host"], "--port", str(payload["port"]),
             "--file", "/dev/stdin"],
            input=script(payload), capture_output=True, text=True, timeout=120,
            env={"HOME": home, "PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        )
    return result.returncode == 0


if __name__ == "__main__":
    if sys.argv[1] == "packages":
        print(json.dumps(packages(sys.argv[2:])))
    elif sys.argv[1] == "mongo":
        # The role's task has failed_when: false; report, never fail, never echo.
        try:
            ok = mongo(json.load(sys.stdin))
        except Exception:
            ok = False
        print("done" if ok else "failed (ignored, as the role's failed_when: false)")
    else:
        raise ValueError("unknown action")
