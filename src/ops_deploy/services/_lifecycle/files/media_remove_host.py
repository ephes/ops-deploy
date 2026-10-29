"""Targeted metadata only; account deletion uses shadow-utils and exact names."""

from __future__ import annotations

import grp
import json
import os
import pwd
import subprocess
import sys

PACKAGES = ("jellyfin", "jellyfin-ffmpeg6", "jellyfin-ffmpeg5", "jellyfin-ffmpeg")


def user_entry(name):
    if name is None:
        return None
    try:
        value = pwd.getpwnam(name)
    except KeyError:
        return None
    return {"uid": value.pw_uid, "gid": value.pw_gid, "home": value.pw_dir}


def group_entry(name):
    if name is None:
        return None
    try:
        return grp.getgrnam(name).gr_gid
    except KeyError:
        return None


def selected_packages():
    result = subprocess.run(["dpkg-query", "-W", "-f=${Package}\t${db:Status-Status}\n", "--", *PACKAGES],
        capture_output=True, text=True, check=False, env={**os.environ, "LC_ALL": "C"})
    if result.returncode not in (0, 1):
        raise RuntimeError("Cannot establish selected Jellyfin package state")
    selected = []
    seen = set()
    statuses = {"installed", "config-files", "half-installed", "unpacked", "half-configured", "triggers-awaited", "triggers-pending"}
    for line in result.stdout.splitlines():
        package, package_state = line.split("\t")
        if package not in PACKAGES or package_state not in statuses | {"not-installed"}:
            raise RuntimeError("Unexpected selected package metadata")
        if package in seen:
            raise RuntimeError("Duplicate selected package metadata")
        seen.add(package)
        if package_state in statuses:
            selected.append(package)
    missing = set()
    for line in result.stderr.splitlines():
        prefix = "dpkg-query: no packages found matching "
        if not line.startswith(prefix) or line[len(prefix):] not in PACKAGES:
            raise RuntimeError("Cannot establish selected Jellyfin package state")
        missing.add(line[len(prefix):])
    if seen & missing or seen | missing != set(PACKAGES) or bool(missing) != (result.returncode == 1):
        raise RuntimeError("Incomplete selected Jellyfin package metadata")
    return selected


def inspect(request):
    paths = {}
    for path in request["paths"]:
        try:
            value = os.lstat(path)
        except FileNotFoundError:
            paths[path] = None
        else:
            paths[path] = {"mode": value.st_mode, "uid": value.st_uid, "gid": value.st_gid}
    return {"paths": paths, "user": user_entry(request["user"]), "group": group_entry(request["group"]),
        "packages": selected_packages() if request["packages"] else []}


def accounts(request):
    if user_entry(request["user"]) is not None:
        subprocess.run(["userdel", "--remove", "--", request["user"]], check=True)
    # userdel can remove the private group itself; inspect again rather than
    # attempting groupdel on the pre-plan snapshot.
    if group_entry(request["group"]) is not None:
        subprocess.run(["groupdel", "--", request["group"]], check=True)


if __name__ == "__main__":
    payload = json.load(sys.stdin)
    if sys.argv[1] == "inspect":
        print(json.dumps(inspect(payload)))
    elif sys.argv[1] == "accounts":
        accounts(payload)
    else:
        raise ValueError("Unknown selected media removal action")
