"""Read-only state of the accounts, units, paths and databases a legacy retirement lists.

Runs on the host as root with ``python3 -I -B``; the request (JSON) is the
first argument. Prints one JSON document. Changes nothing.
"""

import grp
import json
import os
import pwd
import subprocess
import sys

UNIT_PROPERTIES = ("LoadState", "ActiveState", "UnitFileState", "FragmentPath", "DropInPaths")


def run(argv):
    return subprocess.run(argv, capture_output=True, text=True, timeout=120, cwd="/", check=False)


def exists_group(name):
    try:
        grp.getgrnam(name)
    except KeyError:
        return False
    return True


def group(name):
    try:
        entry = grp.getgrnam(name)
    except KeyError:
        return {"exists": False, "gid": None, "members": [], "primary_of": []}
    return {
        "exists": True,
        "gid": entry.gr_gid,
        "members": sorted(entry.gr_mem),
        "primary_of": sorted(user.pw_name for user in pwd.getpwall() if user.pw_gid == entry.gr_gid),
    }


def account(name):
    """The account, or what an interrupted removal left of it (home, mail spool, group)."""
    try:
        entry = pwd.getpwnam(name)
    except KeyError:
        entry = None
    home = entry.pw_dir if entry else "/home/" + name
    state = {
        "present": entry is not None,
        "uid": entry.pw_uid if entry else None,
        "home": home,
        "home_exists": os.path.isdir(home) and not os.path.islink(home),
        "home_link": os.path.islink(home),
        "mail": os.path.lexists("/var/mail/" + name),
        "group": exists_group(name),
        "processes": 0,
        "linger": os.path.lexists("/var/lib/systemd/linger/" + name),
        "crontab": os.path.lexists("/var/spool/cron/crontabs/" + name),
    }
    if entry is not None:
        state["processes"] = len(run(["ps", "-u", name, "-o", "pid="]).stdout.split())
    return state


def unit(name):
    argv = ["systemctl", "show", "--no-pager"]
    for prop in UNIT_PROPERTIES:
        argv += ["-p", prop]
    shown = run(argv + ["--", name])
    if shown.returncode != 0:
        raise SystemExit("systemctl show failed for " + name)
    values = dict(line.split("=", 1) for line in shown.stdout.splitlines() if "=" in line)
    state = {prop: values.get(prop, "") for prop in UNIT_PROPERTIES}
    state["file"] = os.path.lexists("/etc/systemd/system/" + name)
    state["dropin_dir"] = os.path.lexists("/etc/systemd/system/" + name + ".d")
    return state


def psql(sql):
    done = run(["runuser", "-u", "postgres", "--", "psql", "-XAtq", "-v", "ON_ERROR_STOP=1", "-d", "postgres", "-c", sql])
    if done.returncode != 0:
        raise SystemExit("psql failed")
    return [line for line in done.stdout.splitlines() if line]


def database(name, owner):
    # Names are validated identifiers ([a-z_][a-z0-9_]*), so literals are safe.
    exists = psql("SELECT 1 FROM pg_database WHERE datname = '" + name + "'") == ["1"]
    role = psql("SELECT 1 FROM pg_roles WHERE rolname = '" + owner + "'") == ["1"]
    connections = psql("SELECT count(*) FROM pg_stat_activity WHERE datname = '" + name + "'")
    others = psql(
        "SELECT d.datname FROM pg_database d JOIN pg_roles r ON r.oid = d.datdba "
        "WHERE r.rolname = '" + owner + "' AND d.datname <> '" + name + "' ORDER BY 1"
    )
    return {
        "exists": exists,
        "owner_exists": role,
        "connections": int(connections[0]) if connections else 0,
        "owner_other_databases": others,
    }


def main():
    request = json.loads(sys.argv[1])
    root = request["archive_dir"]
    postgres = bool(request["databases"]) and os.path.exists("/usr/bin/psql")
    try:
        pwd.getpwnam("postgres")
    except KeyError:
        postgres = False
    state = {
        "accounts": {name: account(name) for name in request["accounts"]},
        "units": {name: unit(name) for name in request["units"]},
        "groups": {name: group(name) for name in request["groups"]},
        "paths": {path: os.path.lexists(path) for path in request["paths"]},
        "archives": {name: os.path.isfile(os.path.join(root, name)) for name in request["archives"]},
        "postgres": postgres,
        "databases": {
            item["name"]: database(item["name"], item["owner"]) for item in request["databases"] if postgres
        },
    }
    print(json.dumps(state, sort_keys=True))


main()
