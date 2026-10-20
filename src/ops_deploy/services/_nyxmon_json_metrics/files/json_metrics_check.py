# Run on the Nyxmon host as the Nyxmon user:
#
#   python3 -I -c <this file> guard DB_PATH
#   python3 -I -c <this file> probe|apply DB_PATH SERVICE_NAME CHECK_NAME
#
# A port of the shared json-metrics upsert of the private host monitoring
# playbooks (tasks/upsert-nyxmon-json-metrics-check.yml, json-metrics checks).
#
# ``guard`` is the task's database privacy requirement: DB_PATH is a regular
# file (not a symlink) owned by the user running this script with mode 0600,
# and so is every regular file next to it whose name starts with the
# database's name (journal, WAL and shm sidecars). ``probe`` and ``apply``
# check it too before they open the database.
#
# ``apply`` reads the desired check from stdin as JSON, {"check_interval": N,
# "data": {...}}: the data may hold a monitor login, so it never travels in
# argv or the environment. It upserts exactly as the task does: the service
# row is created when missing (more than one with the name is refused), the
# check (service, name; more than one is refused) is inserted with status
# 'idle', next_check_time, processing_started_at and disabled 0, or, when its
# type, url, interval, data (both sides as sorted JSON; stored data that is
# not JSON is compared as text) or disabled flag differs, updated, re-enabled
# and reset to 'idle' with next_check_time and processing_started_at 0. A
# check Nyxmon is processing right now is not updated: the run fails and is
# retried by the caller. The check's url is data["url"]. Prints
# "changed=true" when it wrote something, else "changed=false".
#
# ``probe`` writes nothing and needs no secret: on a read-only connection it
# prints "service absent", "check absent" or "check <digest>", the sha256 of
# the stored type, url, interval, data (in the comparison form above) and
# disabled flag, so the deploy can tell "already current" by comparing
# digests without the login ever being read back.
#
# The required columns are checked first, as the task does. Like the task,
# the upsert runs with umask 077 (a sidecar SQLite creates stays private),
# a 10 s busy timeout and BEGIN IMMEDIATE. Unlike the task, the database is
# opened by URI with mode=rw (apply) or mode=ro (probe), so a missing
# database is an error, never a new file.
import fnmatch
import hashlib
import json
import os
import pathlib
import sqlite3
import stat
import sys

CHECK_TYPE = "json-metrics"
REQUIRED_COLUMNS = {
    "service": {"id", "name"},
    "health_check": {
        "id",
        "name",
        "service_id",
        "check_type",
        "url",
        "check_interval",
        "status",
        "next_check_time",
        "processing_started_at",
        "disabled",
        "data",
    },
}


def guard(db_path):
    me = os.geteuid()
    try:
        info = os.lstat(db_path)
    except FileNotFoundError:
        sys.exit(f"Nyxmon database {db_path} not found: deploy Nyxmon first")
    if not stat.S_ISREG(info.st_mode) or info.st_uid != me or stat.S_IMODE(info.st_mode) != 0o600:
        sys.exit(
            f"Nyxmon DB must be a regular file owned by the Nyxmon user at {db_path} "
            "with mode 0600. Deploy Nyxmon first to activate its SQLite privacy policy."
        )
    folder, name = os.path.split(db_path)
    for entry in os.scandir(folder):
        if not fnmatch.fnmatchcase(entry.name, name + "*"):
            continue
        found = entry.stat(follow_symlinks=False)
        if not stat.S_ISREG(found.st_mode):
            continue
        if found.st_uid != me or stat.S_IMODE(found.st_mode) != 0o600:
            sys.exit(
                f"Nyxmon database file {entry.name} must be owned by the Nyxmon user with "
                "mode 0600. Deploy Nyxmon first to activate its SQLite privacy policy."
            )


def normalized(raw):
    try:
        return json.dumps(json.loads(raw or "{}"), sort_keys=True)
    except json.JSONDecodeError:
        return raw or ""


def digest(check_type, url, interval, data_json, disabled):
    state = json.dumps([check_type, url, int(interval), data_json, int(disabled)])
    return hashlib.sha256(state.encode()).hexdigest()


def connect(db_path, mode):
    uri = pathlib.PurePosixPath(db_path).as_uri() + "?mode=" + mode
    conn = sqlite3.connect(uri, uri=True, timeout=10, isolation_level=None)
    conn.execute("PRAGMA busy_timeout = 10000")
    cur = conn.cursor()
    for table, required in REQUIRED_COLUMNS.items():
        actual = {row[1] for row in cur.execute(f"PRAGMA table_info({table})")}
        missing = sorted(required - actual)
        if missing:
            sys.exit(f"Nyxmon table {table} lacks required columns: {missing}")
    return conn, cur


def service_id(cur, service_name):
    rows = cur.execute("SELECT id FROM service WHERE name = ?", (service_name,)).fetchall()
    if len(rows) > 1:
        sys.exit(f"ambiguous Nyxmon service name: {service_name}")
    return rows[0][0] if rows else None


def check_rows(cur, sid, check_name):
    rows = cur.execute(
        """
        SELECT id, check_type, url, check_interval, data, disabled,
               status, processing_started_at
        FROM health_check WHERE service_id = ? AND name = ?
        """,
        (sid, check_name),
    ).fetchall()
    if len(rows) > 1:
        sys.exit(f"ambiguous Nyxmon check name: {check_name}")
    return rows


def probe(cur, service_name, check_name):
    sid = service_id(cur, service_name)
    if sid is None:
        print("service absent")
        return
    rows = check_rows(cur, sid, check_name)
    if not rows:
        print("check absent")
        return
    _, check_type, url, interval, data, disabled, _, _ = rows[0]
    print("check", digest(check_type, url, interval, normalized(data), disabled))


def apply(cur, service_name, check_name, desired):
    check_interval = int(desired["check_interval"])
    desired_data = desired["data"]
    desired_data_json = json.dumps(desired_data, sort_keys=True)
    check_url = desired_data["url"]
    changed = False

    sid = service_id(cur, service_name)
    if sid is None:
        cur.execute("INSERT INTO service (name) VALUES (?)", (service_name,))
        sid = cur.lastrowid
        changed = True

    rows = check_rows(cur, sid, check_name)
    if not rows:
        cur.execute(
            """
            INSERT INTO health_check (
                name, service_id, check_type, url, check_interval,
                status, next_check_time, processing_started_at, disabled, data
            ) VALUES (?, ?, ?, ?, ?, 'idle', 0, 0, 0, ?)
            """,
            (check_name, sid, CHECK_TYPE, check_url, check_interval, desired_data_json),
        )
        return True

    check_id, current_type, current_url, current_interval, current_data, disabled, status, lease = rows[0]
    differs = (
        current_type != CHECK_TYPE
        or current_url != check_url
        or int(current_interval) != check_interval
        or normalized(current_data) != desired_data_json
        or int(disabled) != 0
    )
    if differs and status == "processing":
        sys.exit(f"Nyxmon check is currently processing with lease {lease}; retry after it becomes idle")
    if differs:
        cur.execute(
            """
            UPDATE health_check
            SET check_type = ?, url = ?, check_interval = ?, data = ?,
                disabled = 0, status = 'idle', next_check_time = 0,
                processing_started_at = 0
            WHERE id = ? AND status != 'processing'
            """,
            (CHECK_TYPE, check_url, check_interval, desired_data_json, check_id),
        )
        if cur.rowcount != 1:
            sys.exit("Nyxmon check lease changed during reconciliation")
        changed = True
    return changed


def main(argv):
    mode = argv[1] if len(argv) > 1 else ""
    if not ((mode == "guard" and len(argv) == 3) or (mode in ("probe", "apply") and len(argv) == 5)):
        sys.exit("usage: json_metrics_check.py guard DB_PATH | probe|apply DB_PATH SERVICE_NAME CHECK_NAME")
    db_path = argv[2]
    os.umask(0o077)
    guard(db_path)
    if mode == "guard":
        return
    service_name, check_name = argv[3], argv[4]
    if mode == "probe":
        conn, cur = connect(db_path, "ro")
        probe(cur, service_name, check_name)
        conn.close()
        return
    desired = json.load(sys.stdin)
    conn, cur = connect(db_path, "rw")
    cur.execute("BEGIN IMMEDIATE")
    changed = apply(cur, service_name, check_name, desired)
    cur.execute("COMMIT")
    conn.close()
    print("changed=true" if changed else "changed=false")


main(sys.argv)
