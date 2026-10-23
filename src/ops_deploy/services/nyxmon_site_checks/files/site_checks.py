# Run on the host as the Nyxmon user: ``python3 -I -c <this file> check|apply``
# with NYXMON_DB_PATH and NYXMON_SERVICE_NAME in the environment and the checks
# on stdin, never in the environment or the arguments: check data can carry a
# monitor login. stdin is either a JSON list of checks ({name, check_type,
# url, check_interval, data}) or an object {"checks": [...], "remove": [...]}
# whose "remove" names checks of the service to delete.
#
# ``apply`` upserts the service row and its checks the way the private
# site-check provisioning playbooks do: a missing service or check is
# inserted (status 'idle', next_check_time, processing_started_at and
# disabled all 0); an existing check whose type, url, interval, data (as
# sorted JSON) or disabled flag differs is updated, re-enabled and reset to
# 'idle' with next_check_time and processing_started_at 0. Rows of checks
# that are neither listed nor named in "remove" are left alone. A missing
# service row is only inserted when there are checks to write.
#
# A check named in "remove" is deleted the way Nyxmon's dashboard deletes one
# (HealthCheck.delete()): its check_result and check_notification_state rows
# first, then the health_check row. The run refuses, before any write, when
# another table references health_check (a dependent this script does not
# know), or when a check to delete is claimed by an agent (status
# 'processing'), whose result write would otherwise outlive the check.
#
# ``check`` runs the same comparison on a read-only connection and writes
# nothing. Both print "changed=true" when an apply wrote something (or, in
# check mode, would), else "changed=false".
#
# Intended differences to the playbooks: umask 077 for any file SQLite
# creates (journal or WAL sidecars), BEGIN IMMEDIATE so the compare and the
# write see the same rows, and the database is opened with mode=rw (apply)
# or mode=ro (check), so a missing database is an error, never a new file.
import json
import os
import pathlib
import sqlite3
import sys

# The tables (and their column) that hold rows of a health check, as
# Nyxmon's models cascade them on delete.
DEPENDENTS = (("check_result", "health_check_id"), ("check_notification_state", "check_id"))

mode = sys.argv[1] if len(sys.argv) == 2 else ""
if mode not in ("check", "apply"):
    sys.exit("usage: site_checks.py check|apply")
apply = mode == "apply"

db_path = os.environ["NYXMON_DB_PATH"]
service_name = os.environ["NYXMON_SERVICE_NAME"]
payload = json.load(sys.stdin)
if isinstance(payload, list):
    checks = payload
    remove = []
else:
    checks = payload["checks"]
    remove = payload["remove"]
if not isinstance(checks, list) or not isinstance(remove, list) or not all(isinstance(n, str) for n in remove):
    sys.exit("stdin must hold a list of checks, or an object with the lists 'checks' and 'remove'")
if set(remove) & {check["name"] for check in checks}:
    sys.exit("a check must not be both listed and removed")

os.umask(0o077)
uri = pathlib.PurePosixPath(db_path).as_uri() + ("?mode=rw" if apply else "?mode=ro")
conn = sqlite3.connect(uri, uri=True, timeout=10)
cur = conn.cursor()
if apply:
    cur.execute("BEGIN IMMEDIATE")
changed = False

cur.execute("SELECT id FROM service WHERE name = ?", (service_name,))
row = cur.fetchone()
service_id = None if row is None else row[0]

doomed = []
if remove and service_id is not None:
    for name in remove:
        cur.execute(
            "SELECT id, status FROM health_check WHERE service_id = ? AND name = ? ORDER BY id",
            (service_id, name),
        )
        for check_id, status in cur.fetchall():
            if status == "processing":
                sys.exit(f"check {check_id} is being processed by an agent; nothing written, run again")
            doomed.append(check_id)

present = set()
if doomed:
    tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()]
    for table in tables:
        for fk in cur.execute("SELECT * FROM pragma_foreign_key_list(?)", (table,)).fetchall():
            if fk[2].lower() == "health_check":
                if (table, fk[3]) not in DEPENDENTS:
                    sys.exit(f"{table}.{fk[3]} references health_check; nothing written")
                present.add((table, fk[3]))
    changed = True
    if apply:
        for check_id in doomed:
            for table, column in DEPENDENTS:
                if (table, column) in present:
                    cur.execute(f"DELETE FROM {table} WHERE {column} = ?", (check_id,))
            cur.execute("DELETE FROM health_check WHERE id = ?", (check_id,))

if service_id is None and checks:
    changed = True
    if apply:
        cur.execute("INSERT INTO service (name) VALUES (?)", (service_name,))
        service_id = cur.lastrowid

for check in checks:
    check_name = check["name"]
    check_type = check["check_type"]
    check_url = check["url"]
    check_interval = int(check["check_interval"])
    desired_data_json = json.dumps(check["data"], sort_keys=True)

    existing = None
    if service_id is not None:
        cur.execute(
            """
            SELECT id, check_type, url, check_interval, data, disabled
            FROM health_check
            WHERE service_id = ? AND name = ?
            """,
            (service_id, check_name),
        )
        existing = cur.fetchone()

    if existing is None:
        changed = True
        if apply:
            cur.execute(
                """
                INSERT INTO health_check (
                    name, service_id, check_type, url, check_interval,
                    status, next_check_time, processing_started_at, disabled, data
                )
                VALUES (?, ?, ?, ?, ?, 'idle', 0, 0, 0, ?)
                """,
                (check_name, service_id, check_type, check_url, check_interval, desired_data_json),
            )
        continue

    check_id, current_type, current_url, current_interval, current_data, current_disabled = existing
    try:
        current_data_json = json.dumps(json.loads(current_data or "{}"), sort_keys=True)
    except json.JSONDecodeError:
        current_data_json = current_data or ""
    if (
        current_type != check_type
        or current_url != check_url
        or int(current_interval) != check_interval
        or current_data_json != desired_data_json
        or int(current_disabled) != 0
    ):
        changed = True
        if apply:
            cur.execute(
                """
                UPDATE health_check
                SET check_type = ?,
                    url = ?,
                    check_interval = ?,
                    data = ?,
                    disabled = 0,
                    status = 'idle',
                    next_check_time = 0,
                    processing_started_at = 0
                WHERE id = ?
                """,
                (check_type, check_url, check_interval, desired_data_json, check_id),
            )

if apply:
    conn.commit()
conn.close()
print("changed=true" if changed else "changed=false")
