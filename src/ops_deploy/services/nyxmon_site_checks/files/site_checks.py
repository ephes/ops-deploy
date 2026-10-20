# Run on the host as the Nyxmon user: ``python3 -I -c <this file> check|apply``
# with NYXMON_DB_PATH, NYXMON_SERVICE_NAME and NYXMON_CHECKS_JSON (a list of
# {name, check_type, url, check_interval, data}) in the environment.
#
# ``apply`` upserts the service row and its checks the way the private
# site-check provisioning playbooks do: a missing service or check is
# inserted (status 'idle', next_check_time, processing_started_at and
# disabled all 0); an existing check whose type, url, interval, data (as
# sorted JSON) or disabled flag differs is updated, re-enabled and reset to
# 'idle' with next_check_time and processing_started_at 0. Rows of checks
# that are not listed are left alone. ``check`` runs the same comparison on a
# read-only connection and writes nothing. Both print "changed=true" when an
# apply wrote something (or, in check mode, would), else "changed=false".
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

mode = sys.argv[1] if len(sys.argv) == 2 else ""
if mode not in ("check", "apply"):
    sys.exit("usage: site_checks.py check|apply")
apply = mode == "apply"

db_path = os.environ["NYXMON_DB_PATH"]
service_name = os.environ["NYXMON_SERVICE_NAME"]
checks = json.loads(os.environ["NYXMON_CHECKS_JSON"])

os.umask(0o077)
uri = pathlib.PurePosixPath(db_path).as_uri() + ("?mode=rw" if apply else "?mode=ro")
conn = sqlite3.connect(uri, uri=True, timeout=10)
cur = conn.cursor()
if apply:
    cur.execute("BEGIN IMMEDIATE")
changed = False

cur.execute("SELECT id FROM service WHERE name = ?", (service_name,))
row = cur.fetchone()
if row is None:
    changed = True
    service_id = None
    if apply:
        cur.execute("INSERT INTO service (name) VALUES (?)", (service_name,))
        service_id = cur.lastrowid
else:
    service_id = row[0]

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
