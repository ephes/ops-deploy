# Run by ``python3 -c`` as the nyxmon user. The playbook's "Upsert Nyxmon checks
# for weeknotes.home" step, plus a read-only "check" mode. The environment
# carries NYXMON_DB_PATH, NYXMON_SERVICE_NAME and NYXMON_MODE (check or apply);
# the checks arrive as JSON on stdin, never in the environment or the
# arguments. Prints "changed=true" when an apply wrote something (or, in check
# mode, would), else "changed=false".
import json
import os
import sqlite3
import sys

db_path = os.environ["NYXMON_DB_PATH"]
service_name = os.environ["NYXMON_SERVICE_NAME"]
checks = json.load(sys.stdin)
apply = os.environ["NYXMON_MODE"] == "apply"

if apply:
    conn = sqlite3.connect(db_path, timeout=10)
else:
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=10)
cur = conn.cursor()
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
    desired_data_json = json.dumps(check["data"], sort_keys=True)
    existing = None
    if service_id is not None:
        cur.execute(
            """
            SELECT id, check_type, url, check_interval, data, disabled
            FROM health_check
            WHERE service_id = ? AND name = ?
            """,
            (service_id, check["name"]),
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
                (
                    check["name"],
                    service_id,
                    check["check_type"],
                    check["url"],
                    int(check["check_interval"]),
                    desired_data_json,
                ),
            )
        continue

    check_id, current_type, current_url, current_interval, current_data, current_disabled = existing
    try:
        current_data_json = json.dumps(json.loads(current_data or "{}"), sort_keys=True)
    except json.JSONDecodeError:
        current_data_json = current_data or ""
    if (
        current_type != check["check_type"]
        or current_url != check["url"]
        or int(current_interval) != int(check["check_interval"])
        or current_data_json != desired_data_json
        or int(current_disabled) != 0
    ):
        changed = True
        if apply:
            cur.execute(
                """
                UPDATE health_check
                SET check_type = ?, url = ?, check_interval = ?, data = ?,
                    disabled = 0, status = 'idle', next_check_time = 0,
                    processing_started_at = 0
                WHERE id = ?
                """,
                (
                    check["check_type"],
                    check["url"],
                    int(check["check_interval"]),
                    desired_data_json,
                    check_id,
                ),
            )

if apply:
    conn.commit()
conn.close()
print("changed=true" if changed else "changed=false")
