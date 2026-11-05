import json
import os
import sqlite3

db_path = os.environ["NYXMON_DB_PATH"]
service_name = os.environ["NYXMON_SERVICE_NAME"]
checks = json.loads(VALUES["_nyxmon_checks_json"])

conn = sqlite3.connect(db_path, timeout=10)
cur = conn.cursor()
changed = False

cur.execute("SELECT id FROM service WHERE name = ?", (service_name,))
row = cur.fetchone()
if row is None:
    cur.execute("INSERT INTO service (name) VALUES (?)", (service_name,))
    service_id = cur.lastrowid
    changed = True
else:
    service_id = row[0]

for check in checks:
    check_name = check["name"]
    check_type = check["check_type"]
    check_url = check["url"]
    check_interval = int(check["check_interval"])
    desired_data_json = json.dumps(check["data"], sort_keys=True)

    cur.execute(
        """
        SELECT id, check_type, url, check_interval, data
        FROM health_check
        WHERE service_id = ? AND name = ?
        """,
        (service_id, check_name),
    )
    existing = cur.fetchone()

    if existing is None:
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
        changed = True
        continue

    check_id, current_type, current_url, current_interval, current_data = existing
    try:
        current_data_json = json.dumps(
            json.loads(current_data or "{}"), sort_keys=True
        )
    except json.JSONDecodeError:
        current_data_json = current_data or ""
    if (
        current_type != check_type
        or current_url != check_url
        or int(current_interval) != check_interval
        or current_data_json != desired_data_json
    ):
        cur.execute(
            """
            UPDATE health_check
            SET check_type = ?, url = ?, check_interval = ?, data = ?, disabled = 0
            WHERE id = ?
            """,
            (check_type, check_url, check_interval, desired_data_json, check_id),
        )
        changed = True

conn.commit()
conn.close()
print("changed=true" if changed else "changed=false")
