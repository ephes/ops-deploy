# Run on the host as the Nyxmon user: ``python3 -I -c <this file> probe|apply``
# with NYXMON_DB_PATH and NYXMON_SERVICE_NAME in the environment. This is the
# "Upsert Nyxmon Logyard json-metrics checks" step of deploy-logyard-core.yml.
#
# ``apply`` reads the desired checks as JSON from stdin (they carry a
# password) and upserts them exactly as the playbook does. ``probe`` needs no
# secret: it prints whether the service exists and, for each of its checks,
# digests of the check name and of its type, url, interval and data (in the
# playbook's comparison form), so the deploy can tell "already current"
# without ever reading a password back.
import hashlib
import json
import os
import sqlite3
import sys

mode = sys.argv[1]
db_path = os.environ["NYXMON_DB_PATH"]
service_name = os.environ["NYXMON_SERVICE_NAME"]


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def normalized(raw):
    try:
        return json.dumps(json.loads(raw or "{}"), sort_keys=True)
    except json.JSONDecodeError:
        return raw or ""


conn = sqlite3.connect(db_path, timeout=10)
cur = conn.cursor()

if mode == "probe":
    cur.execute("SELECT id FROM service WHERE name = ?", (service_name,))
    row = cur.fetchone()
    print("service present" if row else "service absent")
    if row:
        cur.execute(
            "SELECT name, check_type, url, check_interval, data FROM health_check WHERE service_id = ?",
            (row[0],),
        )
        for name, check_type, url, interval, data in cur.fetchall():
            state = json.dumps([check_type, url, int(interval), normalized(data)])
            print("check", digest(name), digest(state))
    conn.close()
    sys.exit(0)

checks = json.load(sys.stdin)
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
    current_data_json = normalized(current_data)
    if (
        current_type != check_type
        or current_url != check_url
        or int(current_interval) != check_interval
        or current_data_json != desired_data_json
    ):
        cur.execute(
            """
            UPDATE health_check
            SET check_type = ?, url = ?, check_interval = ?, data = ?
            WHERE id = ?
            """,
            (check_type, check_url, check_interval, desired_data_json, check_id),
        )
        changed = True

conn.commit()
conn.close()
print("changed=true" if changed else "changed=false")
