import json
import os
import sqlite3

db_path = os.environ["NYXMON_DB_PATH"]
service_name = os.environ["NYXMON_SERVICE_NAME"]
checks = json.loads(VALUES["_nyxmon_checks_json"])
declaration_state = os.environ["DECLARATION_STATE"]
allow_reenable = json.loads(os.environ["ALLOW_REENABLE"])

conn = sqlite3.connect(db_path, timeout=10)
cur = conn.cursor()
changed = False

required_columns = {
    "service": {"id", "name"},
    "health_check": {
        "id", "name", "service_id", "check_type", "url",
        "check_interval", "status", "next_check_time",
        "processing_started_at", "disabled", "data",
    },
}
for table, required in required_columns.items():
    table_info = list(cur.execute(f"PRAGMA table_info({table})"))
    actual = {row[1] for row in table_info}
    missing = sorted(required - actual)
    if missing:
        raise RuntimeError(
            f"Nyxmon table {table} lacks required columns: {missing}"
        )

def assert_insert_compatible(table, supplied):
    table_info = list(cur.execute(f"PRAGMA table_info({table})"))
    unsupported_required = sorted(
        row[1]
        for row in table_info
        if row[3]
        and row[4] is None
        and not row[5]
        and row[1] not in supplied
    )
    if unsupported_required:
        raise RuntimeError(
            f"Nyxmon table {table} has unsupported required insert "
            f"columns: {unsupported_required}"
        )

cur.execute("SELECT id FROM service WHERE name = ?", (service_name,))
row = cur.fetchone()
if row is None:
    assert_insert_compatible("service", {"name"})
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
        SELECT id, check_type, url, check_interval, data, disabled
        FROM health_check
        WHERE service_id = ? AND name = ?
        """,
        (service_id, check_name),
    )
    existing = cur.fetchone()

    if existing is None:
        assert_insert_compatible(
            "health_check",
            {
                "name", "service_id", "check_type", "url",
                "check_interval", "status", "next_check_time",
                "processing_started_at", "disabled", "data",
            },
        )
        insert_disabled = 1 if declaration_state == "retired" else 0
        cur.execute(
            """
            INSERT INTO health_check (
                name, service_id, check_type, url, check_interval,
                status, next_check_time, processing_started_at,
                disabled, data
            )
            VALUES (?, ?, ?, ?, ?, 'idle', 0, 0, ?, ?)
            """,
            (
                check_name,
                service_id,
                check_type,
                check_url,
                check_interval,
                insert_disabled,
                desired_data_json,
            ),
        )
        changed = True
        continue

    (
        check_id,
        current_type,
        current_url,
        current_interval,
        current_data,
        current_disabled,
    ) = existing
    if (
        declaration_state == "present"
        and int(current_disabled)
        and not allow_reenable
    ):
        raise RuntimeError(
            "Vaultwarden backup target is present but its named "
            "Nyxmon check is disabled; review the lifecycle state "
            "and explicitly allow monitor re-enablement"
        )
    desired_disabled = (
        1
        if declaration_state == "retired"
        else (0 if allow_reenable else int(current_disabled))
    )
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
        or int(current_disabled) != desired_disabled
    ):
        cur.execute(
            """
            UPDATE health_check
            SET check_type = ?, url = ?, check_interval = ?,
                data = ?, disabled = ?
            WHERE id = ?
            """,
            (
                check_type,
                check_url,
                check_interval,
                desired_data_json,
                desired_disabled,
                check_id,
            ),
        )
        changed = True

conn.commit()
conn.close()
print("changed=true" if changed else "changed=false")
