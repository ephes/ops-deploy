"""The Nyxmon upsert of ops-control's ``deploy-os-apt-maintenance.yml`` (second play).

``apply``: the playbook's inline script with its inputs on stdin
(``{"db": ..., "service": ..., "checks": [...]}``) instead of the environment
and an embedded literal; the comparison and the writes are unchanged: type,
URL, interval and data are compared (``disabled`` is not), an update sets
those and ``disabled = 0`` only, a new check starts idle.

``probe`` (read-only; argv: db, service, check names): one line for the
service and one digest per named check of the values ``apply`` compares, so
the deploy can tell a current database without sending the password.
"""

import hashlib
import json
import sqlite3
import sys


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


def normalized(data):
    try:
        return json.dumps(json.loads(data or "{}"), sort_keys=True)
    except json.JSONDecodeError:
        return data or ""


def probe(db_path, service_name, names):
    conn = sqlite3.connect("file:" + db_path + "?mode=ro", uri=True, timeout=10)
    try:
        row = conn.execute("SELECT id FROM service WHERE name = ?", (service_name,)).fetchone()
        print("service", "absent" if row is None else "present")
        for name in names:
            existing = None
            if row is not None:
                existing = conn.execute(
                    "SELECT check_type, url, check_interval, data FROM health_check WHERE service_id = ? AND name = ?",
                    (row[0], name),
                ).fetchone()
            if existing is None:
                print("check", digest(name), "absent")
                continue
            check_type, url, interval, data = existing
            try:
                interval = int(interval)
            except (TypeError, ValueError):
                print("check", digest(name), "invalid")
                continue
            print("check", digest(name), digest(json.dumps([check_type, url, interval, normalized(data)])))
    finally:
        conn.close()


def apply(db_path, service_name, checks):
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
            current_data_json = json.dumps(json.loads(current_data or "{}"), sort_keys=True)
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


if __name__ == "__main__":
    if sys.argv[1] == "probe":
        probe(sys.argv[2], sys.argv[3], sys.argv[4:])
    else:
        payload = json.load(sys.stdin)
        apply(payload["db"], payload["service"], payload["checks"])
