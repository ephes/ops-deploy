"""Read-only view of the rows the role's ``nyxmon_checks.py`` compares (ops-deploy, standard library).

``upsert DB SERVICE NAME [SERVICE NAME ...]``: per check one digest of what
``upsert`` compares (type, URL, interval, normalized data, disabled), so the
deploy tells a current database without sending the password.
``disable DB NAME ...``: how many of these checks are still enabled.
"""

import hashlib
import json
import sqlite3
import sys


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


def main():
    mode, db_path, rest = sys.argv[1], sys.argv[2], sys.argv[3:]
    connection = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=10)
    try:
        if mode == "disable":
            count = 0
            for name in rest:
                count += connection.execute(
                    "SELECT count(*) FROM health_check WHERE name=? AND service_id IN "
                    "(SELECT id FROM service WHERE name='Live software health') AND disabled=0",
                    (name,),
                ).fetchone()[0]
            print("enabled", count)
            return
        for service, name in zip(rest[0::2], rest[1::2]):
            key = digest(json.dumps([service, name]))
            row = connection.execute(
                "SELECT h.check_type, h.url, h.check_interval, h.data, h.disabled FROM health_check h "
                "JOIN service s ON s.id = h.service_id WHERE s.name=? AND h.name=?",
                (service, name),
            ).fetchone()
            if row is None:
                print("check", key, "absent")
                continue
            try:
                data = json.dumps(json.loads(row[3] or "{}"), sort_keys=True)
            except ValueError:
                print("check", key, "invalid")
                continue
            print("check", key, digest(json.dumps([row[0], row[1], row[2], data, bool(row[4])])))
    finally:
        connection.close()


if __name__ == "__main__":
    main()
