#!/usr/bin/env python3
"""Upsert explicitly supplied Nyxmon checks; input (including auth) is stdin only."""

import json
import sqlite3
import sys


def upsert(db_path, checks):
    connection = sqlite3.connect(f"file:{db_path}?mode=rw", uri=True, timeout=10)
    changed = False
    try:
        with connection:
            for check in checks:
                row = connection.execute(
                    "SELECT id FROM service WHERE name=?", (check["service"],)
                ).fetchone()
                if row is None:
                    service_id = connection.execute(
                        "INSERT INTO service (name) VALUES (?)", (check["service"],)
                    ).lastrowid
                    changed = True
                else:
                    service_id = row[0]
                desired = (
                    "json-metrics",
                    check["url"],
                    check["interval"],
                    json.dumps(check["data"], sort_keys=True),
                )
                row = connection.execute(
                    "SELECT id,check_type,url,check_interval,data,disabled FROM health_check WHERE service_id=? AND name=?",
                    (service_id, check["name"]),
                ).fetchone()
                if row is None:
                    connection.execute(
                        "INSERT INTO health_check (name,service_id,check_type,url,check_interval,data,status,next_check_time,processing_started_at,disabled) VALUES (?,?,?,?,?,?,'idle',0,0,0)",
                        (check["name"], service_id, *desired),
                    )
                    changed = True
                else:
                    current = (
                        row[1],
                        row[2],
                        row[3],
                        json.dumps(json.loads(row[4] or "{}"), sort_keys=True),
                    )
                    if current != desired or row[5]:
                        connection.execute(
                            "UPDATE health_check SET check_type=?,url=?,check_interval=?,data=?,disabled=0,next_check_time=0 WHERE id=?",
                            (*desired, row[0]),
                        )
                        changed = True
        return changed
    finally:
        connection.close()


def disable(db_path, names):
    connection = sqlite3.connect(f"file:{db_path}?mode=rw", uri=True, timeout=10)
    try:
        with connection:
            count = 0
            for name in names:
                count += connection.execute(
                    "UPDATE health_check SET disabled=1 WHERE name=? AND service_id IN "
                    "(SELECT id FROM service WHERE name='Live software health') AND disabled=0",
                    (name,),
                ).rowcount
        return bool(count)
    finally:
        connection.close()


if __name__ == "__main__":
    payload = json.load(sys.stdin)
    changed = (
        disable(payload["db"], payload["disable_names"])
        if "disable_names" in payload
        else upsert(payload["db"], payload["checks"])
    )
    print("changed=true" if changed else "changed=false")
