#!/usr/bin/env python3
"""Idempotently upsert one Fractal Nyxmon JSON-metrics check."""

from __future__ import annotations

import json
import os
import sqlite3
import sys
from pathlib import Path
from contextlib import closing
from typing import Any

ORDERING_OPERATORS = {"<", "<=", ">", ">="}
LEGACY_CHECK_NAME = "Fractal Storage Health (HTTP)"


def normalize_ordering_thresholds(desired_data: dict[str, Any]) -> None:
    """Ensure ordering checks use JSON numbers, not templated strings."""

    for threshold in desired_data.get("checks", []):
        if threshold.get("op") not in ORDERING_OPERATORS:
            continue
        value = threshold.get("value")
        if not isinstance(value, str):
            continue
        try:
            parsed_value = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Ordering threshold {threshold.get('path')} must be numeric, "
                f"got {value!r}"
            ) from exc
        if isinstance(parsed_value, bool) or not isinstance(parsed_value, (int, float)):
            raise ValueError(
                f"Ordering threshold {threshold.get('path')} must be numeric, "
                f"got {value!r}"
            )
        threshold["value"] = parsed_value


def upsert_check(
    db_path: str,
    check_name: str,
    desired_data: dict[str, Any],
) -> bool:
    """Create or update the managed check and return whether state changed."""

    normalize_ordering_thresholds(desired_data)
    desired_data_json = json.dumps(desired_data, sort_keys=True)
    service_name = "fractal"
    check_type = "json-metrics"
    check_url = desired_data["url"]
    check_interval = 300

    with closing(sqlite3.connect(db_path, timeout=10)) as conn, conn:
        cur = conn.cursor()
        cur.execute("SELECT id FROM service WHERE name = ?", (service_name,))
        row = cur.fetchone()
        if row is None:
            cur.execute("INSERT INTO service (name) VALUES (?)", (service_name,))
            service_id = cur.lastrowid
        else:
            service_id = row[0]

        cur.execute(
            """
            UPDATE health_check
            SET disabled = 1, status = 'idle', next_check_time = 0,
                processing_started_at = 0
            WHERE name = ? AND disabled = 0
            """,
            (LEGACY_CHECK_NAME,),
        )
        legacy_changed = cur.rowcount > 0

        cur.execute(
            """
            SELECT id, check_type, url, check_interval, data, disabled
            FROM health_check WHERE service_id = ? AND name = ?
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
                ) VALUES (?, ?, ?, ?, ?, 'idle', 0, 0, 0, ?)
                """,
                (
                    check_name,
                    service_id,
                    check_type,
                    check_url,
                    check_interval,
                    desired_data_json,
                ),
            )
            return True

        (
            check_id,
            current_type,
            current_url,
            current_interval,
            current_data,
            disabled,
        ) = existing
        try:
            current_data_json = json.dumps(
                json.loads(current_data or "{}"), sort_keys=True
            )
        except json.JSONDecodeError:
            current_data_json = current_data or ""
        changed = (
            current_type != check_type
            or current_url != check_url
            or int(current_interval) != check_interval
            or current_data_json != desired_data_json
            or int(disabled) != 0
        )
        if changed:
            cur.execute(
                """
                UPDATE health_check
                SET check_type = ?, url = ?, check_interval = ?, data = ?,
                    disabled = 0, status = 'idle', next_check_time = 0,
                    processing_started_at = 0
                WHERE id = ?
                """,
                (
                    check_type,
                    check_url,
                    check_interval,
                    desired_data_json,
                    check_id,
                ),
            )
        return legacy_changed or changed



def current(db_path: str, check_name: str, data: dict[str, Any]) -> bool:
    normalize_ordering_thresholds(data)
    with closing(sqlite3.connect(Path(db_path).as_uri() + "?mode=ro", uri=True, timeout=10)) as conn:
        if conn.execute("SELECT 1 FROM health_check WHERE name=? AND disabled=0", (LEGACY_CHECK_NAME,)).fetchone():
            return False
        service = conn.execute("SELECT id FROM service WHERE name='fractal'").fetchone()
        if service is None:return False
        row = conn.execute("SELECT check_type,url,check_interval,data,disabled FROM health_check WHERE service_id=? AND name=?", (service[0],check_name)).fetchone()
        if row is None:return False
        try: canonical=json.dumps(json.loads(row[3] or "{}"),sort_keys=True)
        except json.JSONDecodeError:return False
        return (row[0],row[1],int(row[2]),canonical,int(row[4])) == ("json-metrics",data["url"],300,json.dumps(data,sort_keys=True),0)


def main() -> None:
    db_path, check_name = sys.argv[2:4]
    path=Path(db_path)
    # Never create a missing DB and never follow a linked deployment path.
    for part in [*reversed(path.parents),path]:
        if part.is_symlink():raise ValueError("Nyxmon database path is linked")
    if not path.is_file():raise ValueError("Existing Nyxmon database required")
    data=json.load(sys.stdin)
    if sys.argv[1]=='check':print('current' if current(db_path,check_name,data) else 'pending')
    elif sys.argv[1]=='apply':
        upsert_check(db_path,check_name,data)
        if not current(db_path,check_name,data):raise ValueError("Nyxmon row did not converge")
        print('current')
    else:raise ValueError("Unknown check action")


if __name__=='__main__':
    try:main()
    except Exception:
        print('Fractal Nyxmon check failed; login/data suppressed',file=sys.stderr)
        sys.exit(1)
