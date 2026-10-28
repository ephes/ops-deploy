"""Exactly scoped original Tailscale SQL upsert; no credential/config body output."""

import json
import os
from pathlib import Path
import pwd
import sqlite3
import stat
import sys


class Refused(Exception):
    pass


def normal(value):
    try:
        return json.dumps(json.loads(value or "{}"), sort_keys=True)
    except (ValueError, TypeError):
        return value or ""


def changes(connection, cfg, apply):
    row = connection.execute("SELECT id FROM service WHERE name = ?", (cfg["service_name"],)).fetchall()
    if len(row) > 1:
        raise Refused("duplicate Tailscale service binding")
    changed = not row
    if row:
        service = row[0][0]
    elif apply:
        service = connection.execute("INSERT INTO service (name) VALUES (?)", (cfg["service_name"],)).lastrowid
    else:
        return True
    for check in cfg["checks"]:
        rows = connection.execute(
            "SELECT id,check_type,url,check_interval,data FROM health_check WHERE service_id=? AND name=?",
            (service, check["name"]),
        ).fetchall()
        if len(rows) > 1:
            raise Refused("duplicate declared Tailscale check binding")
        data = json.dumps(check["data"], sort_keys=True)
        if not rows:
            changed = True
            if apply:
                connection.execute(
                    "INSERT INTO health_check (name,service_id,check_type,url,check_interval,status,next_check_time,processing_started_at,disabled,data) VALUES (?,?,?,?,?,'idle',0,0,0,?)",
                    (check["name"], service, check["check_type"], check["url"], check["check_interval"], data),
                )
        elif (rows[0][1], rows[0][2], int(rows[0][3]), normal(rows[0][4])) != (
            check["check_type"],
            check["url"],
            check["check_interval"],
            data,
        ):
            changed = True
            if apply:
                # Intentionally preserve ALL original lifecycle/runtime columns.
                connection.execute(
                    "UPDATE health_check SET check_type=?,url=?,check_interval=?,data=? WHERE id=?",
                    (check["check_type"], check["url"], check["check_interval"], data, rows[0][0]),
                )
    return changed


def main():
    action = sys.argv[1]
    if action not in ("check", "apply"):
        raise Refused("unknown Tailscale SQL action")
    cfg = json.load(sys.stdin)
    path = Path(cfg["db_path"])
    for parent in reversed(path.parents):
        if parent.is_symlink():
            raise Refused("Tailscale SQL path parent is linked")
    try:
        info = path.lstat()
    except FileNotFoundError:
        print("absent")
        return
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != os.geteuid()
        or pwd.getpwuid(os.geteuid()).pw_name != cfg["user"]
    ):
        raise Refused("Tailscale SQL requires the original owner and ordinary DB path")
    uri = path.as_uri() + ("?mode=ro" if action == "check" else "?mode=rw")
    connection = sqlite3.connect(uri, uri=True, timeout=10)
    try:
        if action == "apply":
            connection.execute("BEGIN IMMEDIATE")
        changed = changes(connection, cfg, action == "apply")
        if action == "apply":
            connection.commit()
        print("pending" if changed and action == "check" else "current")
    finally:
        connection.close()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("Declared Tailscale SQL state failed; all credential/row contents suppressed", file=sys.stderr)
        raise SystemExit(2) from None
