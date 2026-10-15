# ruff: noqa: E501
"""Stand-ins for Echoport, FastDeploy and Nyxmon on the smoke VM.

The real services are not installed there. The stubs keep the interfaces the
weeknotes.home deploy talks to: ``manage.py shell -c`` with ``backups.models``
(targets in a JSON file), ``commands.py issueservicetoken`` (prints a service
JWT) and the Nyxmon SQLite database. The deploy's own scripts run unchanged.
"""

from __future__ import annotations

import hashlib

ECHOPORT_MODELS = """
import json
import os

STORE = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "targets.json")


class BackupStatus:
    ACTIVE = "active"


class BackupTargetMode:
    SERVICE_OWNED = "service_owned"


FIELDS = ("name", "description", "icon", "fastdeploy_service", "service_name", "restore_owner", "target_mode",
          "db_path", "backup_files", "schedule", "status", "retention_days", "timeout_seconds", "storage_bucket",
          "service_token")


def _load():
    try:
        with open(STORE) as handle:
            return json.load(handle)
    except FileNotFoundError:
        return []


class BackupTarget:
    def __init__(self, **values):
        self.id = None
        for field in FIELDS:
            setattr(self, field, "")
        self.backup_files = []
        self.__dict__.update(values)

    def save(self):
        rows = _load()
        if self.id is None:
            self.id = max([row["id"] for row in rows], default=0) + 1
            rows.append({})
            index = len(rows) - 1
        else:
            index = next(i for i, row in enumerate(rows) if row["id"] == self.id)
        rows[index] = {"id": self.id, **{field: getattr(self, field) for field in FIELDS}}
        with open(STORE, "w") as handle:
            json.dump(rows, handle)


class _Manager:
    def filter(self, name):
        rows = [row for row in _load() if row["name"] == name]
        return _Result([_make(row) for row in rows])


def _make(row):
    target = BackupTarget(**row)
    return target


class _Result(list):
    def first(self):
        return self[0] if self else None


BackupTarget.objects = _Manager()
"""

ECHOPORT_MANAGE = """#!/usr/bin/env python3
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "stub"))
if sys.argv[1:2] == ["shell"] and "-c" in sys.argv:
    exec(sys.argv[sys.argv.index("-c") + 1], globals())
else:
    sys.exit("stub manage.py only supports: shell -c CODE")
"""

FASTDEPLOY_COMMANDS = """#!/usr/bin/env python3
import argparse
import base64
import hashlib
import json
import os
import time
import uuid


def cli():
    parser = argparse.ArgumentParser()
    parser.add_argument("command")
    parser.add_argument("--service", required=True)
    parser.add_argument("--user", required=True)
    parser.add_argument("--days", type=int, required=True)
    parser.add_argument("--origin", required=True)
    args = parser.parse_args()
    here = os.path.dirname(os.path.abspath(__file__))
    wanted = open(os.path.join(here, "operator.sha256")).read().strip()
    if hashlib.sha256(args.user.encode()).hexdigest() != wanted:
        raise SystemExit("unknown user")
    b64 = lambda data: base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()
    claims = {"type": "service", "service": args.service, "jti": str(uuid.uuid4()),
              "exp": int(time.time()) + args.days * 86400}
    with open(os.path.join(here, "issued.log"), "a") as log:
        log.write(f"{args.service} {args.days} {args.origin}\\n")
    print(f"{b64({'alg': 'none'})}.{b64(claims)}.c2lnbmF0dXJl")


if __name__ == "__main__":
    cli()
"""


def setup_script(operator: str, fastdeploy_config: str) -> str:
    """Shell script (run as root) creating the stubs; ``operator`` is only stored as a hash."""

    digest = hashlib.sha256(operator.encode()).hexdigest()
    return f"""set -eu
for user in echoport fastdeploy nyxmon; do
    id "$user" >/dev/null 2>&1 || useradd --system --create-home --home-dir "/home/$user" --shell /usr/sbin/nologin "$user"
done
install -d -o echoport -g echoport /home/echoport/site /home/echoport/site/stub/backups /home/echoport/site/.venv/bin
ln -sf /usr/bin/python3 /home/echoport/site/.venv/bin/python
cat >/home/echoport/site/stub/backups/models.py <<'PY'
{ECHOPORT_MODELS}
PY
touch /home/echoport/site/stub/backups/__init__.py
cat >/home/echoport/site/manage.py <<'PY'
{ECHOPORT_MANAGE}
PY
rm -f /home/echoport/site/targets.json
chown -R echoport:echoport /home/echoport/site

install -d -o fastdeploy -g fastdeploy /home/fastdeploy/site/.venv/bin /home/fastdeploy/site/services/weeknotes-home-backup
ln -sf /usr/bin/python3 /home/fastdeploy/site/.venv/bin/python
cat >/home/fastdeploy/site/commands.py <<'PY'
{FASTDEPLOY_COMMANDS}
PY
printf '%s\\n' {digest} >/home/fastdeploy/site/operator.sha256
rm -f /home/fastdeploy/site/issued.log
cat >/home/fastdeploy/site/services/weeknotes-home-backup/config.json <<'JSON'
{fastdeploy_config}
JSON
chown -R fastdeploy:fastdeploy /home/fastdeploy/site

runuser -u postgres -- psql -XAtq -c "CREATE DATABASE fastdeploy" 2>/dev/null || true
runuser -u postgres -- psql -XAtq -d fastdeploy -c "CREATE TABLE IF NOT EXISTS service (name varchar PRIMARY KEY, data json)"
runuser -u postgres -- psql -XAtq -d fastdeploy -c "DELETE FROM service"

install -d -o nyxmon -g nyxmon /home/nyxmon/site
rm -f /home/nyxmon/site/db.sqlite3
runuser -u nyxmon -- python3 - <<'PY'
import sqlite3
conn = sqlite3.connect("/home/nyxmon/site/db.sqlite3")
conn.executescript('''
CREATE TABLE service (id integer primary key autoincrement, name text unique);
CREATE TABLE health_check (id integer primary key autoincrement, name text, service_id integer,
  check_type text, url text, check_interval integer, status text, next_check_time integer,
  processing_started_at integer, disabled integer, data text);
''')
conn.commit()
PY
"""


def teardown_script() -> str:
    return """set -u
runuser -u postgres -- psql -XAtq -c "DROP DATABASE IF EXISTS fastdeploy" || true
for user in echoport fastdeploy nyxmon; do userdel -r "$user" 2>/dev/null || true; done
rm -rf /home/echoport /home/fastdeploy /home/nyxmon
"""


def reset_script() -> str:
    """Remove a previous weeknotes-home deploy (and the stand-ins) from the smoke VM."""

    return """set -u
systemctl disable --now weeknotes-home 2>/dev/null
systemctl stop weeknotes-port-squatter 2>/dev/null
rm -f /etc/systemd/system/weeknotes-home.service /etc/traefik/dynamic/weeknotes-home.yml
systemctl daemon-reload
runuser -u postgres -- psql -XAtq -c "DROP DATABASE IF EXISTS weeknotes_home" 2>/dev/null
runuser -u postgres -- psql -XAtq -c "DROP ROLE IF EXISTS weeknotes_home" 2>/dev/null
userdel -r weeknotes-home 2>/dev/null
rm -rf /home/weeknotes-home
true
""" + teardown_script()
