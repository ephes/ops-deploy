# Upserts one Echoport backup target. Run by ``manage.py shell -c`` in the
# Echoport site as the echoport user, after the ``PARAMS = ...`` lines that
# :func:`ops_deploy.services._echoport.target_code` prepends. Shared by every
# service that registers a target (the playbooks' "Upsert Echoport backup
# target" tasks).
#
# Modes (P["mode"]):
#   check  prints "unchanged" when an apply would write nothing, else "pending".
#   apply  prints "created", "updated" or "unchanged"; with "service_token"
#          set it prints "need-token" (and writes nothing) when the stored
#          FastDeploy service token must be re-issued and none arrives on
#          stdin (one line).
#
# Parameters: "name", "description", "icon", "service_name", "restore_owner",
# "schedule" (required, not empty); "target_mode" ("generic_paths", default,
# or "service_owned"), "fastdeploy_service" (default "echoport-backup"),
# "db_path", "backup_files", "schedule_policy" ("keep", default: a schedule
# set in the Echoport UI survives deploys and only an empty one is filled;
# "set": every deploy sets it), "legacy_name" (an older name, renamed),
# "service_token" ({"renewal_days": int, "force_rotate": bool}).
#
# A token is never printed. The decision to rotate follows ops-control's
# files/fastdeploy/echoport_service_token_status.py: keep the two in step.
import base64
import json
import re
import sys
import time

from backups.models import BackupStatus, BackupTarget, BackupTargetMode
from django.db import connection

P = PARAMS  # type: ignore[name-defined]  # noqa: F821

JWT_SHAPE = re.compile(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")


def token_claims(token):
    if not isinstance(token, str) or not JWT_SHAPE.fullmatch(token):
        return None
    try:
        segment = token.split(".")[1]
        segment += "=" * (-len(segment) % 4)
        claims = json.loads(base64.urlsafe_b64decode(segment.encode("ascii")).decode("utf-8"))
    except (AttributeError, IndexError, UnicodeError, ValueError):
        return None
    return claims if isinstance(claims, dict) else None


def rotation_reason(token, service, renewal_days, now):
    if not token:
        return "missing"
    claims = token_claims(token)
    if claims is None:
        return "undecodable"
    if claims.get("type") != "service" or claims.get("service") != service:
        return "wrong_scope"
    if not claims.get("jti"):
        return "legacy_without_jti"
    try:
        expires_at = int(claims["exp"])
    except (KeyError, TypeError, ValueError):
        return "no_expiry"
    if expires_at <= now + renewal_days * 86400:
        return "expiring"
    return None


field_names = {field.name for field in BackupTarget._meta.get_fields()}
with connection.cursor() as cursor:
    database_columns = {
        column.name for column in connection.introspection.get_table_description(cursor, BackupTarget._meta.db_table)
    }
if "schedule_required" not in field_names or "schedule_required" not in database_columns:
    raise RuntimeError("Echoport model/database lacks schedule_required; deploy migration 0008 first")

schedule = P["schedule"]
if not schedule.strip():
    raise RuntimeError("Refusing to register an empty Echoport schedule; the scheduler would skip this target")
policy = P.get("schedule_policy", "keep")
if policy not in ("keep", "set"):
    raise RuntimeError(f"unknown schedule_policy {policy!r}")

name = P["name"]
legacy = P.get("legacy_name")
target = BackupTarget.objects.filter(name=name).first()
legacy_target = BackupTarget.objects.filter(name=legacy).first() if legacy else None
created = renamed = False
if target is None and legacy_target is not None:
    target, renamed = legacy_target, True
elif target is None:
    target, created = BackupTarget(name=name), True

wanted = {
    "description": P["description"],
    "icon": P["icon"],
    "fastdeploy_service": P.get("fastdeploy_service", "echoport-backup"),
    "service_name": P["service_name"],
    "restore_owner": P["restore_owner"],
    "target_mode": BackupTargetMode(P.get("target_mode", BackupTargetMode.GENERIC_PATHS)),
    "db_path": P.get("db_path", ""),
    "backup_files": list(P.get("backup_files", [])),
    "status": BackupStatus.ACTIVE,
    "retention_days": 30,
    "timeout_seconds": 900,
    "storage_bucket": "backups",
}
if created or policy == "set" or not target.schedule:
    wanted["schedule"] = schedule
# Never cleared here: the Echoport health view flags an active target whose
# required schedule goes missing.
if wanted.get("schedule") or target.schedule:
    wanted["schedule_required"] = True

rotate = False
token_params = P.get("service_token")
if token_params is not None:
    reason = rotation_reason(
        target.service_token, wanted["fastdeploy_service"], token_params["renewal_days"], int(time.time())
    )
    rotate = token_params["force_rotate"] or reason is not None

stale = [field for field, value in wanted.items() if getattr(target, field) != value]
if not (created or renamed or rotate or stale):
    print("unchanged")
    sys.exit(0)
if P["mode"] == "check":
    print("pending")
    sys.exit(0)

if rotate:
    token = sys.stdin.readline().strip()
    if not token:
        print("need-token")
        sys.exit(0)
    wanted["service_token"] = token

if renamed:
    target.name = name
for field, value in wanted.items():
    setattr(target, field, value)
target.save()
print("created" if created else "updated")
