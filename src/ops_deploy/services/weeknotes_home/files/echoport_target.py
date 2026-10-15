# Run by ``manage.py shell -c`` in the Echoport site, after a ``PARAMS = {...}``
# line the deploy prepends. It is the playbook's "Inspect the token stored in
# Echoport" and "Upsert Echoport backup target" steps in one, plus a read-only
# "check" mode.
#
# Modes (P["mode"]):
#   check  prints "unchanged" when an apply would write nothing, else "pending".
#   apply  prints "need-token" (and writes nothing) when the stored FastDeploy
#          service token must be re-issued and none arrives on stdin; otherwise
#          it upserts the target, taking a new token (one line) from stdin when
#          given, and prints "created", "updated" or "unchanged".
#
# The token is never printed. The decision to rotate follows ops-control's
# files/fastdeploy/echoport_service_token_status.py: keep the two in step.
import base64
import json
import re
import sys
import time

from backups.models import BackupStatus, BackupTarget, BackupTargetMode

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


name = P["name"]
legacy = P["legacy_name"]
target = BackupTarget.objects.filter(name=name).first()
legacy_target = BackupTarget.objects.filter(name=legacy).first()
if target is None:
    if legacy_target is not None:
        target = legacy_target
        target.name = name
        created, migrated = False, True
    else:
        target = BackupTarget(name=name)
        created, migrated = True, False
else:
    created, migrated = False, False

# The playbook inspects the first existing of (name, legacy name).
inspected = BackupTarget.objects.filter(name=name).first() or legacy_target
stored = inspected.service_token if inspected is not None else ""
reason = rotation_reason(stored, P["fastdeploy_service"], P["renewal_days"], int(time.time()))
rotate = P["force_rotate"] or reason is not None

desired = {
    "description": P["description"],
    "icon": "notebook",
    "fastdeploy_service": P["fastdeploy_service"],
    "service_name": P["service_name"],
    "restore_owner": P["restore_owner"],
    "target_mode": BackupTargetMode.SERVICE_OWNED,
    "db_path": "",
    "backup_files": [],
    "schedule": P["schedule"],
    "status": BackupStatus.ACTIVE,
    "retention_days": 30,
    "timeout_seconds": 900,
    "storage_bucket": "backups",
}

changed = created or migrated or rotate
for field, value in desired.items():
    if getattr(target, field) != value:
        changed = True

if P["mode"] == "check":
    print("pending" if changed else "unchanged")
    sys.exit(0)

token = ""
if rotate:
    token = sys.stdin.readline().strip()
    if not token:
        print("need-token")
        sys.exit(0)
    desired["service_token"] = token

for field, value in desired.items():
    if getattr(target, field) != value:
        setattr(target, field, value)
if changed:
    target.save()
    print("created" if created else "updated")
else:
    print("unchanged")
