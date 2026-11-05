import json
from backups.models import BackupTarget, BackupTargetMode

name = VALUES["target_name"]
schedule = VALUES["target_schedule"]

def daily_minute(expr):
    parts = (expr or "").split()
    if len(parts) != 5 or parts[2:] != ["*", "*", "*"]:
        return None
    if not (parts[0].isdigit() and parts[1].isdigit()):
        return None
    return int(parts[1]) * 60 + int(parts[0])

own = daily_minute(schedule)
if own is None:
    raise RuntimeError(f"schedule {schedule!r} is not a plain daily 'M H * * *'")
clashes = []
for other in BackupTarget.objects.exclude(name=name).filter(status="active"):
    minute = daily_minute(other.schedule)
    if minute is not None and min(abs(minute - own), 1440 - abs(minute - own)) < 10:
        clashes.append(f"{other.name} ({other.schedule})")
if clashes:
    raise RuntimeError(f"schedule {schedule} is within 10 minutes of: {', '.join(clashes)}")

target = BackupTarget.objects.filter(name=name).first()
created = target is None
if target is None:
    target = BackupTarget(name=name)
else:
    if target.status != "active" and not VALUES["allow_reactivation"]:
        raise RuntimeError(f"Refusing implicit reactivation from status={target.status}")
    if target.fastdeploy_service != VALUES["service_name_fd"]:
        raise RuntimeError(f"existing target is wired to {target.fastdeploy_service!r}")

target.description = VALUES["target_description"]
target.fastdeploy_service = VALUES["service_name_fd"]
target.fastdeploy_endpoint_key = ""
issued_token = SERVICE_TOKEN
if issued_token:
    target.service_token = issued_token
elif not target.service_token:
    raise RuntimeError("no FastDeploy service token to store")
target.service_name = VALUES["target_service_name"]
target.target_mode = BackupTargetMode.SERVICE_OWNED
target.db_path = ""
target.backup_files = []
target.schedule = schedule
target.schedule_required = True
target.status = VALUES["target_status"]
target.retention_days = VALUES["target_retention_days"]
target.timeout_seconds = VALUES["target_timeout_seconds"]
target.storage_bucket = VALUES["echoport_backup_default_bucket"]
target.save()

print(json.dumps({
    "created": created,
    "name": target.name,
    "status": target.status,
    "target_mode": target.target_mode,
    "fastdeploy_service": target.fastdeploy_service,
    "schedule": target.schedule,
    "schedule_required": target.schedule_required,
    "retention_days": target.retention_days,
    "timeout_seconds": target.timeout_seconds,
    "has_service_token_override": bool(target.service_token),
}, indent=2))
