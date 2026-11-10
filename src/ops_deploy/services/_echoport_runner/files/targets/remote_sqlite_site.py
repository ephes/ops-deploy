import json
from backups.models import BackupTarget, BackupTargetMode

target = BackupTarget.objects.filter(
    name=VALUES["target_name"],
).first()
created = target is None
if target is None:
    target = BackupTarget(name=VALUES["target_name"])

target.description = VALUES["target_description"]
target.icon = ""
target.fastdeploy_service = VALUES["service_name_fd"]
target.fastdeploy_endpoint_key = ""
issued_token = SERVICE_TOKEN
if issued_token:
    target.service_token = issued_token
elif not target.service_token:
    raise RuntimeError("no FastDeploy service token to store")
target.service_name = ""
target.restore_owner = ""
target.target_mode = BackupTargetMode.SERVICE_OWNED
target.db_path = ""
target.backup_files = []
target.schedule = VALUES["target_schedule"]
target.status = "active"
target.retention_days = VALUES["target_retention_days"]
target.timeout_seconds = VALUES["target_timeout_seconds"]
target.storage_bucket = VALUES["default_bucket"]
target.save()

print(json.dumps({
    "created": created,
    "name": target.name,
    "status": target.status,
    "target_mode": target.target_mode,
    "fastdeploy_service": target.fastdeploy_service,
    "service_name": target.service_name,
    "backup_files": target.backup_files,
    "schedule": target.schedule,
    "retention_days": target.retention_days,
    "timeout_seconds": target.timeout_seconds,
    "has_service_token_override": bool(target.service_token),
}, indent=2))
