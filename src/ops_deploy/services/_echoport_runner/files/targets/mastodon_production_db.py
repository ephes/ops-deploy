import json
from backups.models import BackupTarget, BackupTargetMode

# Fields this play owns; the target is saved (and the task reports a
# change) only when one of them differs.
FIELDS = (
    "description", "icon", "fastdeploy_service", "fastdeploy_endpoint_key",
    "service_token", "service_name", "restore_owner", "target_mode", "db_path",
    "backup_files", "schedule", "schedule_required", "status", "retention_days",
    "timeout_seconds", "storage_bucket",
)
target = BackupTarget.objects.filter(
    name=VALUES["target_name"],
).first()
created = target is None
if target is None:
    target = BackupTarget(name=VALUES["target_name"])
elif target.status != "active" and not VALUES["allow_reactivation"]:
    # A paused or disabled target is not re-enabled by a re-run.
    raise RuntimeError(f"Refusing implicit reactivation from status={target.status}")
before = {field: getattr(target, field) for field in FIELDS}

target.description = VALUES["target_description"]
target.icon = ""
target.fastdeploy_service = VALUES["service_name_fd"]
target.fastdeploy_endpoint_key = ""
issued_token = SERVICE_TOKEN
if issued_token:
    target.service_token = issued_token
elif not target.service_token:
    raise RuntimeError("no FastDeploy service token to store")
target.service_name = VALUES["target_service_name"]
target.restore_owner = ""
target.target_mode = BackupTargetMode.SERVICE_OWNED
target.db_path = ""
target.backup_files = []
target.schedule = VALUES["target_schedule"]
target.schedule_required = True
target.status = VALUES["target_status"]
target.retention_days = VALUES["target_retention_days"]
target.timeout_seconds = VALUES["target_timeout_seconds"]
target.storage_bucket = VALUES["default_bucket"]
changed = created or before != {field: getattr(target, field) for field in FIELDS}
if changed:
    target.save()

# One line, last on stdout: the task reads `changed` from it.
print(json.dumps({
    "changed": changed,
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
}))
