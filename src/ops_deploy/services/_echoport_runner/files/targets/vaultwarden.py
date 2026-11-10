import json
from backups.models import BackupTarget, BackupTargetMode
from django.db import connection

desired_state = VALUES["declaration_state"]
field_names = {field.name for field in BackupTarget._meta.get_fields()}
with connection.cursor() as cursor:
    database_columns = {
        column.name
        for column in connection.introspection.get_table_description(
            cursor,
            BackupTarget._meta.db_table,
        )
    }
if (
    "schedule_required" not in field_names
    or "schedule_required" not in database_columns
):
    raise RuntimeError(
        "Echoport model/database lacks schedule_required; "
        "deploy migration 0008 first"
    )

target = BackupTarget.objects.filter(
    name=VALUES["target_name"],
).first()
created = target is None
changed = created
if target is None:
    if desired_state == "retired":
        print(json.dumps({
            "changed": False,
            "created": False,
            "retired": True,
            "absent": True,
        }))
        raise SystemExit(0)
    target = BackupTarget(
        name=VALUES["target_name"]
    )

if desired_state == "retired":
    if target.status != "disabled":
        target.status = "disabled"
        target.save()
        changed = True
    if target.schedule_required or target.schedule:
        target.schedule_required = False
        target.schedule = ""
        target.save()
        changed = True
    if target.service_token:
        target.service_token = ""
        target.save(update_fields=["service_token"])
        changed = True
else:
    if (
        not created
        and target.status != "active"
        and not VALUES["allow_reactivation"]
    ):
        raise RuntimeError(
            f"Refusing implicit reactivation from status={target.status}"
        )
    desired = {
        "description": VALUES["target_description"],
        "icon": "",
        "fastdeploy_service": VALUES["service_name_fd"],
        "fastdeploy_endpoint_key": "",
        "service_name": VALUES["service_name"],
        "restore_owner": "",
        "target_mode": BackupTargetMode.SERVICE_OWNED,
        "db_path": "",
        "backup_files": [],
        "schedule": VALUES["target_schedule"],
        "schedule_required": True,
        "status": "active",
        "retention_days": VALUES["target_retention_days"],
        "timeout_seconds": VALUES["target_timeout_seconds"],
        "storage_bucket": VALUES["default_bucket"],
    }
    for field_name, desired_value in desired.items():
        if getattr(target, field_name) != desired_value:
            setattr(target, field_name, desired_value)
            changed = True
    if changed:
        target.save()

target.refresh_from_db()
print(json.dumps({
    "changed": changed,
    "created": created,
    "name": target.name,
    "status": target.status,
    "target_mode": target.target_mode,
    "fastdeploy_service": target.fastdeploy_service,
    "service_name": target.service_name,
    "schedule": target.schedule,
    "schedule_required": target.schedule_required,
    "retention_days": target.retention_days,
    "timeout_seconds": target.timeout_seconds,
    "has_service_token_override": bool(target.service_token),
}, sort_keys=True))

if SERVICE_TOKEN:
    from backups.models import BackupTarget

    target = BackupTarget.objects.get(
        name=VALUES["target_name"],
    )
    target.service_token = SERVICE_TOKEN
    target.save(update_fields=["service_token"])
