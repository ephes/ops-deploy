import json
from backups.models import BackupTarget
from django.db import connection

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

name = VALUES["target_name"]
target = BackupTarget.objects.filter(name=name).first()
if target is None:
    raise RuntimeError(
        f"BackupTarget {name!r} does not exist. This task converges the "
        "schedule of an existing service-owned target; create the target "
        "first."
    )

# Identifying fields are asserted rather than rewritten: if they have
# drifted, that is something to look at, not something to silently
# overwrite from a playbook whose job is the schedule.
expected = {
    "target_mode": "service_owned",
    "fastdeploy_service": VALUES["service_name_fd"],
}
mismatched = {
    field: (getattr(target, field), value)
    for field, value in expected.items()
    if str(getattr(target, field)) != value
}
if mismatched:
    raise RuntimeError(f"Unexpected BackupTarget wiring: {mismatched}")

if target.status != "active" and not VALUES["allow_reactivation"]:
    raise RuntimeError(
        f"Refusing implicit reactivation from status={target.status}"
    )

desired = {
    "schedule": VALUES["target_schedule"],
    "schedule_required": True,
    "retention_days": VALUES["target_retention_days"],
    "timeout_seconds": VALUES["target_timeout_seconds"],
}
applied = {
    field: value
    for field, value in desired.items()
    if getattr(target, field) != value
}
if applied:
    for field, value in applied.items():
        setattr(target, field, value)
    target.save(update_fields=list(applied))

print(json.dumps({
    "changed": bool(applied),
    "applied": {k: str(v) for k, v in applied.items()},
    "schedule": target.schedule,
    "schedule_required": target.schedule_required,
    "retention_days": target.retention_days,
}, sort_keys=True))
