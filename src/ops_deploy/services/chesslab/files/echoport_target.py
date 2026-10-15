# Run by ``manage.py shell -c`` in the Echoport site, after a ``PARAMS = {...}``
# line the deploy prepends. The playbook's "Upsert Echoport backup target"
# step, plus a read-only "check" mode that prints "unchanged" when an "apply"
# would not write anything (the playbook always reports a change).
from backups.models import BackupStatus, BackupTarget, BackupTargetMode
from django.db import connection

P = PARAMS  # type: ignore[name-defined]  # noqa: F821

field_names = {field.name for field in BackupTarget._meta.get_fields()}
with connection.cursor() as cursor:
    database_columns = {
        column.name for column in connection.introspection.get_table_description(cursor, BackupTarget._meta.db_table)
    }
if "schedule_required" not in field_names or "schedule_required" not in database_columns:
    raise RuntimeError("Echoport model/database lacks schedule_required; deploy migration 0008 first")

default_schedule = P["schedule"]
if not default_schedule.strip():
    raise RuntimeError("Refusing to register an empty Echoport schedule; the scheduler would skip this target")

fixed = {
    "description": P["description"],
    "icon": P["icon"],
    "fastdeploy_service": "echoport-backup",
    "service_name": P["service_name"],
    "restore_owner": P["restore_owner"],
    "target_mode": BackupTargetMode.GENERIC_PATHS,
    "db_path": P["db_path"],
    "backup_files": [],
    "status": BackupStatus.ACTIVE,
    "retention_days": 30,
    "timeout_seconds": 900,
    "storage_bucket": "backups",
}

target = BackupTarget.objects.filter(name=P["name"]).first()
if target is None:
    if P["mode"] == "check":
        print("pending")
    else:
        target = BackupTarget.objects.create(
            name=P["name"], schedule=default_schedule, schedule_required=bool(default_schedule), **fixed
        )
        print(f"created schedule={target.schedule!r}")
else:
    wanted = dict(fixed)
    # A schedule set by hand in the Echoport UI survives redeploys; only an
    # empty one is filled, unless the deploy is told to overwrite it.
    schedule = default_schedule if P["update_schedule"] or not target.schedule else target.schedule
    wanted["schedule"] = schedule
    # Never cleared here: the Echoport health view flags an active target
    # whose required schedule goes missing.
    if schedule:
        wanted["schedule_required"] = True
    stale = [name for name, value in wanted.items() if getattr(target, name) != value]
    if not stale:
        print("unchanged")
    elif P["mode"] == "check":
        print("pending")
    else:
        for name in stale:
            setattr(target, name, wanted[name])
        target.save()
        print(f"updated schedule={target.schedule!r}")
