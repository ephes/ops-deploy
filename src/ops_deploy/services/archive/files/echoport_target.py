# Run by Echoport's ``manage.py shell -c`` as the echoport user. Port of the
# "Upsert Echoport backup target for archive" task in deploy-archive.yml.
# ARCHIVE_ECHOPORT (JSON) holds the target; with "apply" false it only prints
# "unchanged" or "pending" and writes nothing.
import json
import os

from backups.models import BackupStatus, BackupTarget, BackupTargetMode
from django.db import connection

params = json.loads(os.environ["ARCHIVE_ECHOPORT"])
field_names = {field.name for field in BackupTarget._meta.get_fields()}
with connection.cursor() as cursor:
    database_columns = {
        column.name for column in connection.introspection.get_table_description(cursor, BackupTarget._meta.db_table)
    }
if "schedule_required" not in field_names or "schedule_required" not in database_columns:
    raise RuntimeError("Echoport model/database lacks schedule_required; deploy migration 0008 first")

default_schedule = params["schedule"]
if not default_schedule.strip():
    raise RuntimeError("Refusing to register an empty Echoport schedule; the scheduler would skip this target")

wanted = {
    "description": "Archive SQLite database backups via echoport-backup",
    "icon": "archive",
    "fastdeploy_service": "echoport-backup",
    "service_name": "archive.service",
    "restore_owner": "archive:archive",
    "target_mode": BackupTargetMode.GENERIC_PATHS,
    "db_path": params["db_path"],
    "backup_files": [],
    "status": BackupStatus.ACTIVE,
    "retention_days": 30,
    "timeout_seconds": 900,
    "storage_bucket": "backups",
}
target = BackupTarget.objects.filter(name=params["name"]).first()
if target is None:
    if params["apply"]:
        target = BackupTarget.objects.create(
            name=params["name"], schedule=default_schedule, schedule_required=bool(default_schedule), **wanted
        )
        print(f"created schedule={target.schedule!r}")
    else:
        print("pending")
else:
    changes = {key: value for key, value in wanted.items() if getattr(target, key) != value}
    # A schedule set by hand in the Echoport UI survives deploys; only an
    # empty one is filled, unless the deploy is told to overwrite it.
    if params["update_schedule"] or not target.schedule:
        if target.schedule != default_schedule:
            changes["schedule"] = default_schedule
    # Never cleared here: the Echoport health view flags an active target
    # whose required schedule goes missing.
    if (changes.get("schedule") or target.schedule) and not target.schedule_required:
        changes["schedule_required"] = True
    if not changes:
        print("unchanged")
    elif not params["apply"]:
        print("pending")
    else:
        for key, value in changes.items():
            setattr(target, key, value)
        target.save()
        print(f"updated schedule={target.schedule!r}")
