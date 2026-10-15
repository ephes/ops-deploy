# Run by ``manage.py shell -c`` in the Echoport site, after a ``PARAMS = {...}``
# line the deploy prepends. The playbook's "Upsert Echoport backup target for
# the work app" step, plus a read-only "check" mode that prints "unchanged"
# when an "apply" would not write anything (the playbook always reports a
# change). Like the playbook, every field including the schedule is set.
from backups.models import BackupStatus, BackupTarget, BackupTargetMode

P = PARAMS  # type: ignore[name-defined]  # noqa: F821

fields = {
    "description": P["description"],
    "icon": P["icon"],
    "fastdeploy_service": "echoport-backup",
    "service_name": P["service_name"],
    "restore_owner": P["restore_owner"],
    "target_mode": BackupTargetMode.GENERIC_PATHS,
    "db_path": P["db_path"],
    "backup_files": [],
    "schedule": P["schedule"],
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
        BackupTarget.objects.create(name=P["name"], **fields)
        print("created")
else:
    stale = [name for name, value in fields.items() if getattr(target, name) != value]
    if not stale:
        print("unchanged")
    elif P["mode"] == "check":
        print("pending")
    else:
        for name in stale:
            setattr(target, name, fields[name])
        target.save()
        print("updated")
