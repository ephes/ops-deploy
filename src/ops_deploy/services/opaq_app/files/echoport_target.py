# Run by Echoport's ``manage.py shell -c`` as the echoport user. Port of the
# "Upsert the Echoport backup target" task in deploy-opaq-app.yml.
# OPAQ_ECHOPORT (JSON) holds the target; with "apply" false it only prints
# "unchanged" or "pending" and writes nothing.
import json
import os

from backups.models import BackupStatus, BackupTarget, BackupTargetMode

params = json.loads(os.environ["OPAQ_ECHOPORT"])
wanted = {
    "description": "Opaq app SQLite database (verified months, saved scenarios)",
    "icon": "landmark",
    "fastdeploy_service": "echoport-backup",
    "service_name": params["service_name"],
    "restore_owner": params["restore_owner"],
    "target_mode": BackupTargetMode.GENERIC_PATHS,
    "db_path": params["db_path"],
    "backup_files": [],
    "schedule": params["schedule"],
    "status": BackupStatus.ACTIVE,
    "retention_days": 30,
    "timeout_seconds": 900,
    "storage_bucket": "backups",
}
target = BackupTarget.objects.filter(name=params["name"]).first()
if target is None:
    if params["apply"]:
        BackupTarget.objects.create(name=params["name"], **wanted)
        print("created")
    else:
        print("pending")
else:
    changes = {key: value for key, value in wanted.items() if getattr(target, key) != value}
    if not changes:
        print("unchanged")
    elif not params["apply"]:
        print("pending")
    else:
        for key, value in changes.items():
            setattr(target, key, value)
        target.save()
        print("updated")
