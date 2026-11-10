import json
from backups.models import BackupTarget
from django.db import transaction
with transaction.atomic():
    target, created = BackupTarget.objects.get_or_create(name=VALUES["target_name"], defaults={'fastdeploy_service': VALUES["service_name_fd"], 'target_mode': 'service_owned'})
    target.fastdeploy_service = VALUES["service_name_fd"]
    issued_token = SERVICE_TOKEN
    if issued_token:
        target.service_token = issued_token
    elif not target.service_token:
        raise RuntimeError('no FastDeploy service token to store')
    target.target_mode = 'service_owned'
    target.service_name = 'daybook-operations'
    target.description = 'Database and replay keyring; restore only through attended operations lifecycle'
    target.db_path = ''
    target.backup_files = []
    target.storage_bucket = VALUES["default_bucket"]
    if created or VALUES["update_schedule"]:
        target.schedule = VALUES["target_schedule"]
        target.schedule_required = bool(target.schedule)
    target.retention_days = VALUES["target_retention_days"]
    target.timeout_seconds = 1800
    if created:
        target.status = 'active'
    target.full_clean()
    target.save()
print(json.dumps({'schedule': target.schedule, 'status': target.status}))
