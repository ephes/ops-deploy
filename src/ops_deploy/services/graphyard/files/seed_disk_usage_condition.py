"""Seed a declared operational condition for deploy_graphyard_conditions.

Derived from the Ansible seed, with existing staleness settings preserved through
--stale-after-seconds and --intermittent. New rows retain upstream defaults.
The condition spec arrives on stdin; the upstream command owns validation.
"""

import json
import sys

from django.core.management import call_command
from graphyard.models import ConditionDefinition

spec = json.load(sys.stdin)
host = str(spec["host"])
mountpoint = str(spec.get("mountpoint", "/"))
name = str(spec.get("name") or f"Host filesystem usage ({host} {mountpoint})")
desired = {
    "enabled": True,
    "metric_name": "host.filesystem_used_ratio",
    "host_filter": host,
    "subject_type_filter": "host",
    "subject_id_filter": host,
    "service_filter": "",
    "tags_filter": {"mountpoint": mountpoint},
    "operator": str(spec.get("operator", "gte")),
    "warning_threshold": float(spec["warning_threshold"]),
    "critical_threshold": float(spec["critical_threshold"]),
    "window_minutes": int(spec.get("window_minutes", 30)),
    "breach_minutes": int(spec.get("breach_minutes", 5)),
}

current = ConditionDefinition.objects.filter(name=name).first()
if current is None:
    differences = ["missing"]
else:
    differences = [
        field for field, value in desired.items() if getattr(current, field) != value
    ]

if differences:
    # The upstream command defaults these non-owned fields on every call.
    # Preserve existing values explicitly; new rows retain upstream defaults.
    preservation = []
    if current is not None:
        if current.stale_after_seconds is not None:
            preservation.extend(["--stale-after-seconds", str(current.stale_after_seconds)])
        if not current.alert_when_stale:
            preservation.append("--intermittent")
    call_command(
        "seed_disk_usage_condition",
        "--host",
        host,
        "--mountpoint",
        mountpoint,
        "--name",
        name,
        "--operator",
        desired["operator"],
        "--warning-threshold",
        str(desired["warning_threshold"]),
        "--critical-threshold",
        str(desired["critical_threshold"]),
        "--window-minutes",
        str(desired["window_minutes"]),
        "--breach-minutes",
        str(desired["breach_minutes"]),
        *preservation,
        verbosity=0,
    )
    current = ConditionDefinition.objects.get(name=name)

print(f"changed={'true' if differences else 'false'}")
print(f"id={current.id}")
print(f"name={current.name}")
print(f"differences={','.join(differences) if differences else '-'}")
