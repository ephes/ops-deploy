"""graphyard conditions: the inventory's disk-usage conditions in Graphyard's database.

Port of ops-control's ``playbooks/seed-graphyard-conditions.yml``. Each enabled
entry becomes one ``host.filesystem_used_ratio`` condition, created or updated
by Graphyard's own ``seed_disk_usage_condition`` management command through
the playbook's seed script (``files/seed_disk_usage_condition.py``, the same
bytes as ops-control's ``files/graphyard_seed_disk_usage_condition.py``). The
playbook started one ``manage.py shell`` per condition on every run; this port
reads first: one read-only ``manage.py shell`` probe compares the fields the
seed manages, and only the conditions it finds missing or different are seeded
(with the spec on stdin, as before). A converged run writes nothing.

What the deploy owns: the named ``condition_definition`` rows and only the
fields the seed manages (enabled, metric name, the host/subject/service/tags
filters, operator, thresholds, window and breach minutes). It never deletes a
row and never touches other rows, ``alert_when_stale``,
``stale_after_seconds`` or evaluation state; an entry with ``enabled: false``
is skipped, not removed.

As in the playbook, ``manage.py`` runs as the Graphyard user with the service
environment sourced (``set -a; . <env>``), and stops when that file does not
set ``DJANGO_SETTINGS_MODULE``. Afterwards ``GET /v1/conditions`` (with
``X-Forwarded-Proto: https``) must answer 200 and list every enabled
condition by name.
"""

from __future__ import annotations

import json
import shlex
from pathlib import Path, PurePosixPath
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictFloat, StrictInt, field_validator, model_validator
from pyinfra.api import deploy
from pyinfra.operations import server

from ops_deploy.base import RoleConfig
from ops_deploy.core.config import UnixUser
from ops_deploy.helpers import mark_read_only
from ops_deploy.helpers.probes import probe, stdin_arguments, verify_probe
from ops_deploy.services.graphyard._common import Url, absolute, runuser

_FILES = Path(__file__).parent / "files"
# The playbook's seed script, unchanged (ops-control tests compare the bytes).
SEED_SCRIPT = (_FILES / "seed_disk_usage_condition.py").read_text()
# Read-only: the desired fields exactly as the seed script derives them, compared
# the way it compares them (``getattr(row, field) != value``). Specs (a JSON list)
# on stdin; one line per spec, then the overall answer.
CONDITIONS_PROBE = """\
import json
import sys

from graphyard.models import ConditionDefinition

pending = False
for index, spec in enumerate(json.load(sys.stdin)):
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
        differences = [field for field, value in desired.items() if getattr(current, field) != value]
    pending = pending or bool(differences)
    print("condition", index, ",".join(differences) if differences else "current")
print("pending" if pending else "current")
"""
# The playbook's ``Read Graphyard conditions summary`` and the name assertion (on the host,
# as ``ansible.builtin.uri`` runs there): 200, every name listed; prints the summary.
CONDITIONS_API = """\
import json, sys, urllib.request
url, names = sys.argv[1], json.loads(sys.argv[2])
request = urllib.request.Request(url, headers={"X-Forwarded-Proto": "https"})
with urllib.request.urlopen(request, timeout=30) as response:
    if response.status != 200:
        sys.exit("GET %s answered %d, expected 200" % (url, response.status))
    body = json.load(response)
listed = [condition.get("name") for condition in body["conditions"]]
missing = [name for name in names if name not in listed]
if missing:
    sys.exit("Graphyard did not list the condition(s) %s after seeding" % ", ".join(missing))
print(json.dumps(body.get("summary"), sort_keys=True))
"""
# The playbook's manage.py wrapper, unchanged: the service environment, then
# DJANGO_SETTINGS_MODULE or stop.
MANAGE_WRAPPER = """\
set -euo pipefail
set -a
. "$GRAPHYARD_CONDITIONS_ENV_FILE"
set +a
if [ -z "${DJANGO_SETTINGS_MODULE:-}" ]; then
  echo "DJANGO_SETTINGS_MODULE is not set in $GRAPHYARD_CONDITIONS_ENV_FILE" >&2
  exit 1
fi
exec "$GRAPHYARD_CONDITIONS_PYTHON" "$GRAPHYARD_CONDITIONS_MANAGE_PY" "$@"
"""

Number = StrictInt | StrictFloat


class DiskUsageCondition(BaseModel):
    """One entry of the playbook's ``macmini_graphyard_disk_usage_conditions``."""

    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    host: Annotated[str, Field(min_length=1)]
    mountpoint: str
    # The playbook's ``is number`` (an int or a float, not text).
    warning_threshold: Number
    critical_threshold: Number
    # The seed's defaults: the name from host and mountpoint, gte, 30 and 5 minutes.
    name: str | None = None
    operator: str = "gte"
    window_minutes: StrictInt = 30
    breach_minutes: StrictInt = 5
    # ``enabled | default(true) | bool``: false skips the entry (it is not removed).
    enabled: StrictBool = True

    @field_validator("mountpoint")
    @classmethod
    def _absolute(cls, value: str) -> str:
        if not value.startswith("/"):
            raise ValueError("mountpoint must be an absolute path")
        return value

    @model_validator(mode="after")
    def _ordered_ratios(self) -> DiskUsageCondition:
        if not 0.0 < float(self.warning_threshold) <= float(self.critical_threshold) <= 1.0:
            raise ValueError("warning/critical ratios must be ordered within (0, 1]")
        return self

    @property
    def listed_name(self) -> str:
        """The name the API must list: ``item.name | default(...)`` (a set name, even an empty one)."""

        return self.name if self.name is not None else f"Host filesystem usage ({self.host} {self.mountpoint})"

    def spec(self) -> str:
        """The seed's stdin (the playbook's ``item | to_json``)."""

        return json.dumps(self.model_dump(exclude_none=True))


class GraphyardConditionsConfig(RoleConfig):
    """The playbook's inputs (each overridable there by a ``macmini_graphyard_*`` variable)."""

    conditions: Annotated[tuple[DiskUsageCondition, ...], Field(min_length=1)]
    python: PurePosixPath = PurePosixPath("/opt/apps/graphyard/site/.venv/bin/python")
    manage_py: PurePosixPath = PurePosixPath("/opt/apps/graphyard/site/src/django/manage.py")
    workdir: PurePosixPath = PurePosixPath("/opt/apps/graphyard/site/src/django")
    system_user: UnixUser = "graphyard"
    # ``HOME`` for the commands, as ``become_user`` sets it.
    home: PurePosixPath = PurePosixPath("/opt/apps/graphyard")
    env_file: PurePosixPath = PurePosixPath("/etc/graphyard/graphyard.env")
    conditions_url: Url = "http://127.0.0.1:8051/v1/conditions"

    @field_validator("python", "manage_py", "workdir", "home", "env_file")
    @classmethod
    def _absolute_paths(cls, value: PurePosixPath) -> PurePosixPath:
        return absolute(value)

    @property
    def enabled(self) -> tuple[DiskUsageCondition, ...]:
        return tuple(condition for condition in self.conditions if condition.enabled)


def manage(cfg: GraphyardConditionsConfig, *args: str) -> str:
    """``manage.py <args>`` through the playbook's wrapper, as the Graphyard user in the workdir."""

    env = {
        "HOME": str(cfg.home),
        "GRAPHYARD_CONDITIONS_ENV_FILE": str(cfg.env_file),
        "GRAPHYARD_CONDITIONS_PYTHON": str(cfg.python),
        "GRAPHYARD_CONDITIONS_MANAGE_PY": str(cfg.manage_py),
    }
    command = runuser(cfg.system_user, ["/bin/bash", "-c", MANAGE_WRAPPER, "graphyard-manage", *args], env=env)
    return f"cd {shlex.quote(str(cfg.workdir))} && {command}"


def pending_conditions(output: str | None, count: int) -> set[int]:
    """Indexes the probe found missing or different; all of them when it failed or said too little."""

    if output is None:
        return set(range(count))
    current: set[int] = set()
    for line in output.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[0] == "condition" and parts[1].isdigit() and parts[2] == "current":
            current.add(int(parts[1]))
    return set(range(count)) - current


def conditions_steps(cfg: GraphyardConditionsConfig) -> None:
    enabled = cfg.enabled
    specs = json.dumps([json.loads(condition.spec()) for condition in enabled])
    check = manage(cfg, "shell", "-c", CONDITIONS_PROBE)
    found = probe(check, name="graphyard conditions", stdin=specs) if enabled else ""
    pending = pending_conditions(found, len(enabled))
    for index, condition in enumerate(enabled):
        if index not in pending:
            continue
        server.shell(
            name=f"Seed Graphyard disk-usage condition {condition.host} {condition.mountpoint}",
            commands=[manage(cfg, "shell", "-c", SEED_SCRIPT)],
            **stdin_arguments(condition.spec()),
        )
    if enabled and found is None:
        verify_probe(check, name="graphyard conditions", expect="current", stdin=specs)
    names = json.dumps([condition.listed_name for condition in enabled])
    mark_read_only(
        server.shell(
            name="Read Graphyard conditions summary",
            commands=[shlex.join(["python3", "-I", "-c", CONDITIONS_API, cfg.conditions_url, names])],
        )
    )


@deploy("Seed graphyard conditions")
def deploy_graphyard_conditions(cfg: GraphyardConditionsConfig) -> None:
    conditions_steps(cfg)
