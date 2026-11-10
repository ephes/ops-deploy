"""The Daybook operations backup bridge's registration (ops-library ``daybook_operations_api_backup``).

Port of the role's ``tasks_from: register_echoport`` as ops-control's
``playbooks/register-daybook-operations-backup.yml`` runs it, after the
playbook's ``common/backup_minio_account.yml`` (:func:`.access.minio_access`).
Unlike the ``fastdeploy_runner`` runners this one is a fixed-source bridge
(``files/daybook_operations/echoport_runner.py``, the role's
``files/echoport_runner.py`` byte for byte) installed directly as
``/usr/local/libexec/daybook-operations-backup``, with its own policy file, a
sudoers rule that allows only ``--config *``, and a FastDeploy service row
written directly (the role does not run ``syncservices``, so no other service
is synced).

:func:`install_daybook_operations_backup` runs the role's tasks in its order:

1. the role's asserts (:class:`DaybookOperationsBackup`), while planning;
2. the runner and upload directories (``root:root``);
3. the bridge script (``root:root 0755``);
4. the policy (``root:root 0600``) and FastDeploy's ``config.json``
   (``root:root 0644``), as the role's ``to_nice_json`` (no final newline);
5. the sudoers rule, validated with ``visudo`` before it goes live;
6. the FastDeploy ``service`` row, upserted as the role's query does, only
   when the stored data differs (read while planning);
7. the FastDeploy token and the Echoport target with the role's own script
   (``files/targets/daybook_operations.py``, :func:`.target.token_and_target`):
   a token is issued only when the stored one is due, as the role's
   ``service_token_status.py`` decides, and the user name reaches
   ``issueservicetoken`` on stdin (the role passes it in argv).

The role's target script saves on every run; the port runs it only when its
check mode finds a difference, so a converged row keeps its ``updated_at``.
:func:`registered_schedule` is the schedule the run leaves on the target (the
role's ``daybook_operations_api_backup_registered_schedule``), read while
planning; ops-control upserts the playbook's Nyxmon checks with it.
"""

from __future__ import annotations

import json
import re
import shlex
from io import StringIO
from pathlib import Path, PurePosixPath
from typing import Annotated, Any

from pydantic import Field, model_validator
from pyinfra.api import DeployError, deploy
from pyinfra.operations import files, server

from ops_deploy.base._common import RoleConfig
from ops_deploy.helpers.probes import last_line, probe, verify_probe, when_present
from ops_deploy.helpers.python import _as_user
from ops_deploy.helpers.users import sudoers_file
from ops_deploy.services._echoport_runner.access import MinioAccess, PlainPath, User, minio_access
from ops_deploy.services._echoport_runner.target import (
    ECHOPORT_SITE,
    ECHOPORT_USER,
    RunnerTarget,
    ServiceToken,
    target_script,
    token_and_target,
)

BRIDGE = (Path(__file__).parent / "files" / "daybook_operations" / "echoport_runner.py").read_text()
# The role's fixed paths (its first assert).
RUNNER = "/usr/local/libexec/daybook-operations-backup"
POLICY = "/etc/daybook-operations-backup.json"
SUDOERS = "daybook_operations_backup"
STEPS = ("backup", "upload", "verify", "result")
DESCRIPTION = "Daybook operations backup; attended restore only"
_Name = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_-]+$")]
_Bucket = Annotated[str, Field(pattern=r"^[a-z][a-z0-9-]+$")]
_Cron = Annotated[str, Field(pattern=r"^[0-9*/,\- ]*$", max_length=100)]


class DaybookOperationsBackup(RoleConfig):
    """The role variables the playbook passes (``defaults/main.yml`` otherwise).

    ``schedule``: the role's ``..._schedule`` (the playbook's
    ``operations_backup_schedule | default('17 4 * * *')``); it reaches the
    target only when the target is new or ``update_schedule`` is set (the
    playbook sets it when ``operations_backup_schedule`` is given).
    """

    access: MinioAccess
    runner: PlainPath = RUNNER
    policy: PlainPath = POLICY
    user: User = "daybook-operations"
    python: PlainPath = "/home/daybook-operations/venv/bin/python"
    script: PlainPath = "/home/daybook-operations/site/services/operations_api/lifecycle.py"
    config: PlainPath = "/etc/daybook-operations/lifecycle.json"
    backup_root: PlainPath = "/opt/backups/daybook_operations"
    staging: PlainPath = "/var/lib/daybook-operations-backup"
    mc: PlainPath = "/usr/local/bin/mc"
    target: _Name = "daybook_operations_api"
    fastdeploy_service: _Name = "daybook-operations-backup"
    fastdeploy_root: PlainPath = "/home/fastdeploy/site"
    fastdeploy_database: Annotated[str, Field(pattern=r"^[a-z_][a-z0-9_]*$")] = "fastdeploy"
    echoport_root: PlainPath = str(ECHOPORT_SITE)
    schedule: _Cron = ""
    update_schedule: bool = False
    retention_days: int = Field(default=30, ge=1)
    token_origin: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")] = "echoport"
    token_days: int = Field(default=90, ge=1, le=90)
    token_renewal_days: int = Field(default=30, ge=1)
    rotate_service_token: bool = False

    @model_validator(mode="after")
    def _role_asserts(self) -> DaybookOperationsBackup:
        problems = []
        if self.runner != RUNNER or self.policy != POLICY:
            problems.append(f"the runner must be {RUNNER} and the policy {POLICY}")
        if self.access.target != self.target:
            problems.append("the object-store access must be the target's")
        if not re.fullmatch(r"[a-z][a-z0-9_-]+", self.alias):
            problems.append("the alias must match ^[a-z][a-z0-9_-]+$")
        if not re.fullmatch(r"[a-z][a-z0-9-]+", self.bucket):
            problems.append("the bucket must match ^[a-z][a-z0-9-]+$")
        if self.token_renewal_days >= self.token_days:
            problems.append("token_renewal_days must stay below token_days")
        if problems:
            raise ValueError("daybook_operations_api_backup: " + "; ".join(problems))
        return self

    @property
    def bucket(self) -> str:
        return self.access.bucket

    @property
    def alias(self) -> str:
        return self.access.alias

    @property
    def service_dir(self) -> str:
        return f"{self.fastdeploy_root}/services/{self.fastdeploy_service}"


def to_nice_json(data: Any) -> str:
    """Ansible's ``to_nice_json`` (sorted keys, four spaces), as ``copy: content:`` writes it."""

    return json.dumps(data, indent=4, sort_keys=True, separators=(",", ": "))


def policy(cfg: DaybookOperationsBackup) -> str:
    return to_nice_json(
        {
            "user": cfg.user,
            "python": cfg.python,
            "lifecycle": cfg.script,
            "config": cfg.config,
            "backup_root": cfg.backup_root,
            "staging_root": cfg.staging,
            "mc": cfg.mc,
            "alias": cfg.alias,
            "bucket": cfg.bucket,
            "target": cfg.target,
            "lock": cfg.staging + "/bridge.lock",
        }
    )


def service_payload(cfg: DaybookOperationsBackup) -> dict[str, Any]:
    """The role's ``daybook_operations_api_backup_service_payload``, in its key order."""

    return {
        "name": cfg.fastdeploy_service,
        "description": DESCRIPTION,
        "deploy_script": cfg.runner,
        "steps": [{"name": step} for step in STEPS],
    }


def service_config(cfg: DaybookOperationsBackup) -> str:
    return to_nice_json(service_payload(cfg))


def sudoers_rule(cfg: DaybookOperationsBackup) -> str:
    return (
        f"fastdeploy ALL=(deploy) NOPASSWD:NOSETENV: {cfg.runner} --config *\n"
        f"deploy ALL=(root) NOPASSWD:NOSETENV: {cfg.runner} --config *\n"
    )


def _psql(cfg: DaybookOperationsBackup, sql: str) -> str:
    argv = ["runuser", "-u", "postgres", "--", "psql", "-XAtq", "-v", "ON_ERROR_STOP=1", "-d", cfg.fastdeploy_database]
    return shlex.join([*argv, "-c", sql])


def _stored_service(cfg: DaybookOperationsBackup) -> str:
    return _psql(cfg, f"select data::text from service where name = '{cfg.fastdeploy_service}'")


def upsert_service_sql(cfg: DaybookOperationsBackup) -> str:
    """The role's ``postgresql_query`` with its parameters inlined (Ansible's ``to_json`` of the payload)."""

    data = json.dumps(service_payload(cfg))
    if "'" in data or "\\" in data:
        raise ValueError("the FastDeploy service data must not contain quotes or backslashes")
    return (
        f"INSERT INTO service (name, data) VALUES ('{cfg.fastdeploy_service}', '{data}'::json) "
        "ON CONFLICT (name) DO UPDATE SET data = EXCLUDED.data "
        "WHERE service.data::jsonb IS DISTINCT FROM EXCLUDED.data::jsonb"
    )


def runner_target(cfg: DaybookOperationsBackup) -> RunnerTarget:
    """The role's target script with its values, and its token settings."""

    return RunnerTarget(
        name=cfg.target,
        script=target_script("daybook_operations"),
        values={
            "target_name": cfg.target,
            "service_name_fd": cfg.fastdeploy_service,
            "default_bucket": cfg.bucket,
            "target_schedule": cfg.schedule,
            "update_schedule": cfg.update_schedule,
            "target_retention_days": cfg.retention_days,
        },
        token=ServiceToken(
            targets=(cfg.target,),
            service=cfg.fastdeploy_service,
            origin=cfg.token_origin,
            days=cfg.token_days,
            renewal_days=cfg.token_renewal_days,
            force_rotate=cfg.rotate_service_token,
            fastdeploy_root=PurePosixPath(cfg.fastdeploy_root),
        ),
        site=PurePosixPath(cfg.echoport_root),
    )


_SCHEDULE_CODE = (
    "import json\n"
    "from backups.models import BackupTarget\n"
    "t = BackupTarget.objects.filter(name={name!r}).first()\n"
    "print(json.dumps(None if t is None else t.schedule))\n"
)


def registered_schedule(cfg: DaybookOperationsBackup) -> str:
    """The schedule the target has after this run (read while planning).

    A new target or ``update_schedule`` gets ``schedule``; an existing target
    keeps its own, as the role's script decides.
    """

    if cfg.update_schedule:
        return cfg.schedule
    run = _as_user(
        ECHOPORT_USER,
        PurePosixPath("/home") / ECHOPORT_USER,
        {},
        [".venv/bin/python", "manage.py", "shell", "-c", _SCHEDULE_CODE.format(name=cfg.target)],
    )
    site = PurePosixPath(cfg.echoport_root)
    command = when_present(
        [site / "manage.py"], last_line(f"cd {shlex.quote(str(site))} && {run}"), otherwise="missing"
    )
    found = (probe(command, name=f"Echoport schedule of {cfg.target}") or "").strip()
    if found == "missing":
        raise DeployError(f"Echoport is not installed at {site}; register the bridge after Echoport")
    try:
        stored = json.loads(found)
    except ValueError as exc:
        raise DeployError(f"could not read the Echoport schedule of {cfg.target}") from exc
    if stored is None:
        return cfg.schedule
    if not isinstance(stored, str):
        raise DeployError(f"could not read the Echoport schedule of {cfg.target}")
    return stored


def install_daybook_operations_backup(cfg: DaybookOperationsBackup, *, secret_key: str, token_user: str) -> None:
    """The playbook's MinIO access and the role's ``register_echoport`` (call inside a deploy)."""

    minio_access(cfg.access, access_key=cfg.access.account.user, secret_key=secret_key)
    for path, mode in (("/usr/local/libexec", "0755"), (cfg.staging, "0700"), (cfg.service_dir, "0755")):
        files.directory(name=f"Ensure directory {path}", path=path, user="root", group="root", mode=mode)
    files.put(
        name="Install the Daybook operations backup bridge",
        src=StringIO(BRIDGE),
        dest=cfg.runner,
        user="root",
        group="root",
        mode="0755",
        create_remote_dir=False,
    )
    files.put(
        name="Write the backup bridge policy",
        src=StringIO(policy(cfg)),
        dest=cfg.policy,
        user="root",
        group="root",
        mode="0600",
        create_remote_dir=False,
    )
    files.put(
        name=f"Write config.json of {cfg.fastdeploy_service}",
        src=StringIO(service_config(cfg)),
        dest=f"{cfg.service_dir}/config.json",
        user="root",
        group="root",
        mode="0644",
        create_remote_dir=False,
    )
    sudoers_file(SUDOERS, sudoers_rule(cfg))
    stored = probe(_stored_service(cfg), name=f"FastDeploy service {cfg.fastdeploy_service}")
    try:
        current = bool(stored and stored.strip() and json.loads(stored) == service_payload(cfg))
    except ValueError:
        current = False
    if not current:
        server.shell(
            name=f"Register the FastDeploy service {cfg.fastdeploy_service}",
            commands=[_psql(cfg, upsert_service_sql(cfg))],
        )
    if stored is None:
        verify_probe(_stored_service(cfg), name=f"FastDeploy service {cfg.fastdeploy_service}")
    token_and_target(runner_target(cfg), token_user)


register_daybook_operations_backup = deploy("Daybook operations backup bridge registration")(
    install_daybook_operations_backup
)

__all__ = [
    "DaybookOperationsBackup",
    "install_daybook_operations_backup",
    "policy",
    "register_daybook_operations_backup",
    "registered_schedule",
    "runner_target",
    "service_config",
    "service_payload",
    "sudoers_rule",
    "upsert_service_sql",
]
