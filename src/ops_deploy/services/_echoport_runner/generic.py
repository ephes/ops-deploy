"""The generic runner ``echoport-backup``: its register playbook as one deploy.

ops-control's ``playbooks/register-echoport-backup.yml`` runs ops-library's
``echoport_backup`` role and then ``common/backup_minio_account.yml`` once per
target the runner serves. One runner script serves many Echoport targets; it
picks the ``mc`` alias by the first segment of the object key
(``MINIO_PREFIX_ALIASES``), so every target has its own scoped MinIO account
and root ``mc`` alias. :class:`GenericRunnerRegistration` carries the values;
:func:`install_generic_registration` does the tasks in the playbook's order:

1. the role's ``sqlite3`` package (``ansible.builtin.package``, no cache update);
2. the role's pinned ``mc`` (``minio_backup`` ``mc_install``: ``get_url`` with
   the checksum, ``root:root 0755``), through the MinIO deploy's helper: kept
   when the checksum matches, else downloaded and verified before it replaces
   the file;
3. ``fastdeploy_runner`` with the role's settings (:func:`.install_runner`);
4. per target, in the playbook's order, the scoped MinIO account and root's
   alias (:func:`.access.minio_access`).

The role's own ``minio_alias`` include is skipped by the playbook (it passes
no credentials), so it is not ported.

Beyond the playbook:

- the accesses need ``mc`` while planning (they read the accounts and
  aliases through it), so a host without ``mc`` is refused before any write;
  the MinIO deploy installs the same pinned client;
- the retired shared alias is looked up and removed once (with the first
  target) instead of once per target; the playbook's later iterations find
  nothing to remove. Every access must retire the same aliases (they are
  all root's).
"""

from __future__ import annotations

import shlex
from collections.abc import Mapping
from typing import Any

from pydantic import Field, model_validator
from pyinfra.api import DeployError, deploy
from pyinfra.operations import apt

from ops_deploy.base._common import RoleConfig
from ops_deploy.helpers.probes import probe
from ops_deploy.services._echoport_runner import RunnerConfig, install_runner
from ops_deploy.services._echoport_runner.access import MinioAccess, minio_access
from ops_deploy.services._echoport_runner.registration import Package, _template_source
from ops_deploy.services.minio.config import MC_DOWNLOAD_URL, MC_SHA256
from ops_deploy.services.minio.deploy import binary

TEMPLATE = "backup.py.j2"
PREFIX_ALIASES = "echoport_backup_minio_prefix_aliases"


class GenericRunnerRegistration(RoleConfig):
    """``register-echoport-backup.yml``: the role's runner and one access per target.

    ``accesses`` are the targets in the playbook's loop order; ``variables``
    are the template variables, resolved. The prefix alias map must name
    exactly those targets with their aliases, in that order (the runner
    renders it as written).
    """

    runner: RunnerConfig
    accesses: tuple[MinioAccess, ...] = Field(min_length=1)
    variables: Mapping[str, Any]
    packages: tuple[Package, ...] = ("sqlite3",)

    @model_validator(mode="after")
    def _playbook_asserts(self) -> GenericRunnerRegistration:
        problems = []
        if self.runner.template != TEMPLATE:
            problems.append(f"the generic runner renders {TEMPLATE}")
        elif "_work_dir.py.j2" not in _template_source(TEMPLATE):
            # The playbook's "Require a generic runner that works on the external disk only".
            problems.append(f"{TEMPLATE} does not include _work_dir.py.j2")
        if self.runner.run_as != "root":
            problems.append("the generic runner runs as root")
        targets = [access.target for access in self.accesses]
        if len(set(targets)) != len(targets):
            problems.append("every target has one access")
        if len({access.retired_aliases for access in self.accesses}) > 1:
            # They are removed once, with the first access.
            problems.append("every access retires the same aliases")
        for access in self.accesses:
            if access.os_user != "root" or not access.scoped:
                problems.append(f"{access.target}: root's alias of its scoped account (a secret) is required")
        aliases = self.variables.get(PREFIX_ALIASES)
        wanted = [(access.target, access.alias) for access in self.accesses]
        if not isinstance(aliases, Mapping) or list(aliases.items()) != wanted:
            problems.append(f"{PREFIX_ALIASES} must map each target to its access's alias, in order")
        for name, field in (("echoport_backup_mc_install_path", "mc"), ("echoport_backup_default_bucket", "bucket")):
            if any(self.variables.get(name) != getattr(access, field) for access in self.accesses):
                problems.append(f"{name} must be every access's {field}")
        if not isinstance(self.variables.get("echoport_backup_minio_require_prefix_alias"), bool):
            problems.append("echoport_backup_minio_require_prefix_alias must be a bool")
        if problems:
            raise ValueError("generic runner registration: " + "; ".join(problems))
        return self


def install_generic_registration(cfg: GenericRunnerRegistration, *, secrets: Mapping[str, str]) -> None:
    """The playbook's tasks (call inside a deploy); ``secrets``: each target's scoped account secret.

    Every refusal (a missing ``mc``, an unsafe directory above the libexec
    root, a bad secret) happens while planning, before any write.
    """

    targets = [access.target for access in cfg.accesses]
    if set(secrets) != set(targets):
        raise DeployError("the generic runner needs exactly the secrets of its targets (values withheld)")
    mc = cfg.accesses[0].mc
    if (probe(f"test -x {shlex.quote(mc)} && echo present || echo missing", name=f"mc at {mc}") or "").strip() != (
        "present"
    ):
        raise DeployError(f"mc (MinIO client) not found at {mc}; `just deploy-one minio` installs the pinned client")
    apt.packages(name=f"Install the packages of {cfg.runner.service}", packages=list(cfg.packages), update=False)
    binary(mc, None, MC_SHA256, MC_DOWNLOAD_URL, "MinIO client")
    install_runner(cfg.runner, cfg.variables)
    for index, access in enumerate(cfg.accesses):
        once = access if index == 0 else access.model_copy(update={"retired_aliases": ()})
        minio_access(once, access_key=access.account.user, secret_key=secrets[access.target])


register_generic_runner = deploy("Echoport generic runner registration")(install_generic_registration)

__all__ = ["GenericRunnerRegistration", "install_generic_registration", "register_generic_runner"]
