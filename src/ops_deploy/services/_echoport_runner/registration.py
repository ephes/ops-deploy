"""One register playbook of a same-host runner that runs as root, as one deploy.

The register playbooks of design note class A1 (snappymail-backup,
delve-backup, echoport-self-backup, fastdeploy-backup, homeassistant-backup,
weeknotes-home-backup, paperless-backup) are the same tasks with other values:

1. install the runner's packages (``ansible.builtin.package``, no cache update);
2. refuse when ``mc`` is missing ("Ensure mc is installed");
3. ``common/backup_minio_account.yml`` for the target (:func:`.access.minio_access`);
4. require a runner template that works on the external disk only (it
   includes ``_work_dir.py.j2``);
5. ``fastdeploy_runner`` with the playbook's settings (:func:`.install_runner`).

:class:`RunnerRegistration` carries those values; ops-control builds it from
its registry of runners and passes the target's account secret. The Echoport
target row stays as it is (managed by hand, or by the service's own deploy).
"""

from __future__ import annotations

import itertools
import re
import shlex
from collections.abc import Mapping
from typing import Annotated, Any

from pydantic import Field, model_validator
from pyinfra.api import DeployError, deploy
from pyinfra.operations import apt

from ops_deploy.base._common import RoleConfig
from ops_deploy.helpers.probes import probe
from ops_deploy.services._echoport_runner import RunnerConfig, install_runner
from ops_deploy.services._echoport_runner.access import MinioAccess, minio_access
from ops_deploy.services._echoport_runner.render import _environment, runner_templates

Package = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9+.-]*$")]
# Ansible's fallback when the host has no default IPv4 route (homeassistant's playbook).
DEFAULT_IPV4_FALLBACK = "192.168.0.1"
# Ansible's ``ansible_default_ipv4``: the source address of the route to this address.
_ROUTE_PROBE = "ip -4 route get 8.8.8.8 2>/dev/null | head -n 1 || true"
_IPV4 = re.compile(r"^(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])){3}$")
# Template variables that name where the runner finds its object store; they must be the access's.
_ACCESS_VARIABLES = {
    "echoport_backup_minio_alias": "alias",
    "echoport_backup_mc_install_path": "mc",
    "echoport_backup_default_bucket": "bucket",
}


def _template_source(template: str) -> str:
    env = _environment()
    assert env.loader is not None
    return env.loader.get_source(env, template)[0]


class RunnerRegistration(RoleConfig):
    """A register playbook of a same-host root runner: packages, object-store access, the runner.

    ``variables`` are the template variables of the playbook, resolved (the
    ``echoport_backup_*`` ones included). ``default_ipv4_variables``: names
    the playbook sets to ``ansible_default_ipv4.address | default(...)``; they
    get the host's address, read while planning (the playbook reads the
    gathered fact, so a changed default route changes the rendered runner
    there too), and the template sees ``ansible_default_ipv4`` with that
    ``address`` (the only key the templates read).
    """

    runner: RunnerConfig
    access: MinioAccess
    packages: tuple[Package, ...]
    variables: Mapping[str, Any]
    default_ipv4_variables: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _playbook_asserts(self) -> RunnerRegistration:
        problems = []
        if self.runner.template is None or self.runner.template not in runner_templates():
            problems.append("the runner must come from a vendored runner template")
        elif "_work_dir.py.j2" not in _template_source(self.runner.template):
            # The playbooks' "Require a runner that works on the external disk only".
            problems.append(f"{self.runner.template} does not include _work_dir.py.j2")
        if self.runner.run_as != "root" or self.access.os_user != "root":
            problems.append("a same-host runner runs as root and reads root's mc alias")
        if not self.access.scoped:
            # root's shared alias is retired (backup_minio_account_legacy_alias_retired_for).
            problems.append("the target needs its scoped account (a secret in minio-backup-accounts.yml)")
        for name, field in _ACCESS_VARIABLES.items():
            if name in self.variables and self.variables[name] != getattr(self.access, field):
                problems.append(f"{name} must be the access's {field}")
        for name in self.default_ipv4_variables:
            if name in self.variables:
                problems.append(f"{name} comes from the host's address, not from variables")
        if problems:
            raise ValueError("runner registration: " + "; ".join(problems))
        return self


def default_ipv4() -> str | None:
    """The host's ``ansible_default_ipv4.address``: ``src`` of ``ip -4 route get 8.8.8.8`` (``None``: no route)."""

    words = (probe(_ROUTE_PROBE, name="default IPv4 address") or "").split()
    if not words or words[0] != "8.8.8.8":
        return None
    for key, value in itertools.pairwise(words):
        if key == "src":
            if not _IPV4.match(value):
                raise DeployError(f"unexpected source address in the default route: {shlex.quote(value)}")
            return value
    return None


def template_variables(cfg: RunnerRegistration) -> dict[str, Any]:
    """The variables the runner template renders with, the host's address included where the playbook reads it."""

    variables = dict(cfg.variables)
    if cfg.default_ipv4_variables:
        address = default_ipv4()
        variables["ansible_default_ipv4"] = {} if address is None else {"address": address}
        for name in cfg.default_ipv4_variables:
            variables[name] = address or DEFAULT_IPV4_FALLBACK
    return variables


def install_registration(cfg: RunnerRegistration, *, secret_key: str) -> None:
    """The playbook's tasks for ``cfg`` (call inside a deploy); ``secret_key``: the target's scoped account secret.

    Every refusal (a missing ``mc``, an unsafe directory above the libexec
    root, a bad secret) happens while planning, before any write.
    """

    variables = template_variables(cfg)
    apt.packages(name=f"Install the packages of {cfg.runner.service}", packages=list(cfg.packages), update=False)
    minio_access(cfg.access, access_key=cfg.access.account.user, secret_key=secret_key)
    install_runner(cfg.runner, variables)


register_runner = deploy("Echoport backup runner registration")(install_registration)

__all__ = [
    "DEFAULT_IPV4_FALLBACK",
    "RunnerRegistration",
    "default_ipv4",
    "install_registration",
    "register_runner",
    "template_variables",
]
