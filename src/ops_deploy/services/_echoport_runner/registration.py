"""One register playbook of an Echoport backup runner without an Echoport row write, as one deploy.

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

The runners of classes A2 and A3 run as the deploy user:
:class:`DeployRunnerRegistration` is their playbook (homepage-staging,
python-podcast-staging, marina-staging, homepage-production-db and
python-podcast-production-db: the remote ones, which reach their hosts over
SSH; homepage-media and python-podcast-media: rclone between two object
stores). Their playbooks add the runner's work dir on the external disk
(``common/backup_work_dir.yml``), the known hosts
(``common/deploy_known_host_ed25519.yml``), the deploy user's SSH key, or
the media runner's credentials file, each in its own order, which
:attr:`DeployRunnerRegistration.tasks` records.
"""

from __future__ import annotations

import itertools
import json
import posixpath
import re
import shlex
from collections.abc import Callable, Mapping
from typing import Annotated, Any, Literal

from pydantic import Field, model_validator
from pyinfra.api import DeployError, deploy
from pyinfra.operations import apt, files

from ops_deploy.base._common import RoleConfig
from ops_deploy.core.secrets import SecretContent
from ops_deploy.helpers.probes import probe
from ops_deploy.ops import secret_file
from ops_deploy.services._echoport_runner import RunnerConfig, install_runner
from ops_deploy.services._echoport_runner import access as _access
from ops_deploy.services._echoport_runner.access import (
    KnownHost,
    MinioAccess,
    PlainPath,
    WorkDir,
    known_hosts_entries,
    minio_access,
    require_mc,
)
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


# -- runners that run as the deploy user (classes A2 and A3) ----------------------

# A playbook task of a deploy-user runner, in the playbook's own order:
# "ssh_key": the deploy user's SSH directory and key pair;
# "known_hosts": the deploy_known_host_ed25519.yml includes, then "Ensure known_hosts ownership";
# "mc": "Ensure mc is installed"; "packages": ``ansible.builtin.package``;
# "access": backup_minio_account.yml; "work_dir": backup_work_dir.yml;
# "credentials": the media runner's credentials directory and file; "runner": fastdeploy_runner.
Task = Literal["ssh_key", "known_hosts", "mc", "packages", "access", "work_dir", "credentials", "runner"]
# Template variables named ``<prefix><suffix>`` must say what the registration provisions.
_BOUND_SUFFIXES = ("_work_dir", "_work_mount", "_credentials_file", "_minio_url", "_default_bucket")
# S3 bucket names; the media templates put the source bucket into a Python string literal unquoted.
_BUCKET = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
# What the media playbooks require of their template while the target has its scoped account.
NO_CHECK_DEST = "--no-check-dest"


class CredentialsFile(RoleConfig):
    """The media runner's credentials file: ``root:<deploy group> 0640`` in a ``root:<deploy group> 0750`` directory."""

    path: PlainPath

    @model_validator(mode="after")
    def _below_a_directory(self) -> CredentialsFile:
        # The directory is made root:<deploy group> 0750: never / or a top-level one such as /etc.
        normal = posixpath.normpath(self.path)
        if normal != self.path or "//" in self.path or posixpath.dirname(normal).count("/") < 2:
            raise ValueError("the credentials file must be a normalized path in a directory of its own")
        return self

    @property
    def directory(self) -> str:
        return posixpath.dirname(self.path)


class DeployKey(RoleConfig):
    """The deploy user's SSH key pair (``deploy_ssh_keys.yml`` ``ssh_private_key``, ``ssh_public_key``)."""

    private: str = Field(repr=False, min_length=1)
    public: str = Field(repr=False, min_length=1)


class MediaSource(RoleConfig):
    """The media runner's source bucket and its credentials (the service's ``django_aws_*`` secrets)."""

    bucket: str = Field(repr=False)
    access_key: str = Field(repr=False, min_length=1)
    secret_key: str = Field(repr=False, min_length=1)

    @model_validator(mode="after")
    def _bucket_name(self) -> MediaSource:
        if not _BUCKET.match(self.bucket):
            raise ValueError("the source bucket must be an S3 bucket name (value withheld)")
        return self


def media_credentials(source: MediaSource, *, access_key: str, secret_key: str) -> str:
    """The media playbooks' credentials file: their ``copy`` content, ``to_json`` and all."""

    values = (source.access_key, source.secret_key, access_key, secret_key)
    names = ("source_access_key", "source_secret_key", "dest_access_key", "dest_secret_key")
    lines = [f'  "{name}": {json.dumps(value)}' for name, value in zip(names, values, strict=True)]
    return "{\n" + ",\n".join(lines) + "\n}\n"


class DeployRunnerRegistration(RoleConfig):
    """A register playbook of a runner that runs as the deploy user (design note classes A2 and A3).

    ``tasks`` is the playbook's order of the parts above (:data:`Task`); each
    part the registration has appears exactly once. ``known_hosts`` are the
    playbook's ``deploy_known_host_ed25519.yml`` includes, in order, all on
    the deploy user's known_hosts file. ``ssh_key``: the playbook installs the
    deploy user's SSH key pair. ``credentials`` (the media runners): the
    access has no ``mc`` alias (``os_user`` ``none``) and the runner reads
    the store credentials from that file instead; ``source_bucket_variable``
    is the template variable that gets the source bucket, which comes from
    the service's secrets with the source credentials.
    """

    runner: RunnerConfig
    access: MinioAccess
    packages: tuple[Package, ...]
    variables: Mapping[str, Any]
    work_dir: WorkDir
    tasks: tuple[Task, ...]
    known_hosts: tuple[KnownHost, ...] = ()
    ssh_key: bool = False
    credentials: CredentialsFile | None = None
    source_bucket_variable: str | None = None

    @property
    def home(self) -> str:
        return f"/home/{self.runner.deploy_user}"

    @property
    def known_hosts_path(self) -> str:
        return f"{self.home}/.ssh/known_hosts"

    @model_validator(mode="after")
    def _playbook_asserts(self) -> DeployRunnerRegistration:
        problems = []
        source = None
        if self.runner.template is None or self.runner.template not in runner_templates():
            problems.append("the runner must come from a vendored runner template")
        else:
            source = _template_source(self.runner.template)
            if "_work_dir.py.j2" not in source:
                # The playbooks' "Require a runner that works on the external disk only".
                problems.append(f"{self.runner.template} does not include _work_dir.py.j2")
        deploy_user = self.runner.deploy_user
        if self.runner.run_as:
            problems.append("a deploy-user runner has no run_as rule (only fastdeploy -> deploy)")
        if self.work_dir.owner != deploy_user:
            problems.append(f"the work dir belongs to the runner's user {deploy_user}")
        if not self.access.scoped:
            # The shared alias is retired for deploy; the media fallback to root's credentials stays with the playbook.
            problems.append("the target needs its scoped account (a secret in minio-backup-accounts.yml)")
        if self.credentials is None:
            if self.access.os_user != deploy_user:
                problems.append(f"the runner reads {deploy_user}'s mc alias")
            if self.source_bucket_variable is not None:
                problems.append("only a media runner gets a source bucket")
        else:
            if self.access.os_user != "none":
                problems.append("a media runner reads its credentials file and gets no mc alias (os_user none)")
            name = self.source_bucket_variable
            if name is None or not name.endswith("_source_bucket") or name in self.variables:
                problems.append("a media runner names its <prefix>_source_bucket variable (it comes from secrets)")
            if source is not None and self.access.scoped and NO_CHECK_DEST not in source:
                # The media playbooks' "Require a media runner that works with a scoped MinIO account".
                problems.append(f"{self.runner.template} uploads the manifest without {NO_CHECK_DEST}")
        for name, field in _ACCESS_VARIABLES.items():
            if name in self.variables and self.variables[name] != getattr(self.access, field):
                problems.append(f"{name} must be the access's {field}")
        bound = {
            "_work_dir": self.work_dir.path,
            "_work_mount": self.work_dir.mount,
            "_credentials_file": None if self.credentials is None else self.credentials.path,
            "_minio_url": self.access.url,
            "_default_bucket": self.access.bucket,
        }
        for name, value in self.variables.items():
            suffix = next((s for s in _BOUND_SUFFIXES if name.endswith(s)), None)
            if suffix is not None and value != bound[suffix]:
                problems.append(f"{name} must be what the registration provisions ({suffix.lstrip('_')})")
        if any(cfg.path != self.known_hosts_path for cfg in self.known_hosts):
            problems.append(f"the known hosts go to {self.known_hosts_path}")
        wanted = {
            "ssh_key": self.ssh_key,
            "known_hosts": bool(self.known_hosts),
            "packages": bool(self.packages),
            "credentials": self.credentials is not None,
        }
        required = {"access", "work_dir", "runner"} | {task for task, present in wanted.items() if present}
        if len(set(self.tasks)) != len(self.tasks) or not required <= set(self.tasks) <= required | {"mc"}:
            problems.append(f"tasks must name each part exactly once: {', '.join(sorted(required))} (and mc)")
        if problems:
            raise ValueError("runner registration: " + "; ".join(problems))
        return self


def _ssh_key(cfg: DeployRunnerRegistration, key: DeployKey) -> None:
    """The production-db playbooks' deploy SSH directory and key pair (``copy`` of the secrets as they are)."""

    user = cfg.runner.deploy_user
    files.directory(
        name=f"Ensure the SSH directory of {user}", path=f"{cfg.home}/.ssh", user=user, group=user, mode="0700"
    )
    for name, value, mode in (("id_ed25519", key.private, "0600"), ("id_ed25519.pub", key.public, "0644")):
        secret_file(
            name=f"Install the SSH key {name} of {user}",
            path=f"{cfg.home}/.ssh/{name}",
            content=SecretContent(value),
            user=user,
            group=user,
            mode=mode,
        )


def _known_hosts(cfg: DeployRunnerRegistration, keyscan: Callable[[str], str] | None) -> None:
    known_hosts_entries(cfg.known_hosts, keyscan or _access.controller_keyscan)
    user = cfg.runner.deploy_user
    files.file(
        name=f"Ensure the ownership of {cfg.known_hosts_path}",
        path=cfg.known_hosts_path,
        user=user,
        group=user,
        mode="0644",
        create_remote_dir=False,
    )


def _credentials(cfg: DeployRunnerRegistration, source: MediaSource, secret_key: str) -> None:
    assert cfg.credentials is not None
    group = cfg.runner.deploy_user
    files.directory(
        name=f"Ensure the credentials directory {cfg.credentials.directory}",
        path=cfg.credentials.directory,
        user="root",
        group=group,
        mode="0750",
    )
    secret_file(
        name=f"Install the credentials file {cfg.credentials.path}",
        path=cfg.credentials.path,
        content=SecretContent(media_credentials(source, access_key=cfg.access.account.user, secret_key=secret_key)),
        user="root",
        group=group,
        mode="0640",
    )


def install_deploy_registration(
    cfg: DeployRunnerRegistration,
    *,
    secret_key: str,
    ssh_key: DeployKey | None = None,
    source: MediaSource | None = None,
    keyscan: Callable[[str], str] | None = None,
) -> None:
    """The playbook's tasks for ``cfg`` in its order (call inside a deploy).

    ``secret_key``: the target's scoped account secret; ``ssh_key``: the
    deploy key pair, exactly when the playbook installs it; ``source``: the
    media runner's source bucket and credentials, exactly for a media runner.
    ``keyscan`` replaces the controller's ``ssh-keyscan`` (tests). Every
    refusal happens while planning, before any write.
    """

    if cfg.ssh_key != (ssh_key is not None):
        raise DeployError(f"{cfg.runner.service}: the deploy SSH key is needed exactly when the playbook installs it")
    if (cfg.credentials is None) != (source is None):
        raise DeployError(f"{cfg.runner.service}: the media source credentials are needed exactly for a media runner")
    variables = dict(cfg.variables)
    if source is not None:
        assert cfg.source_bucket_variable is not None
        variables[cfg.source_bucket_variable] = source.bucket
    for task in cfg.tasks:
        if task == "ssh_key":
            assert ssh_key is not None
            _ssh_key(cfg, ssh_key)
        elif task == "known_hosts":
            _known_hosts(cfg, keyscan)
        elif task == "mc":
            require_mc(cfg.access)
        elif task == "packages":
            apt.packages(
                name=f"Install the packages of {cfg.runner.service}", packages=list(cfg.packages), update=False
            )
        elif task == "access":
            minio_access(cfg.access, access_key=cfg.access.account.user, secret_key=secret_key)
        elif task == "work_dir":
            _access.work_dir(cfg.work_dir)
        elif task == "credentials":
            assert source is not None
            _credentials(cfg, source, secret_key)
        else:
            install_runner(cfg.runner, variables)


register_deploy_runner = deploy("Echoport backup runner registration")(install_deploy_registration)

__all__ = [
    "DEFAULT_IPV4_FALLBACK",
    "NO_CHECK_DEST",
    "CredentialsFile",
    "DeployKey",
    "DeployRunnerRegistration",
    "MediaSource",
    "RunnerRegistration",
    "default_ipv4",
    "install_deploy_registration",
    "install_registration",
    "media_credentials",
    "register_deploy_runner",
    "register_runner",
    "template_variables",
]
