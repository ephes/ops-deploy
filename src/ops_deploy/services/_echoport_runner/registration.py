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
its registry of runners and passes the target's account secret. For class A1
the Echoport target row stays as it is (managed by hand, or by the service's
own deploy).

The same-host root runners of class B (mail-db-backup, postfixadmin-backup,
graphyard-backup) add their playbook's own steps around these:

- "Require the <runner> in the ops-library checkout": a text the vendored
  template must contain (``template_markers``), checked while planning;
- a credential file the runner reads (postfixadmin's database login,
  :class:`CredentialFile`), written after the object-store access as the
  playbook writes it;
- after the runner, the playbook's own Echoport target script
  (:mod:`.target`, with the FastDeploy service token when it issues one)
  and graphyard's own Nyxmon check script (:mod:`.nyxmon`).

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
from functools import cache
from pathlib import PurePosixPath
from typing import Annotated, Any, Literal

from jinja2 import meta, nodes
from pydantic import Field, model_validator
from pyinfra.api import DeployError, deploy
from pyinfra.operations import apt, files, server

from ops_deploy.base._common import RoleConfig
from ops_deploy.core.secrets import SecretContent
from ops_deploy.helpers.checks import mark_read_only
from ops_deploy.helpers.probes import probe
from ops_deploy.ops import secret_file
from ops_deploy.services._echoport_runner import RunnerConfig, _plain_path, install_runner
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
from ops_deploy.services._echoport_runner.nyxmon import NyxmonScript, upsert_nyxmon_script
from ops_deploy.services._echoport_runner.render import _environment, render_text, runner_templates, text_names
from ops_deploy.services._echoport_runner.target import RunnerTarget, token_and_target, upsert_runner_target

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


# A template variable without a constant ``| default(...)``.
_NO_DEFAULT = object()


@cache
def _template_variables(template: str) -> Mapping[str, Any]:
    """Every variable ``template`` reads -> its constant ``| default(...)``, else :data:`_NO_DEFAULT`.

    What the runner gets for a variable the registration leaves out. The
    includes read no variable of their own.
    """

    tree = _environment().parse(_template_source(template))
    found: dict[str, Any] = dict.fromkeys(meta.find_undeclared_variables(tree), _NO_DEFAULT)
    for node in tree.find_all(nodes.Filter):
        if (
            node.name == "default"
            and isinstance(node.node, nodes.Name)
            and len(node.args) == 1
            and isinstance(node.args[0], nodes.Const)
        ):
            found[node.node.name] = node.args[0].value
    return found


_Owner = Annotated[str, Field(pattern=r"^[a-z_][a-z0-9_-]*$")]


class CredentialFile(RoleConfig):
    """A file the playbook writes with ``copy: content:`` from a secret (and its directory with ``file``).

    ``template`` is the playbook's ``content`` text unchanged; ``variables``
    are the names it reads that hold no secret, resolved, and ``secrets`` the
    names whose values the deploy passes (from the controller's SOPS files).
    The file is written with :func:`ops_deploy.ops.secret_file`, so its
    content travels on stdin only.
    """

    path: str
    owner: _Owner = "root"
    group: _Owner = "root"
    mode: Literal["0600", "0640"] = "0600"
    directory_owner: _Owner = "root"
    directory_group: _Owner = "root"
    directory_mode: Literal["0700", "0750", "0755"] = "0700"
    template: str = Field(min_length=1)
    variables: Mapping[str, Any]
    secrets: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _complete(self) -> CredentialFile:
        problems = []
        if not _plain_path(self.path) or self.path.count("/") < 2:
            problems.append("the path must be a plain absolute path below a directory")
        names = text_names(self.template)
        given = set(self.variables) | set(self.secrets)
        if names != given:
            problems.append(f"the template reads {sorted(names)}, given {sorted(given)}")
        if set(self.variables) & set(self.secrets):
            problems.append("a name is both a variable and a secret")
        if problems:
            raise ValueError("credential file: " + "; ".join(problems))
        return self

    @property
    def directory(self) -> str:
        return str(PurePosixPath(self.path).parent)

    def content(self, secrets: Mapping[str, str]) -> str:
        """The file as Ansible's ``copy`` writes it, with the deploy's ``secrets``."""

        if set(secrets) != set(self.secrets):
            raise DeployError(f"{self.path} needs exactly the secrets {', '.join(self.secrets)} (values withheld)")
        return render_text(self.template, {**self.variables, **secrets})


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
    # Class B: the playbook's own checks of the template, files, target row and Nyxmon check.
    template_markers: tuple[str, ...] = ()
    credential_files: tuple[CredentialFile, ...] = ()
    target: RunnerTarget | None = None
    nyxmon: NyxmonScript | None = None

    @model_validator(mode="after")
    def _playbook_asserts(self) -> RunnerRegistration:
        problems = []
        if self.runner.template is None or self.runner.template not in runner_templates():
            problems.append("the runner must come from a vendored runner template")
        elif "_work_dir.py.j2" not in _template_source(self.runner.template):
            # The playbooks' "Require a runner that works on the external disk only".
            problems.append(f"{self.runner.template} does not include _work_dir.py.j2")
        else:
            source = _template_source(self.runner.template)
            # The class B playbooks' "Require the <runner> in the ops-library checkout".
            missing = [marker for marker in self.template_markers if marker not in source]
            problems += [f"{self.runner.template} lacks {marker!r}" for marker in missing]
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
        if self.target is not None:
            # In the playbooks the target's bucket and the runner's are one variable.
            for name in ("default_bucket", "echoport_backup_default_bucket"):
                if name in self.target.values and self.target.values[name] != self.access.bucket:
                    problems.append(f"the target's {name} must be the access's bucket")
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


def install_registration(
    cfg: RunnerRegistration,
    *,
    secret_key: str,
    token_user: str | None = None,
    credentials: Mapping[str, str] | None = None,
) -> None:
    """The playbook's tasks for ``cfg`` (call inside a deploy); ``secret_key``: the target's scoped account secret.

    ``token_user``: the FastDeploy user that issues the target's service token
    (a target with a token needs it); ``credentials``: the values of the
    credential files' ``secrets``. Every refusal (a missing ``mc``, an unsafe
    directory above the libexec root, a bad secret, a target script's
    refusal) happens while planning, before any write.
    """

    given = dict(credentials or {})
    wanted = {name for file in cfg.credential_files for name in file.secrets}
    if set(given) != wanted:
        raise DeployError(f"{cfg.runner.service} needs exactly the credentials {sorted(wanted)} (values withheld)")
    if cfg.target is not None and cfg.target.token is not None and token_user is None:
        raise DeployError(f"{cfg.runner.service} issues a FastDeploy token and needs the token user")
    contents = [(file, file.content({name: given[name] for name in file.secrets})) for file in cfg.credential_files]
    variables = template_variables(cfg)
    apt.packages(name=f"Install the packages of {cfg.runner.service}", packages=list(cfg.packages), update=False)
    minio_access(cfg.access, access_key=cfg.access.account.user, secret_key=secret_key)
    for file, content in contents:
        files.directory(
            name=f"Ensure directory {file.directory}",
            path=file.directory,
            user=file.directory_owner,
            group=file.directory_group,
            mode=file.directory_mode,
        )
        secret_file(
            name=f"Write {file.path}",
            path=file.path,
            content=SecretContent(content),
            user=file.owner,
            group=file.group,
            mode=file.mode,
        )
    install_runner(cfg.runner, variables)
    if cfg.target is not None:
        if cfg.target.token is None:
            upsert_runner_target(cfg.target)
        else:
            assert token_user is not None
            token_and_target(cfg.target, token_user)
    if cfg.nyxmon is not None:
        upsert_nyxmon_script(cfg.nyxmon)


register_runner = deploy("Echoport backup runner registration")(install_registration)


# -- runners that run as the deploy user (classes A2 and A3) ----------------------

# A playbook task of a deploy-user runner, in the playbook's own order:
# "ssh_key": the deploy user's SSH directory and key pair;
# "known_hosts": the deploy_known_host_ed25519.yml includes, then "Ensure known_hosts ownership";
# "mc": "Ensure mc is installed"; "packages": ``ansible.builtin.package``;
# "access": backup_minio_account.yml; "work_dir": backup_work_dir.yml;
# "credentials": the media runner's credentials directory and file; "runner": fastdeploy_runner;
# class B: "pg_restore": the mastodon playbook's pg_restore version check (after the packages);
# "target": the token include and the playbook's own Echoport target script.
Task = Literal[
    "ssh_key", "known_hosts", "mc", "packages", "pg_restore", "access", "work_dir", "credentials", "runner", "target"
]
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
    """The deploy user's SSH key pair (``deploy_ssh_keys.yml`` ``ssh_private_key``, ``ssh_public_key``).

    ``public`` is ``None`` for the class B playbooks, which install the private key only.
    """

    private: str = Field(repr=False, min_length=1)
    public: Annotated[str, Field(min_length=1)] | None = Field(default=None, repr=False)


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

    Class B (the remote runners whose playbook writes their Echoport target):
    ``ssh_key_public`` false installs the private key only, as those
    playbooks do; ``template_markers`` as for :class:`RunnerRegistration`;
    ``min_pg_restore_major``: the mastodon playbook's "Require a pg_restore
    that reads production's dumps" (task ``pg_restore``); ``target``: the
    playbook's own target script (task ``target``, with the token step when
    it has a :class:`~.target.ServiceToken`).
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
    ssh_key_public: bool = True
    template_markers: tuple[str, ...] = ()
    min_pg_restore_major: Annotated[int, Field(ge=1)] | None = None
    target: RunnerTarget | None = None

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
        declared: Mapping[str, Any] = {}
        if self.runner.template is None or self.runner.template not in runner_templates():
            problems.append("the runner must come from a vendored runner template")
        else:
            source = _template_source(self.runner.template)
            declared = _template_variables(self.runner.template)
            if "_work_dir.py.j2" not in source:
                # The playbooks' "Require a runner that works on the external disk only".
                problems.append(f"{self.runner.template} does not include _work_dir.py.j2")
            # The class B playbooks' "Require the <runner> in the ops-library checkout".
            missing = [marker for marker in self.template_markers if marker not in source]
            problems += [f"{self.runner.template} lacks {marker!r}" for marker in missing]
        if self.target is not None:
            # In the playbooks the target's bucket and the runner's are one variable.
            for key in ("default_bucket", "echoport_backup_default_bucket"):
                if key in self.target.values and self.target.values[key] != self.access.bucket:
                    problems.append(f"the target's {key} must be the access's bucket")
        if not self.ssh_key_public and not self.ssh_key:
            problems.append("ssh_key_public is about the SSH key the playbook installs (ssh_key)")
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
            elif source is not None and name not in declared:
                problems.append(f"{self.runner.template} does not read {name}")
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
        # The values the runner gets: the given ones, else the template's defaults.
        effective = {**declared, **self.variables}
        for name, value in sorted(effective.items()):
            suffix = next((s for s in _BOUND_SUFFIXES if name.endswith(s)), None)
            if suffix is None:
                continue
            if value is _NO_DEFAULT:
                problems.append(f"{self.runner.template} needs {name} (it has no default)")
            elif value != bound[suffix]:
                problems.append(f"{name} must be what the registration provisions ({suffix.lstrip('_')})")
        if any(cfg.path != self.known_hosts_path for cfg in self.known_hosts):
            problems.append(f"the known hosts go to {self.known_hosts_path}")
        wanted = {
            "ssh_key": self.ssh_key,
            "known_hosts": bool(self.known_hosts),
            "packages": bool(self.packages),
            "credentials": self.credentials is not None,
            "pg_restore": self.min_pg_restore_major is not None,
            "target": self.target is not None,
        }
        required = {"access", "work_dir", "runner"} | {task for task, present in wanted.items() if present}
        if len(set(self.tasks)) != len(self.tasks) or not required <= set(self.tasks) <= required | {"mc"}:
            problems.append(f"tasks must name each part exactly once: {', '.join(sorted(required))} (and mc)")
        if problems:
            raise ValueError("runner registration: " + "; ".join(problems))
        return self


def _ssh_key(cfg: DeployRunnerRegistration, key: DeployKey) -> None:
    """The production-db playbooks' deploy SSH directory and key pair (``copy`` of the secrets as they are).

    The class B playbooks install the private key only (``ssh_key_public`` false).
    """

    user = cfg.runner.deploy_user
    files.directory(
        name=f"Ensure the SSH directory of {user}", path=f"{cfg.home}/.ssh", user=user, group=user, mode="0700"
    )
    keys = [("id_ed25519", key.private, "0600")]
    if key.public is not None:
        keys.append(("id_ed25519.pub", key.public, "0644"))
    for name, value, mode in keys:
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


# ``regex_findall('[(]PostgreSQL[)] ([0-9]+)') | first`` of ``pg_restore --version``.
_PG_RESTORE_MAJOR = "grep -o '(PostgreSQL) [0-9][0-9]*' | head -n 1 | cut -d ' ' -f 2"


def _pg_restore(cfg: DeployRunnerRegistration) -> None:
    """The mastodon playbook's pg_restore check: refuse a pg_restore older than production's PostgreSQL.

    While planning, a pg_restore that is already installed and too old
    refuses (a dry run shows it, as the playbook's check mode does). The
    check itself is a read-only step after the packages, as the playbook
    reads the version after installing ``postgresql-client``.
    """

    major = cfg.min_pg_restore_major
    assert major is not None
    found = _PG_RESTORE_MAJOR
    message = f"pg_restore on this host cannot read a PostgreSQL {major} dump; install postgresql-client-{major}"
    planned = (probe(f"(pg_restore --version 2>/dev/null || true) | {found}", name="pg_restore version") or "").strip()
    if planned.isdigit() and int(planned) < major:
        raise DeployError(message)
    mark_read_only(
        server.shell(
            name=f"Require a pg_restore that reads PostgreSQL {major} dumps",
            commands=[
                f'v=$(pg_restore --version | {found}); [ "${{v:-0}}" -ge {major} ] '
                f"|| {{ echo {shlex.quote(message)} >&2; exit 1; }}"
            ],
        )
    )


def install_deploy_registration(
    cfg: DeployRunnerRegistration,
    *,
    secret_key: str,
    ssh_key: DeployKey | None = None,
    source: MediaSource | None = None,
    keyscan: Callable[[str], str] | None = None,
    token_user: str | None = None,
) -> None:
    """The playbook's tasks for ``cfg`` in its order (call inside a deploy).

    ``secret_key``: the target's scoped account secret; ``ssh_key``: the
    deploy key pair, exactly when the playbook installs it; ``source``: the
    media runner's source bucket and credentials, exactly for a media runner.
    ``keyscan`` replaces the controller's ``ssh-keyscan`` (tests);
    ``token_user``: the FastDeploy user that issues the target's service
    token (a target with a token needs it). Every refusal happens while
    planning, before any write, except the pg_restore version check, which
    runs after the packages as in the playbook.
    """

    if cfg.ssh_key != (ssh_key is not None):
        raise DeployError(f"{cfg.runner.service}: the deploy SSH key is needed exactly when the playbook installs it")
    if ssh_key is not None and (ssh_key.public is not None) != cfg.ssh_key_public:
        raise DeployError(
            f"{cfg.runner.service}: the public deploy key is needed exactly when the playbook installs it"
        )
    if cfg.target is not None and cfg.target.token is not None and token_user is None:
        raise DeployError(f"{cfg.runner.service} issues a FastDeploy token and needs the token user")
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
        elif task == "pg_restore":
            _pg_restore(cfg)
        elif task == "target":
            assert cfg.target is not None
            if cfg.target.token is None:
                upsert_runner_target(cfg.target)
            else:
                assert token_user is not None
                token_and_target(cfg.target, token_user)
        else:
            install_runner(cfg.runner, variables)


register_deploy_runner = deploy("Echoport backup runner registration")(install_deploy_registration)

__all__ = [
    "DEFAULT_IPV4_FALLBACK",
    "NO_CHECK_DEST",
    "CredentialFile",
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
