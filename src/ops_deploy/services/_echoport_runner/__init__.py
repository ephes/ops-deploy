"""Echoport backup runners registered with FastDeploy: the generic parts.

Port of ops-library's ``fastdeploy_runner`` role and of the pieces the
ops-control register playbooks share (design note
``ECHOPORT-FASTDEPLOY-REGISTRATIONS-20261105`` on ops-meta's ``pyinfra-port``
branch, §3). A runner port is a :class:`RunnerConfig` (the role variables the
playbook passes) plus the parts its playbook uses:

- :func:`deploy_runner`: the role's nine steps (this module);
- :mod:`.render`: the role's runner templates, rendered as Ansible renders them;
- :mod:`.access`: ``common/backup_minio_account.yml`` (the scoped MinIO account
  and the runner user's ``mc`` alias), :func:`.access.work_dir`
  (``common/backup_work_dir.yml``) and :func:`.access.known_host`
  (``common/deploy_known_host_ed25519.yml``);
- :mod:`.target`: a playbook's own Echoport target script with a check mode,
  and the FastDeploy service token piped into it.
- :mod:`.nyxmon`: a playbook's own Nyxmon check script with a check mode
  (graphyard's backup freshness check);
- :mod:`.registration`: a same-host root runner's whole register playbook
  (packages, access, runner, and for class B the playbook's credential file,
  target script and Nyxmon script), the entry point of ops-control's runner
  entries.

:func:`deploy_runner` does what the role does, in its order:

1. validates the settings (:class:`RunnerConfig` copies the role's assert);
2. makes the parent of the libexec root ``root:root 0755`` and refuses, while
   planning, when a directory above it is not a root-owned directory that only
   root can write;
3. makes the libexec root and the script directory ``root:root 0755``;
4. installs the script ``root:<deploy group>`` with the configured mode;
5. makes the services root and the service directory ``root:root 0755``;
6. writes ``config.json`` (``root:root 0644``) byte for byte as the role's
   ``to_nice_json`` plus a newline;
7. writes the sudoers rule, validated with ``visudo`` before it goes live;
8. runs FastDeploy's ``commands.py syncservices`` as the fastdeploy user;
9. removes the legacy copies.

Unlike the role, step 8 runs only when ``config.json`` changed or FastDeploy's
stored service differs from it (read while planning from FastDeploy's
database), so a converged host gets no mutating operation. FastDeploy's sync
compares exactly that: the stored ``data`` against the parsed ``config.json``.
"""

from __future__ import annotations

import json
import posixpath
import re
import shlex
from collections.abc import Mapping
from io import StringIO
from pathlib import PurePosixPath
from typing import Any, Literal

from pydantic import Field, model_validator
from pyinfra.api import DeployError, deploy
from pyinfra.api.operation import OperationMeta
from pyinfra.operations import files, server

from ops_deploy.base._common import RoleConfig
from ops_deploy.helpers.probes import probe, verify_probe
from ops_deploy.helpers.python import _as_user
from ops_deploy.helpers.users import sudoers_file
from ops_deploy.services._echoport_runner.render import render_runner

_USER = r"^[a-z_][a-z0-9_-]*$"
_PATH = re.compile(r"^/[A-Za-z0-9._/-]+$")
_DOT_SEGMENT = re.compile(r"/\.\.?(/|$)")
SUDOERS_DIR = "/etc/sudoers.d/"


def _plain_path(value: str) -> bool:
    return bool(_PATH.match(value)) and not _DOT_SEGMENT.search(value)


class RunnerConfig(RoleConfig):
    """The ``fastdeploy_runner_*`` variables a register playbook passes (``defaults/main.yml``).

    ``None`` means the role's default, derived from the other values as the
    role derives it. The validator is the role's first task.
    """

    service: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]*$")
    description: str | None = None
    steps: tuple[str, ...]
    # Exactly one: a vendored runner template (:func:`.render.render_runner`) or the literal script.
    template: str | None = None
    content: str | None = None
    script_name: str = Field(default="backup.py", pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

    libexec_root: str = "/usr/local/libexec/fastdeploy"
    dir: str | None = None
    script_group: str | None = None
    script_mode: Literal["0750", "0755"] = "0750"

    fastdeploy_root: str = "/home/fastdeploy/site"
    services_root: str | None = None
    config_dir: str | None = None
    fastdeploy_user: str = Field(default="fastdeploy", pattern=_USER)
    deploy_user: str = Field(default="deploy", pattern=_USER)

    run_as: str = Field(default="", pattern=r"^$|^[a-z_][a-z0-9_-]*$")
    sudoers_file: str | None = None
    legacy_files: tuple[str, ...] | None = None

    sync: bool = True
    sync_python: str | None = None
    # Not role variables: where step 8 reads FastDeploy's stored service, and
    # the home the fastdeploy user runs ``commands.py`` with.
    fastdeploy_database: str = Field(default="fastdeploy", pattern=r"^[a-z_][a-z0-9_]*$")
    fastdeploy_home: str = "/home/fastdeploy"

    @property
    def runner_description(self) -> str:
        return self.service if self.description is None else self.description

    @property
    def runner_dir(self) -> str:
        return f"{self.libexec_root}/{self.service}" if self.dir is None else self.dir

    @property
    def script(self) -> str:
        return f"{self.runner_dir}/{self.script_name}"

    @property
    def group(self) -> str:
        return self.deploy_user if self.script_group is None else self.script_group

    @property
    def services(self) -> str:
        return f"{self.fastdeploy_root}/services" if self.services_root is None else self.services_root

    @property
    def service_dir(self) -> str:
        return f"{self.services}/{self.service}" if self.config_dir is None else self.config_dir

    @property
    def sudoers(self) -> str:
        default = f"{SUDOERS_DIR}{self.service.replace('-', '_')}"
        return default if self.sudoers_file is None else self.sudoers_file

    @property
    def legacy(self) -> tuple[str, ...]:
        return (f"{self.service_dir}/backup.py",) if self.legacy_files is None else self.legacy_files

    @property
    def python(self) -> str:
        return f"{self.fastdeploy_root}/.venv/bin/python" if self.sync_python is None else self.sync_python

    @model_validator(mode="after")
    def _role_assert(self) -> RunnerConfig:
        # The role's "Validate the runner settings", condition by condition.
        problems = []
        if not self.steps:
            problems.append("steps must not be empty")
        if (self.template is None) == (self.content is None) or not (self.template or self.content):
            problems.append("exactly one of template and content is required")
        if not _plain_path(self.libexec_root):
            problems.append("libexec_root must be a plain absolute path")
        if not _plain_path(self.runner_dir) or posixpath.dirname(self.runner_dir) != self.libexec_root:
            problems.append("the script directory must be a plain path directly below libexec_root")
        if (self.runner_dir + "/").startswith(self.fastdeploy_root + "/"):
            problems.append("the script directory must be outside the FastDeploy site")
        if not re.match(_USER, self.group):
            problems.append("script_group must be a plain group name")
        if not re.fullmatch(r"/etc/sudoers\.d/[A-Za-z0-9_-]+", self.sudoers):
            problems.append("the sudoers file must lie directly in /etc/sudoers.d (no dots)")
        if problems:
            raise ValueError("fastdeploy_runner settings: " + "; ".join(problems))
        return self


def service_config(cfg: RunnerConfig) -> str:
    """``config.json`` as the role writes it: ``to_nice_json`` of the service, then a newline."""

    data = {
        "name": cfg.service,
        "description": cfg.runner_description,
        "deploy_script": cfg.script,
        "steps": [{"name": step} for step in cfg.steps],
    }
    return json.dumps(data, indent=4, sort_keys=True, separators=(",", ": ")) + "\n"


def sudoers_rule(cfg: RunnerConfig) -> str:
    """The role's sudoers drop-in: fastdeploy may run the script as deploy (and deploy as ``run_as``)."""

    lines = [
        f"# FastDeploy runner {cfg.service} (ops-library fastdeploy_runner).",
        "# The script and every directory above it are root-owned; NOSETENV because",
        "# FastDeploy passes the context in the --config file, not the environment.",
        f"{cfg.fastdeploy_user} ALL=({cfg.deploy_user}) NOPASSWD:NOSETENV: {cfg.script} *",
    ]
    if cfg.run_as:
        lines.append(f"{cfg.deploy_user} ALL=({cfg.run_as}) NOPASSWD:NOSETENV: {cfg.script} *")
    return "\n".join(lines) + "\n"


def libexec_ancestors(libexec_root: str) -> list[str]:
    """The role's ``fastdeploy_runner_libexec_ancestors``: ``/`` and every directory above the libexec root."""

    parts = libexec_root.strip("/").split("/")
    return ["/"] + ["/" + "/".join(parts[:i]) for i in range(1, len(parts))]


def _ancestor_probe(paths: list[str]) -> str:
    # One line per path: uid, gid, octal mode and type, or "missing"; never follows a link.
    # The C locale: GNU stat translates %F ("Verzeichnis" under a German locale).
    checks = [
        f"if [ -e {p} ] || [ -L {p} ]; then LC_ALL=C LANG=C stat -c '%u %g %a %F' {p}; else echo missing; fi"
        for p in map(shlex.quote, paths)
    ]
    return "; ".join(checks)


def _require_root_owned_ancestors(cfg: RunnerConfig) -> None:
    """The role's ancestor check, while planning: refuse before any write.

    The parent of the libexec root is one of the role's ancestors, but the role
    creates (or resets) it ``root:root 0755`` just before checking, so only the
    directories above it are read here; step 2 then fixes the parent itself.
    """

    paths = libexec_ancestors(cfg.libexec_root)[:-1]
    if not paths:
        return
    found = probe(_ancestor_probe(paths), name="directories above the libexec root")
    lines = (found or "").splitlines()
    if found is None or len(lines) != len(paths):
        raise DeployError(f"could not read the directories above {cfg.libexec_root}")
    for path, line in zip(paths, lines, strict=True):
        fields = line.split(" ", 3)
        ok = len(fields) == 4 and fields[3] == "directory" and fields[0] == "0"
        if ok:
            mode = int(fields[2], 8)
            ok = (not mode & 0o020 or fields[1] == "0") and not mode & 0o002
        if not ok:
            raise DeployError(f"{path} must be a root-owned directory that only root can write.")


def _directory(path: str) -> OperationMeta:
    return files.directory(name=f"Ensure directory {path}", path=path, user="root", group="root", mode="0755")


def _stored_service(cfg: RunnerConfig) -> str:
    """Strict probe: FastDeploy's stored ``data`` of the service (empty when it has none)."""

    query = f"select data::text from service where name = '{cfg.service}'"
    psql = ["runuser", "-u", "postgres", "--", "psql", "-XAtq", "-v", "ON_ERROR_STOP=1", "-d", cfg.fastdeploy_database]
    return shlex.join([*psql, "-c", query])


def _stored_matches(stored: str | None, wanted: str) -> bool:
    if not stored or not stored.strip():
        return False
    try:
        return bool(json.loads(stored) == json.loads(wanted))
    except json.JSONDecodeError:
        return False


def runner_script(cfg: RunnerConfig, variables: Mapping[str, Any] | None = None) -> str:
    """The script the role installs: the rendered template, or the literal content."""

    if cfg.template is not None:
        return render_runner(cfg.template, variables or {})
    assert cfg.content is not None
    return cfg.content


def install_runner(cfg: RunnerConfig, variables: Mapping[str, Any] | None = None) -> None:
    """The role's steps 2 to 9 for ``cfg`` (call inside a deploy); ``variables`` render the template."""

    script = runner_script(cfg, variables)
    _require_root_owned_ancestors(cfg)
    _directory(posixpath.dirname(cfg.libexec_root))
    for path in (cfg.libexec_root, cfg.runner_dir):
        _directory(path)
    files.put(
        name=f"Install the {cfg.service} runner script",
        src=StringIO(script),
        dest=cfg.script,
        user="root",
        group=cfg.group,
        mode=cfg.script_mode,
        create_remote_dir=False,
    )
    for path in (cfg.services, cfg.service_dir):
        _directory(path)
    wanted = service_config(cfg)
    config = files.put(
        name=f"Write config.json of {cfg.service}",
        src=StringIO(wanted),
        dest=f"{cfg.service_dir}/config.json",
        user="root",
        group="root",
        mode="0644",
        create_remote_dir=False,
    )
    sudoers_file(cfg.sudoers.removeprefix(SUDOERS_DIR), sudoers_rule(cfg))
    if cfg.sync:
        stored = probe(_stored_service(cfg), name=f"FastDeploy service {cfg.service}")
        current = _stored_matches(stored, wanted)
        sync = _as_user(
            cfg.fastdeploy_user, PurePosixPath(cfg.fastdeploy_home), {}, [cfg.python, "commands.py", "syncservices"]
        )
        server.shell(
            name=f"Sync FastDeploy services for {cfg.service}",
            commands=[f"cd {shlex.quote(cfg.fastdeploy_root)} && {sync}"],
            _if=lambda: config.did_change() or not current,
        )
        if stored is None:
            verify_probe(_stored_service(cfg), name=f"FastDeploy service {cfg.service}")
    for path in cfg.legacy:
        if path != cfg.script:
            files.file(name=f"Remove the old FastDeploy-writable copy {path}", path=path, present=False)


deploy_runner = deploy("Echoport backup runner")(install_runner)

__all__ = [
    "RunnerConfig",
    "deploy_runner",
    "install_runner",
    "libexec_ancestors",
    "runner_script",
    "service_config",
    "sudoers_rule",
]
