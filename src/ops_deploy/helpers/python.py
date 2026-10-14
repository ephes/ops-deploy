"""uv-managed Python apps and Django management commands.

Both helpers run their command as the service user via ``runuser`` inside the
command string. The ``_sudo``/``_sudo_user`` global arguments are banned (see
``tests/test_policy.py``), so the deploy connects as root and drops privileges
per command. ``HOME`` is set explicitly so uv's cache and Python's user paths
belong to the service user, not root.
"""

from __future__ import annotations

import shlex
from collections.abc import Callable, Sequence
from pathlib import PurePosixPath

from pyinfra import host
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.server import Command
from pyinfra.operations import server

DEFAULT_UV = PurePosixPath("/usr/local/bin/uv")
# What the Ansible roles run: locked, runtime dependencies only.
DEFAULT_UV_SYNC_ARGS = ("--frozen", "--no-dev", "--no-default-groups")


def _as_user(user: str, home: PurePosixPath, env: dict[str, str], argv: Sequence[str]) -> str:
    assignments = [f"{key}={value}" for key, value in {"HOME": str(home), **env}.items()]
    return shlex.join(["runuser", "-u", user, "--", "env", *assignments, *argv])


def _gate(when_changed: Sequence[OperationMeta] | None, force: bool = False) -> Callable[[], bool]:
    def run() -> bool:
        if force or when_changed is None:
            return True
        return any(meta.did_change() for meta in when_changed)

    return run


def uv_sync(
    project_dir: PurePosixPath,
    *,
    user: str,
    home: PurePosixPath,
    venv: PurePosixPath | None = None,
    python: str | None = None,
    args: Sequence[str] = DEFAULT_UV_SYNC_ARGS,
    uv: PurePosixPath = DEFAULT_UV,
    when_changed: Sequence[OperationMeta] | None = None,
) -> OperationMeta:
    """Run ``uv sync`` in ``project_dir`` as ``user``.

    ``venv`` sets ``UV_PROJECT_ENVIRONMENT`` (default: ``<project_dir>/.venv``).
    With ``when_changed`` the sync runs only if one of those operations
    changed, or if ``<venv>/bin/python`` is not executable (first deploy, a
    venv removed by hand, or a dangling interpreter symlink). Without it, the
    sync runs on every deploy.
    """

    environment = venv or project_dir / ".venv"
    # ``test -x`` follows symlinks, so a venv whose interpreter is gone counts as missing.
    interpreter = shlex.quote(str(environment / "bin" / "python"))
    venv_missing = host.get_fact(Command, command=f"test -x {interpreter} && echo present || true") != "present"
    argv = [str(uv), "sync", *args]
    if python is not None:
        argv += ["--python", python]
    env = {"UV_PROJECT_ENVIRONMENT": str(environment)}
    command = f"cd {shlex.quote(str(project_dir))} && {_as_user(user, home, env, argv)}"
    return server.shell(
        name=f"uv sync {project_dir}",
        commands=[command],
        _if=_gate(when_changed, force=venv_missing),
    )


def django_manage(
    project_dir: PurePosixPath,
    *command: str,
    user: str,
    home: PurePosixPath,
    venv: PurePosixPath,
    env_file: PurePosixPath | None = None,
    when_changed: Sequence[OperationMeta] | None = None,
    name: str | None = None,
) -> OperationMeta:
    """Run ``./manage.py <command>`` in ``project_dir`` as ``user``.

    ``env_file`` (a shell-sourceable ``KEY=value`` file, like the roles'
    ``.env.shell``) is sourced on the target with ``set -a``, so secret values
    never appear on the command line. ``venv``'s ``bin`` is put first on
    ``PATH``. ``when_changed`` gates the run as in :func:`uv_sync`.
    """

    if not command:
        raise ValueError("django_manage needs a management command")
    lines = []
    if env_file is not None:
        lines += ["set -a", f". {shlex.quote(str(env_file))}", "set +a"]
    lines += [
        f'export PATH={shlex.quote(str(venv / "bin"))}:"$PATH"',
        f"export VIRTUAL_ENV={shlex.quote(str(venv))}",
        f"exec {shlex.join(['./manage.py', *command])}",
    ]
    script = "; ".join(lines)
    shell = f"cd {shlex.quote(str(project_dir))} && {_as_user(user, home, {}, ['sh', '-c', script])}"
    return server.shell(
        name=name or f"manage.py {' '.join(command)}",
        commands=[shell],
        _if=_gate(when_changed),
    )
