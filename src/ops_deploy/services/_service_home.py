"""Deploying into a service's home without root writing there by path.

A deploy connects as root. Whatever root writes, deletes or re-owns by path
below a directory the service user can write, a compromised service can point
somewhere else (``docs/plans/root-writes-in-service-homes.md``). The building
blocks here do that work as the service user instead:

- :func:`as_user`: a command as the user, entering its directory as the user;
- :func:`trusted_home_check` and :func:`user_directories`: root creates only
  the home, under a path nobody else can change; the user makes the rest;
- :func:`sync_tree_as_user`: ``sync_tree`` with the remote rsync running as
  the user;
- :func:`uv_sync_as_user`: ``uv_sync`` entering the project as the user.

They live with the services, not in the shared layer (``helpers``/``ops``),
until every service uses them: the shared layer's size cap is an owner
decision (``docs/development.md``). chesslab is the first user.

Linux only (``runuser``), and only over a root connection.
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Generator, Sequence
from pathlib import Path, PurePosixPath

from pyinfra import host, logger
from pyinfra.api import FunctionCommand, OperationError, OperationValueError, StringCommand, operation
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.files import Directory
from pyinfra.facts.server import Command, Users
from pyinfra.operations import server

from ops_deploy.core.rsync import RsyncRunner, run_checked, subprocess_rsync_runner
from ops_deploy.helpers.checks import mark_read_only
from ops_deploy.helpers.python import DEFAULT_UV, _gate
from ops_deploy.ops.sync_tree import _dry_run, _run_rsync, _ssh_target, rsync_argv

PLAN = "docs/plans/root-writes-in-service-homes.md"
_NAME = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
_MODE = re.compile(r"^0?[0-7]{3}$")
# A path that needs no quoting in any shell a command passes through.
_PLAIN_PATH = re.compile(r"^(/[A-Za-z0-9_.@+-]+)+$")
# ``cd <dir> && runuser ...`` would resolve ``<dir>`` as root and hand it to the
# unprivileged program as its working directory, also where the user could not
# have reached it. The user changes directory itself.
_ENTER = 'cd "$1" && shift && exec "$@"'
# As the user: the destination is a real directory now, then the rsync the controller asked for.
_RSYNC_GUARD = 'test -d "$1" && test ! -L "$1" && shift && exec rsync "$@"'


def require_plain(user: str, *paths: PurePosixPath) -> None:
    """Refuse a name or path that any shell on the way to the host would read as more than a word."""

    if not _NAME.fullmatch(user):
        raise OperationValueError(f"not a plain user or group name: {user!r}")
    for path in paths:
        if not _PLAIN_PATH.fullmatch(str(path)) or ".." in path.parts or str(PurePosixPath(str(path))) != str(path):
            raise OperationValueError(f"not a plain normalized absolute path: {path}")


def as_user(
    user: str, home: PurePosixPath, env: dict[str, str], argv: Sequence[str], *, cwd: PurePosixPath | None = None
) -> str:
    """``argv`` as ``user`` with ``HOME`` and ``env``; with ``cwd`` the user enters that directory itself.

    ``runuser`` without ``-g``: the process gets the account's primary group
    and its supplementary groups, as the unit's ``User=`` does. ``cd /`` leaves
    root's working directory behind.
    """

    assignments = [f"{key}={value}" for key, value in {"HOME": str(home), **env}.items()]
    enter = [] if cwd is None else ["sh", "-c", _ENTER, "sh", str(cwd)]
    return "cd / && " + shlex.join(["runuser", "-u", user, "--", "env", *assignments, *enter, *argv])


def trusted_home_check(user: str, home: PurePosixPath) -> OperationMeta:
    """Read-only: only root can replace a directory on the way to ``home``.

    Every ancestor from ``/`` down must be a real directory (no symlink) owned
    by root and not writable by group or others; an existing ``home`` must be a
    real directory owned by ``user``. Root creates the home by path, which is
    only safe under such a chain.
    """

    require_plain(user, home)
    ancestors = " ".join(str(path) for path in reversed(home.parents))
    script = (
        f"for p in {ancestors}; do "
        '[ -n "$(find "$p" -maxdepth 0 -type d -user root ! -perm /022)" ] || '
        '{ echo "$p is not a real directory owned by root and closed to group and others" >&2; exit 1; }; done; '
        f"if [ -e {home} ] || [ -L {home} ]; then "
        f'[ -n "$(find {home} -maxdepth 0 -type d -user {user})" ] || '
        f"{{ echo '{home} is not a real directory owned by {user}' >&2; exit 1; }}; fi"
    )
    return mark_read_only(server.shell(name=f"Check the path to {home}", commands=[f"sh -c {shlex.quote(script)}"]))


def _directory_state(path: str, user: str, group: str, mode: str) -> str:
    """``missing``, ``mode`` (the user's own, with another mode) or ``ok``; anything else is refused."""

    info = host.get_fact(Directory, path=path)
    if info is None:
        return "missing"
    if info is False:
        raise OperationError(f"{path} exists and is not a directory (a symlink?). Root does not repair it ({PLAN}).")
    if (info["user"], info["group"]) != (user, group):
        owner = f"{info['user']}:{info['group']}"
        raise OperationError(f"{path} belongs to {owner}, not {user}:{group}. Root does not repair it ({PLAN}).")
    return "ok" if info["mode"] == int(mode.lstrip("0") or "0") else "mode"


@operation()
def _user_directory(path: str, user: str, group: str, mode: str) -> Generator[StringCommand, None, None]:
    state = _directory_state(path, user, group, mode)
    if state == "ok":
        host.noop(f"directory {path} is up to date")
    elif state == "missing":
        yield StringCommand(f"cd / && runuser -u {user} -- mkdir -p -m {mode} {path}")
    else:
        yield StringCommand(f"cd / && runuser -u {user} -- chmod {mode} {path}")


def _check_layout(user: str, group: str, home: PurePosixPath, directories: Sequence[PurePosixPath], mode: str) -> None:
    require_plain(user, home, *directories)
    if not _NAME.fullmatch(group) or not _MODE.fullmatch(mode):
        raise OperationValueError("user_directories needs a plain group name and an octal mode")
    if any(home not in path.parents for path in directories):
        raise OperationValueError(f"user_directories: every directory must lie below the home {home}")
    existing = host.get_fact(Users).get(user)
    if existing is not None and existing.get("group") != group:
        raise OperationError(
            f"{user}'s primary group is {existing.get('group')!r}, not {group!r}: what the user creates "
            f"would get the wrong group. Fix the account before converting the service ({PLAN})."
        )


def user_directories(
    user: str, group: str, home: PurePosixPath, directories: Sequence[PurePosixPath], *, mode: str = "0755"
) -> tuple[OperationMeta, ...]:
    """``directories`` below ``home``, each made (or its mode corrected) by ``user`` itself.

    A directory that is a symlink, not a directory, or owned by another user
    or group fails the deploy while it plans: root does not repair it by path.
    ``group`` must be the account's primary group, because that is the group
    of what the user creates. Call it after ``system_user`` created the home.
    """

    _check_layout(user, group, home, directories, mode)
    return tuple(
        _user_directory(name=f"Ensure directory {path} as {user}", path=str(path), user=user, group=group, mode=mode)
        for path in directories
    )


def user_directories_pending(
    user: str, group: str, home: PurePosixPath, directories: Sequence[PurePosixPath], *, mode: str = "0755"
) -> list[str]:
    """What :func:`user_directories` would do, read-only: one line per directory it would make or re-mode.

    The same predicates and the same refusals (a symlink, a foreign owner, a
    group that is not the account's primary one), without queuing anything.
    """

    _check_layout(user, group, home, directories, mode)
    # The directories first: a symlink or a foreign owner is refused also when the account is missing.
    states = {str(path): _directory_state(str(path), user, group, mode) for path in directories}
    pending = [] if host.get_fact(Users).get(user) is not None else [f"the account {user} does not exist"]
    return pending + [
        f"{path} is {'missing' if state == 'missing' else 'not ' + mode}"
        for path, state in states.items()
        if state != "ok"
    ]


def remote_rsync_command(user: str, dest: PurePosixPath) -> str:
    """The remote rsync command (``--rsync-path``) that receives as ``user``; rsync appends ``--server ...``.

    Whatever path the receiver ends up in, it can only change what that user
    may change: the UID is the boundary. The guard in front is a correctness
    check (rsync would create a missing last component; a destination that is
    a symlink is refused when the guard looks).
    """

    require_plain(user, dest)
    return f"cd / && runuser -u {user} -- sh -c {shlex.quote(_RSYNC_GUARD)} rsync {dest}"


def _sync_argv(
    src: Path, dest: PurePosixPath, user: str, excludes: Sequence[str], *, dry_run: bool
) -> tuple[list[str], str]:
    if not src.is_dir():
        raise OperationValueError(f"sync_tree_as_user source is not a directory: {src}")
    remote, ssh_command = _ssh_target()
    if not remote.startswith("root@"):
        raise OperationValueError("sync_tree_as_user needs a root connection (runuser)")
    command = remote_rsync_command(user, dest)
    built = rsync_argv(src, dest, remote, ssh_command=ssh_command, excludes=excludes, dry_run=dry_run)
    built.insert(built.index("-e"), f"--rsync-path={command}")
    return built, command


def sync_dry_run_as_user(
    src: Path | str,
    dest: PurePosixPath | str,
    user: str,
    excludes: Sequence[str] = (),
    runner: RsyncRunner = subprocess_rsync_runner,
) -> list[str] | None:
    """The itemized changes :func:`sync_tree_as_user` would transfer, asked now and never transferred.

    Not an operation: it runs the dry run while planning and queues nothing,
    so no later re-evaluation can turn it into a transfer. ``None`` when the
    account or the destination does not exist (nothing to compare with).
    """

    dest_path = PurePosixPath(dest)
    argv, command = _sync_argv(Path(src), dest_path, user, excludes, dry_run=True)
    destination = host.get_fact(Directory, path=str(dest_path))
    if destination is False:
        raise OperationError(f"{dest_path} exists and is not a directory (a symlink?). See {PLAN}.")
    if destination is None or user not in host.get_fact(Users):
        return None
    logger.info(f"{host.print_prefix}sync_tree remote command: {command}")
    return run_checked(runner, argv).itemized_lines


@operation()
def sync_tree_as_user(
    src: Path | str,
    dest: PurePosixPath | str,
    user: str,
    excludes: Sequence[str] = (),
    runner: RsyncRunner = subprocess_rsync_runner,
) -> Generator[FunctionCommand, None, None]:
    """``sync_tree`` whose remote rsync runs as ``user``: no ``--chown``, the files are the user's own.

    + src, dest, excludes, runner: as for ``sync_tree`` (``--delete``, checksum comparison, one dry run)
    + user: the service user the remote rsync runs as (``runuser``)

    While the account or ``dest`` does not exist yet (a first deploy: an
    earlier operation creates them), nobody can dry-run as the user. The
    operation then counts as a change and transfers at its place in the
    order; the guard fails it if the directory is still missing then.
    """

    src_path, dest_path = Path(src), PurePosixPath(dest)

    def argv(*, dry_run: bool) -> list[str]:
        return _sync_argv(src_path, dest_path, user, excludes, dry_run=dry_run)[0]

    # Shown on every run: the runner captures rsync's output and logs nothing on success.
    command = _sync_argv(src_path, dest_path, user, excludes, dry_run=True)[1]
    logger.info(f"{host.print_prefix}sync_tree remote command: {command}")

    destination = host.get_fact(Directory, path=str(dest_path))
    if destination is False:
        raise OperationError(f"{dest_path} exists and is not a directory (a symlink?). See {PLAN}.")
    if destination is None or user not in host.get_fact(Users):
        yield FunctionCommand(_run_rsync, (runner, argv(dry_run=False)), {})
        return
    if not _dry_run(runner, argv(dry_run=True)).itemized_lines:
        host.noop(f"{dest_path} is up to date")
        return
    yield FunctionCommand(_run_rsync, (runner, argv(dry_run=False)), {})


def uv_sync_as_user(
    project_dir: PurePosixPath,
    *,
    user: str,
    home: PurePosixPath,
    venv: PurePosixPath,
    python: str,
    args: Sequence[str],
    when_changed: Sequence[OperationMeta],
) -> OperationMeta:
    """``uv_sync`` with the user entering ``project_dir`` (same gate: a change, or no interpreter in the venv)."""

    interpreter = shlex.quote(str(venv / "bin" / "python"))
    missing = host.get_fact(Command, command=f"test -x {interpreter} && echo present || true") != "present"
    argv = [str(DEFAULT_UV), "sync", *args, "--python", python]
    command = as_user(user, home, {"UV_PROJECT_ENVIRONMENT": str(venv)}, argv, cwd=project_dir)
    return server.shell(name=f"uv sync {project_dir}", commands=[command], _if=_gate(when_changed, force=missing))
