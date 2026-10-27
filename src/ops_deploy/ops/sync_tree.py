"""``sync_tree``: push a controller directory to the host with rsync.

Replaces ``ansible.posix.synchronize`` and pyinfra's alpha ``files.rsync``.
At plan time the operation runs an itemized ``rsync --dry-run``; no itemized
lines means no change and nothing is yielded. Otherwise it yields a
``FunctionCommand`` that runs the real rsync, so ``did_change`` is accurate.

pyinfra runs an operation body at plan time and again while executing, so the
dry-run result is cached per host and operation: the dry run happens once and
execution acts on exactly what was planned.
"""

from __future__ import annotations

import shlex
import weakref
from collections.abc import Generator, Sequence
from pathlib import Path, PurePosixPath

from pyinfra import host
from pyinfra.api import FunctionCommand, OperationValueError, operation
from pyinfra.api.host import Host
from pyinfra.api.operation import OperationMeta
from pyinfra.context import ctx_host
from pyinfra.facts.files import Directory

from ops_deploy.core.rsync import RsyncResult, RsyncRunner, run_checked, subprocess_rsync_runner

# Never transferred, and protected from ``--delete`` on the host: version
# control and local tooling state, plus markers deploys keep next to the tree.
MANDATORY_EXCLUDES = (".git", ".venv", "__pycache__", ".ops-deploy-*", ".pyinfra-*")

DRY_RUN_FLAGS = ("--dry-run", "--itemize-changes", "--out-format=%i %n%L")

_dry_runs: weakref.WeakKeyDictionary[Host, dict[tuple[str | None, tuple[str, ...]], RsyncResult]]
_dry_runs = weakref.WeakKeyDictionary()


def rsync_argv(
    src: Path,
    dest: PurePosixPath,
    remote: str,
    *,
    ssh_command: Sequence[str] = ("ssh",),
    user: str | None = None,
    group: str | None = None,
    excludes: Sequence[str] = (),
    delete: bool = True,
    chmod: str | None = None,
    rsync_path: str | None = None,
    dry_run: bool,
) -> list[str]:
    """Build the rsync command line; ``remote`` is ``user@host``.

    Ownership from the controller is never preserved. With ``user`` the files
    are created as ``user:group`` (``group`` defaults to ``user``), which needs
    root on the host; without it they belong to the SSH user.
    """

    # Directory times are left alone: the app writing into a synced directory
    # (``__pycache__``, a database) would otherwise show up as a change on every
    # next run and retrigger everything gated on the sync.
    # Content decides, not times: a fresh clone of unchanged code (new mtimes)
    # must be a no-op, so files are compared by checksum and times are not
    # synced at all (``-t`` would itemize every time-only difference).
    argv = ["rsync", "-rl", "--checksum", "--omit-dir-times"]
    if delete:
        argv.append("--delete")
    argv += ["--no-owner", "--no-group"]
    if user is not None:
        argv.append(f"--chown={user}:{group or user}")
    if chmod is not None:
        # ``--perms`` makes the modes apply to existing files too, and shows
        # a mode difference as an itemized change.
        argv += ["--perms", f"--chmod={chmod}"]
    if dry_run:
        argv += DRY_RUN_FLAGS
    if rsync_path is not None:
        remote_binary = PurePosixPath(rsync_path)
        if (
            not remote_binary.is_absolute()
            or remote_binary == PurePosixPath("/")
            or ".." in remote_binary.parts
            or str(remote_binary) != rsync_path
            or any(c in rsync_path for c in "\x00\r\n")
        ):
            raise OperationValueError("rsync_path must be a normalized absolute executable path")
        argv.append("--rsync-path=" + shlex.quote(rsync_path))
    argv += [f"--exclude={pattern}" for pattern in (*MANDATORY_EXCLUDES, *excludes)]
    argv += ["-e", shlex.join(ssh_command), f"{src}/", f"{remote}:{dest}/"]
    return argv


def _ssh_target() -> tuple[str, list[str]]:
    hostname = host.data.get("ssh_hostname") or host.name
    ssh_user = host.data.get("ssh_user") or "root"
    ssh_command = ["ssh"]
    port = host.data.get("ssh_port")
    if port:
        ssh_command += ["-p", str(int(port))]
    # The same host data keys pyinfra's ssh connector reads, so rsync reaches
    # the host the way the connector does.
    key = host.data.get("ssh_key")
    if key:
        ssh_command += ["-i", str(key), "-o", "IdentitiesOnly=yes"]
    known_hosts = host.data.get("ssh_known_hosts_file")
    if known_hosts:
        ssh_command += ["-o", f"UserKnownHostsFile={known_hosts}"]
    strict = host.data.get("ssh_strict_host_key_checking")
    if strict:
        ssh_command += ["-o", f"StrictHostKeyChecking={strict}"]
    return f"{ssh_user}@{hostname}", ssh_command


def _dry_run(runner: RsyncRunner, argv: Sequence[str]) -> RsyncResult:
    per_host = _dry_runs.setdefault(ctx_host.get(), {})
    key = (host.current_op_hash, tuple(argv))
    if key not in per_host:
        per_host[key] = run_checked(runner, argv)
    return per_host[key]


def _run_rsync(runner: RsyncRunner, argv: Sequence[str]) -> None:
    run_checked(runner, argv)


def _run_prepared_rsync(runner: RsyncRunner, argv: Sequence[str], prepared_by: OperationMeta) -> None:
    if not prepared_by.is_complete() or not prepared_by.did_succeed():
        raise OperationValueError("sync_tree destination preparation did not succeed")
    run_checked(runner, argv)


@operation()
def sync_tree(
    src: Path | str,
    dest: PurePosixPath | str,
    user: str | None = None,
    group: str | None = None,
    excludes: Sequence[str] = (),
    delete: bool = True,
    chmod: str | None = None,
    rsync_path: str | None = None,
    prepared_by: OperationMeta | None = None,
    runner: RsyncRunner = subprocess_rsync_runner,
) -> Generator[FunctionCommand, None, None]:
    """Make ``dest`` on the host mirror the controller directory ``src``.

    + src: local directory; its contents (not the directory itself) are synced
    + dest: absolute remote directory
    + user/group: owner of the transferred files (``--chown``); needs root
    + excludes: extra rsync exclude patterns, added to ``MANDATORY_EXCLUDES``
    + delete: remove remote files missing from ``src`` (excluded paths are kept)
    + chmod: rsync ``--chmod`` modes (for example ``D0755,F0644``), enforced on existing files too
    + rsync_path: explicit already-installed remote rsync executable; defaults to the original remote command
    + prepared_by: preceding preparation operation creating a fresh destination; existing destinations still dry-run
    + runner: controller-side rsync runner; tests inject a recorder
    """

    src_path = Path(src)
    dest_path = PurePosixPath(dest)
    if not src_path.is_dir():
        raise OperationValueError(f"sync_tree source is not a directory: {src_path}")
    if not dest_path.is_absolute():
        raise OperationValueError(f"sync_tree destination must be absolute: {dest_path}")
    if group is not None and user is None:
        raise OperationValueError("sync_tree group requires user")
    if prepared_by is not None and (
        dest_path == PurePosixPath("/")
        or ".." in dest_path.parts
        or str(dest_path) != str(dest)
        or any(c in str(dest) for c in "\x00\r\n")
    ):
        raise OperationValueError("prepared sync_tree destination must be a normalized absolute non-root path")

    remote, ssh_command = _ssh_target()

    def argv(*, dry_run: bool) -> list[str]:
        return rsync_argv(
            src_path,
            dest_path,
            remote,
            ssh_command=ssh_command,
            user=user,
            group=group,
            excludes=excludes,
            delete=delete,
            chmod=chmod,
            rsync_path=rsync_path,
            dry_run=dry_run,
        )

    if prepared_by is not None and not host.get_fact(Directory, path=str(dest_path)):
        # A real preceding operation must be queued on this same host. Merely
        # passing a flag cannot suppress the checksum dry-run of an existing tree.
        current_host = ctx_host.get()
        order = current_host.op_hash_order
        if (
            prepared_by._hash not in order
            or (host.current_op_hash in order and order.index(prepared_by._hash) >= order.index(host.current_op_hash))
            or not prepared_by.will_change
        ):
            raise OperationValueError("fresh sync_tree destination requires a preceding planned preparation operation")
        actual = argv(dry_run=False)
        remote = shlex.quote(rsync_path) if rsync_path else "rsync"
        target = shlex.quote(str(dest_path))
        guarded = f"test -d {target} && test ! -L {target} && {remote}"
        actual = [arg for arg in actual if not arg.startswith("--rsync-path=")]
        actual.insert(actual.index("-e"), "--rsync-path=" + guarded)
        yield FunctionCommand(_run_prepared_rsync, (runner, actual, prepared_by), {})
        return
    plan = _dry_run(runner, argv(dry_run=True))
    if not plan.itemized_lines:
        host.noop(f"{dest_path} is up to date")
        return
    yield FunctionCommand(_run_rsync, (runner, argv(dry_run=False)), {})
