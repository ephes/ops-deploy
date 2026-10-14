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
from pyinfra.context import ctx_host

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
    if dry_run:
        argv += DRY_RUN_FLAGS
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


@operation()
def sync_tree(
    src: Path | str,
    dest: PurePosixPath | str,
    user: str | None = None,
    group: str | None = None,
    excludes: Sequence[str] = (),
    delete: bool = True,
    runner: RsyncRunner = subprocess_rsync_runner,
) -> Generator[FunctionCommand, None, None]:
    """Make ``dest`` on the host mirror the controller directory ``src``.

    + src: local directory; its contents (not the directory itself) are synced
    + dest: absolute remote directory
    + user/group: owner of the transferred files (``--chown``); needs root
    + excludes: extra rsync exclude patterns, added to ``MANDATORY_EXCLUDES``
    + delete: remove remote files missing from ``src`` (excluded paths are kept)
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
            dry_run=dry_run,
        )

    plan = _dry_run(runner, argv(dry_run=True))
    if not plan.itemized_lines:
        host.noop(f"{dest_path} is up to date")
        return
    yield FunctionCommand(_run_rsync, (runner, argv(dry_run=False)), {})
