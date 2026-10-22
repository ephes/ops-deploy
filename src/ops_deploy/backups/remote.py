"""Run a bash script on a host from the controller, outside a pyinfra run.

The backup steps in :mod:`ops_deploy.backups` run *before* a deploy (or on
their own, from an explicit backup command), so they cannot be pyinfra
operations: an operation is planned first and executed later, and its output
cannot decide whether the deploy goes on. Instead each step sends a fixed bash
script on stdin (``bash -s -- ARGS``) and reads the result.

A :data:`Runner` is any callable with the signature of
:meth:`SubprocessRunner.__call__`; tests pass a fake. :func:`ssh_runner` builds
the real one. Scripts travel on stdin, so their text never passes through the
remote login shell (fish on some hosts, see :func:`check_arg`); only the
arguments do, quoted, and :func:`check_arg` refuses the few characters a fish
login shell would read differently from ``sh``.
"""

from __future__ import annotations

import contextlib
import math
import os
import shlex
import signal
import subprocess
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field


class RemoteCommandError(RuntimeError):
    """The script could not be run at all (ssh missing, timeout, bad argument)."""


@dataclass(frozen=True)
class CommandResult:
    """Exit status and output of one script run."""

    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


Runner = Callable[[str, Sequence[str], float], CommandResult]
"""``runner(script, args, timeout)``: run ``script`` with bash, ``args`` as ``$1...``."""


def check_arg(value: str) -> str:
    """``value`` as a script argument, or :class:`RemoteCommandError`.

    sshd joins the remote command into one line for the user's login shell.
    Inside single quotes, fish (root's login shell on some hosts) reads ``\\\\``
    and ``\\'`` as escapes, so a backslash is refused; so are newlines and NUL,
    which no path, target name or label here needs.
    """

    if any(char in value for char in ("\\", "\n", "\r", "\0")):
        raise RemoteCommandError(f"refusing script argument with a backslash, newline or NUL: {value!r}")
    return value


# Seconds between SIGTERM and SIGKILL when a run times out, and the margin the
# controller gives a remote ``timeout`` to stop and clean up first.
STOP_GRACE = 30.0


@dataclass(frozen=True)
class SubprocessRunner:
    """Run scripts with ``bash -s`` behind ``prefix`` (empty: on this machine).

    ``quote`` quotes each argument for a remote shell: ``ssh`` joins its
    arguments into one command line, a local ``bash`` gets them as argv.

    On timeout the whole local process group gets ``SIGTERM`` (the scripts trap
    it and remove partial files), and whatever is left of it ``SIGKILL`` after
    ``stop_grace`` seconds (default :data:`STOP_GRACE`).
    Killing a local ``ssh`` does not stop the remote side, so with
    ``remote_timeout`` the remote command runs under coreutils ``timeout``
    (``SIGTERM`` to the remote process group, ``SIGKILL`` after the grace),
    and the controller waits that long plus a margin before it gives up.
    """

    prefix: tuple[str, ...] = ()
    quote: bool = False
    env: Mapping[str, str] | None = None
    remote_timeout: bool = False
    stop_grace: float = STOP_GRACE

    def __call__(self, script: str, args: Sequence[str], timeout: float) -> CommandResult:
        checked = [check_arg(arg) for arg in args]
        tail = [shlex.quote(arg) for arg in checked] if self.quote else checked
        command = ["bash", "-s", "--", *tail]
        local_timeout = timeout
        if self.remote_timeout:
            seconds = max(1, math.ceil(timeout))
            grace = max(1, math.ceil(self.stop_grace))
            command = ["timeout", "-k", str(grace), str(seconds), *command]
            local_timeout = seconds + 2 * grace
        argv = [*self.prefix, *command]
        try:
            process = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=None if self.env is None else dict(self.env),
                start_new_session=True,
            )
        except OSError as exc:
            raise RemoteCommandError(f"cannot run {argv[0]}: {exc}") from exc
        try:
            stdout, stderr = process.communicate(script, timeout=local_timeout)
        except subprocess.TimeoutExpired:
            _stop(process, self.stop_grace)
            raise RemoteCommandError(
                f"{' '.join(self.prefix) or 'bash'}: no result within {local_timeout:.0f}s; stopped"
            ) from None
        if self.remote_timeout and process.returncode in (124, 137):
            raise RemoteCommandError(f"{' '.join(self.prefix)}: no result within {timeout:.0f}s; stopped on the host")
        return CommandResult(process.returncode, stdout, stderr)


def _stop(process: subprocess.Popen[str], grace: float) -> None:
    """SIGTERM to the process group; SIGKILL to whatever is left after ``grace``.

    The group outlives its leader when a member ignores SIGTERM, so the end of
    the leader is not the end of the wait: the group gets SIGKILL unless it is
    gone within ``grace``.
    """

    deadline = time.monotonic() + grace
    _signal_group(process.pid, signal.SIGTERM)
    with contextlib.suppress(subprocess.TimeoutExpired):
        process.communicate(timeout=grace)
    while time.monotonic() < deadline and _signal_group(process.pid, 0):
        time.sleep(0.05)
    _signal_group(process.pid, signal.SIGKILL)
    # A member that left the group could still hold the pipes open.
    with contextlib.suppress(subprocess.TimeoutExpired):
        process.communicate(timeout=5)


def _signal_group(pgid: int, sig: int) -> bool:
    """Send ``sig`` to the group; whether any member was left to receive it."""

    try:
        os.killpg(pgid, sig)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


@dataclass(frozen=True)
class SshTarget:
    """Where :func:`ssh_runner` connects; mirrors pyinfra's ssh connector keys."""

    hostname: str
    user: str | None = None
    port: int | None = None
    key: str | None = None
    known_hosts_file: str | None = None
    strict_host_key_checking: str | None = None
    options: tuple[tuple[str, str], ...] = field(default=())


def ssh_command(target: SshTarget) -> tuple[str, ...]:
    """The ``ssh`` argv up to the remote command (BatchMode: never prompts)."""

    argv = ["ssh", "-o", "BatchMode=yes"]
    if target.port is not None:
        argv += ["-p", str(target.port)]
    if target.key is not None:
        argv += ["-i", target.key]
    if target.known_hosts_file is not None:
        argv += ["-o", f"UserKnownHostsFile={target.known_hosts_file}"]
    if target.strict_host_key_checking is not None:
        argv += ["-o", f"StrictHostKeyChecking={target.strict_host_key_checking}"]
    for key, value in target.options:
        argv += ["-o", f"{key}={value}"]
    if target.user is not None:
        argv += ["-l", target.user]
    # ``--`` ends ssh's options: a hostname can never be read as one.
    return (*argv, "--", target.hostname)


def ssh_runner(target: SshTarget, *, env: Mapping[str, str] | None = None) -> SubprocessRunner:
    """A :data:`Runner` that runs scripts on ``target`` over ssh.

    The remote side runs under coreutils ``timeout`` (``remote_timeout``), so a
    run that outlives its timeout is stopped on the host too.
    """

    return SubprocessRunner(prefix=ssh_command(target), quote=True, env=env, remote_timeout=True)
