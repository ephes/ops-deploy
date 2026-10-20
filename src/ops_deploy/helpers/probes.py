"""Read-only probes that report their failures instead of answering with them.

A deploy decides while planning whether a step is needed by asking the host:
``migrate --check``, a check-mode run of a wiring script, a database query.
A probe written as ``... 2>/dev/null || true`` turns every failure (a broken
venv, a crashed script, a command a login shell mangled) into an answer such
as "not current", and the deploy carries on as if the host had said so.

Probes here are strict: the command prints its answer and exits non-zero on
any error. States that are expected before a first deploy (no venv, no
database yet) are answers the command prints itself, never a failure.

A failed probe is not fatal while planning, because the step it gates is how
a half-finished earlier run repairs itself (a sync that died before
``uv sync``). :func:`probe` logs the failure and returns ``None``; the caller
runs the gated step and then :func:`verify_probe`, which runs the probe again
and fails the deploy if it still fails (or still does not give the expected
answer). A probe that fails for its own reasons can no longer pass as a
change that is needed on every run.
"""

from __future__ import annotations

import shlex
from collections.abc import Iterable
from pathlib import PurePosixPath
from typing import Any

from pyinfra import host, logger
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.server import Command
from pyinfra.operations import server

from ops_deploy.helpers.checks import mark_read_only

FAILED = "ops-deploy-probe-failed"


def probe_command(command: str) -> str:
    """The fact command :func:`probe` runs: ``command`` in a subshell, a marker line if it fails."""

    # The marker on a line of its own, also after output without a final newline.
    return f"( {command} ) || {{ echo; echo {FAILED}; }}"


def probe_output(output: str) -> str | None:
    """:func:`probe_command`'s stdout, or ``None`` when it ends in the failure marker."""

    return None if output.splitlines()[-1:] == [FAILED] else output


class StdinLines(list[str]):
    """``_stdin`` for a fact or command that prints as ``<stdin redacted>``.

    pyinfra logs a fact's arguments, ``_stdin`` included ("Loaded fact ..."),
    so a plain string payload would end up in its debug output.
    """

    def __init__(self, text: str) -> None:
        super().__init__(text.splitlines(keepends=True))

    def __repr__(self) -> str:
        return "<stdin redacted>"

    __str__ = __repr__


def stdin_arguments(stdin: str | None) -> dict[str, Any]:
    """Global arguments that feed ``stdin`` (redacted in pyinfra's logs) without a pty, which would echo it."""

    return {} if stdin is None else {"_stdin": StdinLines(stdin), "_get_pty": False}


def probe(command: str, *, name: str, stdin: str | None = None) -> str | None:
    """Stdout of the strict probe ``command`` while planning, or ``None`` if it failed.

    The command runs in a subshell, so it may ``exit``. A failure is logged as
    a warning; follow the step the probe gates with :func:`verify_probe`.
    ``stdin``: text for the command's standard input (data that must stay off
    the command line, such as a check payload; line based, so text only).
    """

    output = probe_output(str(host.get_fact(Command, command=probe_command(command), **stdin_arguments(stdin)) or ""))
    if output is None:
        logger.warning(f"{host.print_prefix}probe failed: {name}; running the step it gates and probing again after it")
    return output


def verify_probe(command: str, *, name: str, expect: str | None = None, stdin: str | None = None) -> OperationMeta:
    """Read-only operation: the probe ``command`` succeeds now (and its last line is ``expect``).

    Its error output is the operation's; a still failing probe fails the deploy.
    ``stdin`` as for :func:`probe`.
    """

    script = f"out=$( {command} ) || {{ echo {shlex.quote(f'probe still fails: {name}')} >&2; exit 1; }}"
    if expect is not None:
        wrong = shlex.quote(f"probe answers something else than {expect}: {name}")
        script += f'; [ "$(printf %s "$out" | tail -n 1)" = {shlex.quote(expect)} ] || {{ echo {wrong} >&2; exit 1; }}'
    return mark_read_only(server.shell(name=f"Probe again: {name}", commands=[script], **stdin_arguments(stdin)))


def when_present(paths: Iterable[PurePosixPath | str], command: str, *, otherwise: str) -> str:
    """``command`` if every path exists, else ``echo <otherwise>`` (a state before a first deploy)."""

    tests = " && ".join(f"test -e {shlex.quote(str(path))}" for path in paths)
    return f"if {tests}; then {command}; else echo {shlex.quote(otherwise)}; fi" if tests else command


def migrations_state(plan: str) -> str:
    """Probe around ``plan``, a ``manage.py migrate --check --plan`` as the service runs it.

    Prints ``current`` or ``pending``. ``migrate --check`` exits 1 both for an
    unapplied migration and for an error; with ``--plan`` Django prints
    "Planned operations:" before it exits for the former, so a failure without
    that line is an error.
    """

    return (
        f"if out=$( {plan} ); then echo current; "
        'else case "$out" in *"Planned operations:"*) echo pending ;; *) exit 1 ;; esac; fi'
    )


def last_line(command: str) -> str:
    """Probe printing the last stdout line of ``command``; fails when ``command`` fails."""

    # "$( (" not "$((": a command starting with a subshell is not arithmetic.
    return f"out=$( {command} ) || exit 1; printf '%s\\n' \"$out\" | tail -n 1"


def uv_sync_state(check: str) -> str:
    """Probe around ``check``, a ``uv sync ... --check``: prints ``current`` or ``pending``.

    uv exits 1 when the environment is out of step with the lock file and 2 on
    an error, which fails the probe.
    """

    return f"{check} >/dev/null; rc=$?; case $rc in 0) echo current ;; 1) echo pending ;; *) exit $rc ;; esac"
