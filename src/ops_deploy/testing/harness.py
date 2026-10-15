"""In-process deploy runs against pyinfra's ``@fake`` connector.

``@fake`` only sees connector shell commands and file transfers. Python
callbacks (``FunctionCommand``) execute on the controller and are invisible to
the connector, so the harness records them too. Code that would shell out on
the controller (rsync) takes an injectable runner; tests pass a
:class:`RecordingRsyncRunner`, so a harness run performs no external I/O.

Typical use::

    run = run_deploy_fake(deploy_toy, cfg, rsync=RecordingRsyncRunner())
    assert run.succeeded
    assert "systemctl restart toy.service" in run.executed_commands
"""

from __future__ import annotations

import io
import re
import threading
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from pyinfra.api import Config, Inventory, State
from pyinfra.api import facts as pyinfra_facts
from pyinfra.api.arguments import CONNECTOR_ARGUMENT_KEYS
from pyinfra.api.command import FunctionCommand, StringCommand
from pyinfra.api.connect import connect_all, disconnect_all
from pyinfra.api.deploy import add_deploy
from pyinfra.api.exceptions import PyinfraError
from pyinfra.api.host import Host
from pyinfra.api.operations import run_ops
from pyinfra.connectors.fake import FakeConnector
from pyinfra.connectors.util import make_unix_command_for_host
from pyinfra.context import ctx_host, ctx_state

from ops_deploy.core.rsync import RsyncResult
from ops_deploy.helpers.checks import is_read_only

EventKind = Literal["fact", "shell", "put", "function"]
Phase = Literal["plan", "execute"]

FAKE_HOST = "@fake/target"

# The recording patches classes process-wide; serialise harness runs.
_RECORDING_LOCK = threading.Lock()


@dataclass(frozen=True)
class RecordedEvent:
    """One thing the deploy did, in order.

    ``value`` is the masked shell command for ``fact`` (a command run to gather
    a fact) and ``shell`` (any other command), the remote path for ``put`` and
    the callback's qualified name for ``function``. pyinfra re-reads facts
    while executing, so ``fact`` events occur in both phases.
    """

    phase: Phase
    kind: EventKind
    value: str


@dataclass(frozen=True)
class OpResult:
    name: str
    changed: bool
    succeeded: bool
    # pyinfra's string form of the op arguments, printed for unnamed ops.
    args: tuple[str, ...] = ()
    # Tagged with ``ops_deploy.helpers.mark_read_only`` (health checks).
    read_only: bool = False


@dataclass
class DeployRun:
    """Per-operation outcome of one deploy run, on any connector."""

    ops: list[OpResult] = field(default_factory=list)
    error: PyinfraError | None = None

    @property
    def succeeded(self) -> bool:
        return self.error is None and all(op.succeeded for op in self.ops)

    @property
    def changed_ops(self) -> list[str]:
        return [op.name for op in self.ops if op.changed]

    @property
    def mutating_changed_ops(self) -> list[str]:
        """Changed ops minus read-only checks; empty on a converged second run."""

        return [op.name for op in self.ops if op.changed and not op.read_only]

    def op(self, name: str) -> OpResult:
        matches = [op for op in self.ops if op.name == name]
        if len(matches) != 1:
            raise KeyError(f"expected exactly one op named {name!r}, found {len(matches)}")
        return matches[0]


def fish_unsafe(command: str) -> bool:
    """Whether a fish login shell would read the wire command ``command`` differently from ``sh``.

    sshd hands each command to the login shell of the SSH user; root's on
    macmini and staging is fish. pyinfra sends ``sh -c '<command>'`` (see
    :func:`wire_command`), and inside single quotes fish, unlike sh and bash,
    reads ``\\\\`` and ``\\'`` as escapes: a backslash pair reaches ``sh`` halved,
    and a command ending in a backslash leaves the quote open. Single
    backslashes before any other character are safe.
    """

    return "\\\\" in command or "\\'" in command


def wire_command(state: State, host: Host, command: str | StringCommand, arguments: Mapping[str, Any]) -> str:
    """The command line pyinfra's SSH connector sends for ``command`` (unmasked).

    The same wrapping as the connector: ``_env``, ``_chdir`` and the
    ``<shell> -c '...'`` quoting, from the operation's connector arguments.
    """

    wanted = {k: v for k, v in arguments.items() if k in CONNECTOR_ARGUMENT_KEYS}
    for key in ("_get_pty", "_timeout", "_stdin", "_success_exit_codes", "_retries", "_retry_delay", "_retry_until"):
        wanted.pop(key, None)
    text = StringCommand(command) if isinstance(command, str) else command
    return make_unix_command_for_host(state, host, text, **wanted).get_raw_value()


@dataclass
class FakeRun(DeployRun):
    """Everything recorded during one :func:`run_deploy_fake` call."""

    events: list[RecordedEvent] = field(default_factory=list)
    uploads: list[tuple[str, bytes]] = field(default_factory=list)
    stdin: list[tuple[str, str]] = field(default_factory=list)
    # Commands (masked) whose wire form a fish login shell would alter, also
    # from ops an ``_if`` gate skipped (see :func:`fish_unsafe`);
    # :func:`run_deploy_fake` fails when there is any.
    fish_unsafe_commands: list[str] = field(default_factory=list)

    @property
    def executed(self) -> list[RecordedEvent]:
        """Events from the execution phase (what would mutate the host)."""

        return [event for event in self.events if event.phase == "execute"]

    @property
    def executed_commands(self) -> list[str]:
        """Non-fact shell commands run while executing, in order."""

        return [event.value for event in self.executed if event.kind == "shell"]

    @property
    def fact_commands(self) -> list[str]:
        """Shell commands run to gather facts, in either phase."""

        return [event.value for event in self.events if event.kind == "fact"]

    @property
    def function_calls(self) -> list[str]:
        return [event.value for event in self.executed if event.kind == "function"]

    @property
    def uploaded_paths(self) -> list[str]:
        return [path for path, _ in self.uploads]

    def upload(self, path: str) -> bytes:
        """Content of the single upload to ``path``."""

        matches = [content for remote, content in self.uploads if remote == path]
        if len(matches) != 1:
            raise KeyError(f"expected exactly one upload to {path!r}, found {len(matches)}")
        return matches[0]

    def all_text(self) -> str:
        """Every recorded command, path, callback name, op name and argument and
        upload, for leak checks.

        Command stdin (:attr:`stdin`) is deliberately excluded: it is the
        channel secrets are meant to travel on.
        """

        parts = [event.value for event in self.events]
        parts.extend(text for op in self.ops for text in (op.name, *op.args))
        parts.extend(content.decode("utf-8", errors="replace") for _, content in self.uploads)
        return "\n".join(parts)


@dataclass
class RecordingRsyncRunner:
    """Rsync runner that records argv and returns scripted results.

    ``responses`` maps a matcher (substring ``str`` or compiled pattern, tried
    in order against the space-joined argv) to a :class:`RsyncResult` or to a
    list of itemized output lines. Unmatched calls succeed with no output,
    meaning "nothing to transfer".
    """

    responses: Mapping[Any, RsyncResult | Sequence[str]] = field(default_factory=dict)
    calls: list[list[str]] = field(default_factory=list)

    def __call__(self, argv: Sequence[str]) -> RsyncResult:
        self.calls.append(list(argv))
        joined = " ".join(argv)
        for matcher, response in self.responses.items():
            if isinstance(matcher, re.Pattern):
                if not matcher.search(joined):
                    continue
            elif matcher not in joined:
                continue
            if isinstance(response, RsyncResult):
                return response
            return RsyncResult(0, "".join(f"{line}\n" for line in response))
        return RsyncResult(0)


def run_deploy_fake(
    deploy_fn: Callable[..., Any],
    *args: Any,
    responses: Mapping[Any, Any] | None = None,
    host_data: Mapping[str, Any] | None = None,
    **kwargs: Any,
) -> FakeRun:
    """Plan and execute ``deploy_fn(*args, **kwargs)`` against one ``@fake`` host.

    ``responses`` is the connector's ``fake_responses`` mapping (first match
    wins, unmatched commands succeed with no output). A failing operation does
    not raise; inspect :attr:`FakeRun.succeeded` / :attr:`FakeRun.error`.
    """

    data: dict[str, Any] = dict(host_data or {})
    data.update(
        {
            "fake_responses": dict(responses or {}),
            "fake_delay": 0,
            "fake_delay_jitter": 0,
        }
    )
    inventory = Inventory(([(FAKE_HOST, data)], {}))
    state = State(inventory, Config())
    run = FakeRun()

    with _RECORDING_LOCK, _recording(run) as phase:
        try:
            connect_all(state)
            add_deploy(state, deploy_fn, *args, **kwargs)
            phase[0] = "execute"
            run_ops(state)
        except PyinfraError as exc:
            run.error = exc
        finally:
            run.ops = collect_ops(state, FAKE_HOST)
            recorded = len(run.events), len(run.uploads), len(run.stdin)
            run.fish_unsafe_commands.extend(_gated_fish_unsafe(state, FAKE_HOST))
            del run.events[recorded[0] :], run.uploads[recorded[1] :], run.stdin[recorded[2] :]
            disconnect_all(state)

    if run.fish_unsafe_commands:
        raise AssertionError(f"commands a fish login shell would alter: {run.fish_unsafe_commands}")
    return run


@contextmanager
def _recording(run: FakeRun) -> Iterator[list[Phase]]:
    phase: list[Phase] = ["plan"]
    fact_depth = [0]

    original_shell = FakeConnector.run_shell_command
    original_put = FakeConnector.put_file
    original_execute = FunctionCommand.execute
    original_get_fact = pyinfra_facts._get_fact

    def run_shell_command(self: FakeConnector, command: Any, *a: Any, **kw: Any) -> Any:
        text = command if isinstance(command, str) else command.get_masked_value()
        if fish_unsafe(wire_command(self.state, self.host, command, kw)):
            run.fish_unsafe_commands.append(text)
        kind: EventKind = "fact" if fact_depth[0] else "shell"
        run.events.append(RecordedEvent(phase[0], kind, text))
        stdin = kw.get("_stdin")
        if stdin is not None:
            run.stdin.append((text, _read_stdin(stdin)))
        return original_shell(self, command, *a, **kw)

    def put_file(self: FakeConnector, filename_or_io: Any, remote_filename: str, *a: Any, **kw: Any) -> Any:
        run.events.append(RecordedEvent(phase[0], "put", remote_filename))
        run.uploads.append((remote_filename, _read_upload(filename_or_io)))
        return original_put(self, filename_or_io, remote_filename, *a, **kw)

    def execute(self: FunctionCommand, *a: Any, **kw: Any) -> Any:
        name = getattr(self.function, "__qualname__", repr(self.function))
        run.events.append(RecordedEvent(phase[0], "function", name))
        return original_execute(self, *a, **kw)

    def get_fact(*a: Any, **kw: Any) -> Any:
        fact_depth[0] += 1
        try:
            return original_get_fact(*a, **kw)
        finally:
            fact_depth[0] -= 1

    pyinfra_facts._get_fact = get_fact
    FakeConnector.run_shell_command = run_shell_command  # type: ignore[method-assign]
    FakeConnector.put_file = put_file  # type: ignore[method-assign]
    FunctionCommand.execute = execute  # type: ignore[method-assign]
    try:
        yield phase
    finally:
        FakeConnector.run_shell_command = original_shell  # type: ignore[method-assign]
        FakeConnector.put_file = original_put  # type: ignore[method-assign]
        FunctionCommand.execute = original_execute  # type: ignore[method-assign]
        pyinfra_facts._get_fact = original_get_fact


def _read_stdin(stdin: Any) -> str:
    """What pyinfra's ``write_stdin`` sends: every line, newline-terminated."""

    if hasattr(stdin, "readlines"):
        raise TypeError("the harness only records str or line-list stdin")
    lines = [stdin] if isinstance(stdin, str) else list(stdin)
    return "".join(line if line.endswith("\n") else f"{line}\n" for line in lines)


def _read_upload(filename_or_io: Any) -> bytes:
    if isinstance(filename_or_io, (str, Path)):
        return Path(filename_or_io).read_bytes()
    # Read from the start, as pyinfra's connectors do, then restore the cursor.
    position = filename_or_io.tell()
    filename_or_io.seek(0)
    content = filename_or_io.read()
    filename_or_io.seek(position)
    if isinstance(content, str):
        return content.encode()
    if isinstance(filename_or_io, io.IOBase) or isinstance(content, bytes):
        return bytes(content)
    raise TypeError(f"cannot read upload source {type(filename_or_io).__name__}")


def _gated_fish_unsafe(state: State, host_name: str) -> list[str]:
    """Fish-unsafe commands of the ops an ``_if`` gate skipped.

    A skipped op never generates its commands, so the run cannot see them.
    Each is generated here once more with the gate ignored (pyinfra checks
    ``_if`` only while executing); facts it reads come from the fake host.
    """

    host = state.inventory.get_host(host_name)
    found: list[str] = []
    was_executing = state.is_executing
    state.is_executing = False
    try:
        for op_hash in state.get_op_order():
            try:
                op_data = state.get_op_data_for_host(host, op_hash)
            except KeyError:
                continue
            if not op_data.global_arguments.get("_if") or op_data.operation_meta._commands:
                continue
            with ctx_state.use(state), ctx_host.use(host):
                commands = list(op_data.command_generator())
            arguments = {k: v for k, v in op_data.global_arguments.items() if k in CONNECTOR_ARGUMENT_KEYS}
            for command in commands:
                if not isinstance(command, StringCommand):
                    continue
                if fish_unsafe(wire_command(state, host, command, {**arguments, **command.connector_arguments})):
                    found.append(f"(gated) {command.get_masked_value()}")
    finally:
        state.is_executing = was_executing
    return found


def collect_ops(state: State, host_name: str) -> list[OpResult]:
    """Per-operation results for ``host_name`` after ``run_ops``, in op order."""

    host = state.inventory.get_host(host_name)
    results = []
    for op_hash in state.get_op_order():
        try:
            op_data = state.get_op_data_for_host(host, op_hash)
        except KeyError:
            continue
        meta = op_data.operation_meta
        op_meta = state.get_op_meta(op_hash)
        name = ", ".join(sorted(op_meta.names))
        complete = meta.is_complete()
        results.append(
            OpResult(
                name=name,
                changed=complete and meta.did_change(),
                succeeded=complete and meta.did_succeed(),
                args=tuple(op_meta.args),
                read_only=is_read_only(state, op_hash),
            )
        )
    return results
