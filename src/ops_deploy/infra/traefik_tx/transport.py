"""Controller side of detached Traefik transactions: stage, start, poll, wait, clean up, inspect.

A binary transaction must not depend on the session that started it: an SSH drop, a
sleeping controller or a killed caller between the binary replacement and its acceptance
would leave a new binary, a ``pending`` record and no rollback. So the engine
(:mod:`ops_deploy.infra.traefik_tx.engine`; ``binary``, and ``resume`` and ``rebaseline``
the same way) runs on the host in a transient
systemd unit, ``traefik-tx-<id>.service``, launched with ``systemd-run`` (``RuntimeMaxSec``,
``--collect``), and the controller polls its result over fresh connections. When that
unit fails (the engine was killed, timed out or gave no result, or the host record was
left ``pending``), ``OnFailure=`` starts ``traefik-tx-safe-restore@<id>.service``, which
puts the original binary back under the rules in
:mod:`ops_deploy.infra.traefik_tx.runner`.

Each step is a bash script sent through a :data:`~ops_deploy.backups.remote.Runner`
(``ssh`` to the host, script on stdin; :func:`~ops_deploy.backups.remote.ssh_runner`
builds one), like the steps in :mod:`ops_deploy.backups`: its result decides what the
caller does next, which a planned pyinfra operation cannot hand back. Every call is a
new connection. The script carries the host program
(:mod:`~ops_deploy.infra.traefik_tx.runner`) and, for :func:`stage_transaction` and
:func:`inspect_host`, the engine and the request, base64-encoded into a private
``mktemp -d`` directory that it removes again; nothing secret is on a command line.

The caller keeps the paired controller journal (as ops-library's ``traefik_control.py``
does): stage first (an unreachable host, GitHub or a checksum mismatch fails here,
before any ``pending`` record), then write the controller's ``pending`` record, then
:func:`start_transaction`, :func:`wait_for_transaction`, persist the returned host
record (:attr:`TransactionStatus.host_record`) and :func:`cleanup_transaction`.
Failures are :class:`TransportError` with a fixed reason and never a host name.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import re
import shlex
import time
import uuid
import zlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast

from ops_deploy.backups.remote import CommandResult, RemoteCommandError, Runner
from ops_deploy.infra.traefik_probes import PROGRAM as PROBE_PROGRAM

ENGINE = (Path(__file__).parent / "engine.py").read_bytes()
RUNNER = (Path(__file__).parent / "runner.py").read_bytes()
RETENTION = (Path(__file__).parent / "retention.py").read_bytes()
ENGINE_SHA256 = hashlib.sha256(ENGINE).hexdigest()
RUNNER_SHA256 = hashlib.sha256(RUNNER).hexdigest()
PYTHON = "/usr/bin/python3"
TRANSPORT_ROOT = "/var/lib/traefik-transport"
DEFAULT_RUNTIME_MAX = 900
_TRANSACTION_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")

Status = Literal["absent", "incomplete", "staged", "running", "restoring", "finished", "interrupted", "unknown"]
STATUSES: frozenset[str] = frozenset(
    {"absent", "incomplete", "staged", "running", "restoring", "finished", "interrupted"}
)
FINAL: frozenset[str] = frozenset({"absent", "finished", "interrupted"})


class TransportError(RuntimeError):
    """A transport step failed or was refused; the message is a fixed reason without host data."""


@dataclass(frozen=True)
class Staged:
    """A staged transaction: its files are in place and verified, nothing ran yet."""

    transaction_id: str
    action: str
    request_sha256: str
    archive_sha256: str | None


@dataclass(frozen=True)
class TransactionStatus:
    """What :func:`poll_transaction` found.

    ``status``: ``absent`` (no transport directory), ``incomplete`` (staging did not
    finish), ``staged`` (never started), ``running``, ``restoring`` (the safe-restore
    unit runs or is due), ``finished`` (the engine's result is final), ``interrupted``
    (the engine gave no result), and from :func:`wait_for_transaction` only
    ``unknown`` (no poll got an answer). ``started``: the engine was started; until
    then nothing on the host was changed by it. ``result``: the unit's ``result.json``
    (``engine_exit``, ``response`` (the engine's JSON), ``host_phase``,
    ``restore_expected``); ``safe_restore``: the safe-restore unit's
    ``safe-restore.json`` (``acted``, ``reason``, ``phase``, ``state``).
    """

    transaction_id: str
    status: Status
    staged: bool = False
    started: bool = False
    result: dict[str, Any] | None = None
    safe_restore: dict[str, Any] | None = None

    @property
    def final(self) -> bool:
        """Nothing of the transaction runs or is due any more."""

        return self.status in FINAL

    @property
    def engine_exit(self) -> int | None:
        value = None if self.result is None else self.result.get("engine_exit")
        return value if isinstance(value, int) else None

    @property
    def response(self) -> dict[str, Any] | None:
        value = None if self.result is None else self.result.get("response")
        return value if isinstance(value, dict) else None

    @property
    def host_record(self) -> dict[str, Any] | None:
        """The host record the transaction left, as returned to the controller, or ``None``.

        The safe-restore unit's record when it acted and saved one, else the engine's
        ``state`` once the status is final. ``None`` means the outcome is unknown: the
        controller keeps its ``pending`` record.
        """

        if not self.final:
            return None
        restored = self.safe_restore or {}
        if restored.get("acted") is True:
            state = restored.get("state")
            return state if isinstance(state, dict) else None
        if self.status != "finished" or self.response is None:
            return None
        state = self.response.get("state")
        return state if isinstance(state, dict) else None


@dataclass(frozen=True)
class EngineRun:
    """The engine's exit status and its JSON output."""

    exit_code: int
    response: dict[str, Any]


def new_transaction_id() -> str:
    return str(uuid.uuid4())


def _check_id(transaction_id: str) -> str:
    if not isinstance(transaction_id, str) or not _TRANSACTION_ID.fullmatch(transaction_id):
        raise TransportError("invalid transaction id")
    return transaction_id


def _blob(data: bytes) -> str:
    return base64.encodebytes(data).decode("ascii")


_SCRIPT = """set -euo pipefail
umask 077
fail() {{ echo "traefik tx: $*" >&2; exit 1; }}
if ! {python} -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then
    fail "{python} 3.11 or newer is required"
fi
dir=$(mktemp -d -t traefik-tx-XXXXXXXXXX)
trap 'rm -rf -- "$dir"' EXIT
trap 'exit 143' TERM HUP INT
{files}{python} -I "$dir/runner.py" {command}
"""
_FILE = """base64 -d >"$dir/{name}" <<'OPS_DEPLOY_{tag}'
{data}OPS_DEPLOY_{tag}
"""


def script(command: str, files: Mapping[str, bytes] | None = None) -> str:
    """The bash script that runs ``runner.py <command>`` with ``files`` next to it.

    ``command`` is the runner's arguments, written as bash words: ``$1``... are the
    script arguments, ``$dir`` the private directory holding the program and ``files``.
    """

    blocks = {"runner.py": RUNNER, **(files or {})}
    text = "".join(
        _FILE.format(name=name, tag=re.sub(r"[^A-Z]", "_", name.upper()), data=_blob(data))
        for name, data in blocks.items()
    )
    return _SCRIPT.format(python=PYTHON, files=text, command=command)


def _failure(what: str, result: CommandResult) -> TransportError:
    # Only the runner's and the script's own fixed reasons are passed on.
    lines = result.stderr.strip().splitlines()
    if lines and lines[-1].startswith("traefik tx: "):
        return TransportError(f"{what}: {lines[-1].removeprefix('traefik tx: ')}")
    return TransportError(f"{what}: failed (exit {result.returncode})")


def _call(
    runner: Runner, what: str, command: str, args: list[str], timeout: float, files: Mapping[str, bytes] | None = None
) -> dict[str, Any]:
    try:
        result = runner(script(command, files), args, timeout)
    except RemoteCommandError:
        # Not chained: the ssh error names the target host.
        raise TransportError(f"{what}: no result (ssh failed or timed out)") from None
    if not result.ok:
        raise _failure(what, result)
    try:
        value = json.loads(result.stdout)
    except ValueError:
        raise TransportError(f"{what}: unusable result") from None
    if not isinstance(value, dict) or value.get("schema") != 1:
        raise TransportError(f"{what}: unusable result")
    return cast(dict[str, Any], value)


def _request_bytes(request: Mapping[str, Any]) -> bytes:
    try:
        return (json.dumps(dict(request), sort_keys=True) + "\n").encode()
    except (TypeError, ValueError):
        raise TransportError("stage: the request is not JSON") from None


def staged_request(request: Mapping[str, Any], transaction_id: str) -> bytes:
    """``request.json`` as the host program writes it into the transport directory.

    For ``binary`` it names the transport's copy of the archive as ``archive_path``,
    as the Ansible transport does; for ``resume`` there is none.
    """

    value = json.loads(_request_bytes(request))
    if value.get("action") == "binary" or (value.get("action") == "routine" and value.get("release") is not None):
        value["archive_path"] = f"{TRANSPORT_ROOT}/{_check_id(transaction_id)}/release.tar.gz"
    else:
        value.pop("archive_path", None)
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def stage_transaction(
    runner: Runner, request: Mapping[str, Any], transaction_id: str, *, timeout: float = 600
) -> Staged:
    """Put engine, runner and ``request`` on the host and fetch the release archive there.

    ``request`` is the engine request for ``binary``, ``resume`` or ``rebaseline`` (ops-library's
    ``TRANSACTIONS.md`` format, ``controller_state`` included); for ``binary`` the host
    downloads ``release.version`` for ``release.arch`` from GitHub and refuses unless
    it has exactly ``release.sha256``, and ``archive_path`` is set to that copy. Nothing
    runs yet: a failure here leaves no transaction and needs no ``pending`` record.
    """

    _check_id(transaction_id)
    action = request.get("action")
    if action not in ("binary", "resume", "rebaseline", "routine"):
        raise TransportError("stage: only binary, resume and rebaseline transactions run detached")
    staged = _call(
        runner,
        "stage",
        'stage "$1" "$dir"',
        [transaction_id],
        timeout,
        {"engine.py": ENGINE, "request.json": _request_bytes(request)},
    )
    release = request.get("release") if action in {"binary", "routine"} else None
    archive = release.get("sha256") if isinstance(release, Mapping) else None
    expected = hashlib.sha256(staged_request(request, transaction_id)).hexdigest()
    if (
        staged.get("id") != transaction_id
        or staged.get("action") != action
        or staged.get("engine_sha256") != ENGINE_SHA256
        or staged.get("runner_sha256") != RUNNER_SHA256
        or staged.get("request_sha256") != expected
        or staged.get("archive_sha256") != archive
    ):
        raise TransportError("stage: the staged files are not the ones sent")
    return Staged(transaction_id, str(action), expected, archive)


def start_transaction(
    runner: Runner, transaction_id: str, *, runtime_max_sec: int = DEFAULT_RUNTIME_MAX, timeout: float = 120
) -> None:
    """Launch the staged transaction's unit; returns once it runs.

    ``runtime_max_sec`` (60 to 3600) bounds the unit: when it is exceeded systemd stops
    the unit and the safe-restore unit takes over (up to 600 s more), so wait at least
    that long in total. A :class:`TransportError` here does not prove that nothing
    started: :func:`poll_transaction` tells (``staged`` means the engine never ran).
    """

    _check_id(transaction_id)
    if not isinstance(runtime_max_sec, int) or not 60 <= runtime_max_sec <= 3600:
        raise TransportError("start: runtime_max_sec must be between 60 and 3600")
    started = _call(runner, "start", 'start "$1" "$2"', [transaction_id, str(runtime_max_sec)], timeout)
    if started.get("id") != transaction_id or started.get("started") is not True:
        raise TransportError("start: unusable result")


def poll_transaction(runner: Runner, transaction_id: str, *, timeout: float = 60) -> TransactionStatus:
    """The transaction's status, read-only, over a new connection."""

    _check_id(transaction_id)
    found = _call(runner, "poll", 'poll "$1"', [transaction_id], timeout)
    status, result, restored = found.get("status"), found.get("result"), found.get("safe_restore")
    staged, started = found.get("staged"), found.get("started")
    if (
        found.get("id") != transaction_id
        or status not in STATUSES
        or not isinstance(staged, bool)
        or not isinstance(started, bool)
        or not (result is None or isinstance(result, dict))
        or not (restored is None or isinstance(restored, dict))
    ):
        raise TransportError("poll: unusable result")
    return TransactionStatus(transaction_id, cast(Status, status), staged, started, result, restored)


def wait_for_transaction(
    runner: Runner,
    transaction_id: str,
    *,
    timeout: float,
    interval: float = 5,
    poll_timeout: float = 60,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> TransactionStatus:
    """Poll every ``interval`` seconds until the status is final or ``timeout`` has passed.

    A failed poll (ssh, a refusal) only waits for the next one. Returns the last status
    (``final`` tells whether it is the outcome), or ``unknown`` if no poll answered.
    """

    deadline = clock() + timeout
    last = TransactionStatus(_check_id(transaction_id), "unknown")
    while True:
        with contextlib.suppress(TransportError):
            last = poll_transaction(runner, transaction_id, timeout=poll_timeout)
        if last.final or clock() >= deadline:
            return last
        sleep(interval)


def cleanup_transaction(runner: Runner, transaction_id: str, *, timeout: float = 60) -> bool:
    """Remove the transport directory; whether there was one. Refused while ``running`` or ``restoring``."""

    _check_id(transaction_id)
    removed = _call(runner, "cleanup", 'cleanup "$1"', [transaction_id], timeout)
    if removed.get("id") != transaction_id or not isinstance(removed.get("removed"), bool):
        raise TransportError("cleanup: unusable result")
    return bool(removed["removed"])


def inspect_host(runner: Runner, policy: Mapping[str, Any], *, timeout: float = 300) -> EngineRun:
    """The engine's read-only ``inspect`` (``identity`` and ``state``), in the foreground.

    It writes nothing on the host but the private directory the script removes again.
    The engine's own refusals come back as its exit code and ``error``.
    """

    request = _request_bytes({"action": "inspect", "policy": dict(policy)})
    found = _call(runner, "inspect", 'inspect "$dir"', [], timeout, {"engine.py": ENGINE, "request.json": request})
    code, response = found.get("engine_exit"), found.get("response")
    if not isinstance(code, int) or not isinstance(response, dict):
        raise TransportError("inspect: unusable result")
    return EngineRun(code, response)


def prove_routine(runner: Runner, request: Mapping[str, Any], *, timeout: float = 900) -> dict[str, Any]:
    """Run the existing isolated proof with routine candidates; this is a mutating preparation step."""

    proof_source = (Path(__file__).parent / "proof.py").read_bytes()
    setup = """import json,sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import runner
root = Path(sys.argv[1])
request = json.loads((root / "request.json").read_text())
if request.pop("fetch_release", False):
    runner.fetch_release(request["release"], root / "release.tar.gz")
    request["archive_path"] = str(root / "release.tar.gz")
(root / "request.json").write_text(json.dumps(request))
"""
    blocks = {
        "runner.py": RUNNER,
        "engine.py": ENGINE,
        "proof.py": proof_source,
        "health.py": PROBE_PROGRAM,
        "request.json": _request_bytes(request),
        "prepare.py": setup.encode(),
    }
    files = "".join(
        _FILE.format(name=name, tag=re.sub(r"[^A-Z]", "_", name.upper()), data=_blob(data))
        for name, data in blocks.items()
    )
    code = _SCRIPT.format(python=PYTHON, files=files, command='inspect "$dir"')
    code = code.replace(
        f'{PYTHON} -I "$dir/runner.py" inspect "$dir"',
        f'{PYTHON} -I -B "$dir/prepare.py" "$dir"\n{PYTHON} -I -B "$dir/proof.py" --request "$dir/request.json"',
    )
    try:
        result = runner(code, [], timeout)
    except RemoteCommandError:
        raise TransportError("proof: no result") from None
    if not result.ok:
        raise _failure("proof", result)
    value = json.loads(result.stdout)
    if not isinstance(value, dict) or value.get("passed") is not True:
        raise TransportError("proof: candidate did not pass")
    return value


def memory_script(source: str) -> str:
    """A builtin printf pipe, never a shell heredoc (large heredocs spool to disk)."""

    encoded = base64.b64encode(zlib.compress(source.encode())).decode()
    bootstrap = (
        "import base64,sys,zlib; "
        "exec(compile(zlib.decompress(base64.b64decode(sys.stdin.buffer.read())), "
        "'<traefik-observation>', 'exec'))"
    )
    return f"builtin printf '%s' {shlex.quote(encoded)} | {PYTHON} -I -B -c {shlex.quote(bootstrap)}\n"


def inspect_memory_host(runner: Runner, policy: Mapping[str, Any], *, timeout: float = 300) -> EngineRun:
    """Observe without uploads, temporary files, bytecode, locks or journals."""

    payload = base64.b64encode(_request_bytes({"action": "inspect", "policy": dict(policy)})).decode()
    source = base64.b64encode(ENGINE).decode()
    program = f"""import base64,json,subprocess
namespace = {{"__name__": "traefik_observation"}}
exec(compile(base64.b64decode({source!r}), "<traefik-engine>", "exec"), namespace)
try:
    response = namespace["execute"](json.loads(base64.b64decode({payload!r})))
    code = 0
except (RuntimeError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
    response = {{"failed": True, "error": str(exc)}}
    code = 2
print(json.dumps({{"engine_exit": code, "response": response}}))
"""
    try:
        result = runner(memory_script(program), [], timeout)
    except RemoteCommandError:
        raise TransportError("inspect: no result (ssh failed or timed out)") from None
    if not result.ok:
        raise _failure("inspect", result)
    try:
        found = json.loads(result.stdout)
        code, response = found["engine_exit"], found["response"]
        if not isinstance(code, int) or not isinstance(response, dict):
            raise ValueError
    except (ValueError, TypeError, KeyError):
        raise TransportError("inspect: unusable result") from None
    return EngineRun(code, response)


def retention_host(
    runner: Runner,
    policy: Mapping[str, Any],
    *,
    keep_minimal: int,
    keep_full: int,
    apply: bool = False,
    timeout: float = 900,
) -> EngineRun:
    """The local rollback set and what retention keeps and removes (:mod:`.retention`).

    Without ``apply`` a read-only listing: no lock, nothing written on the host but the
    private directory the script removes again. With ``apply`` it removes what the listing
    says, under the transaction lock and only for a ``clear`` host record. The program's
    own refusals come back as its exit code (2) and ``error``.
    """

    request = _request_bytes(
        {
            "action": "retention",
            "policy": dict(policy),
            "keep_minimal": keep_minimal,
            "keep_full": keep_full,
            "apply": apply,
        }
    )
    files = {"engine.py": ENGINE, "retention.py": RETENTION, "request.json": request}
    found = _call(runner, "retention", 'retention "$dir"', [], timeout, files)
    code, response = found.get("engine_exit"), found.get("response")
    if not isinstance(code, int) or not isinstance(response, dict):
        raise TransportError("retention: unusable result")
    return EngineRun(code, response)
