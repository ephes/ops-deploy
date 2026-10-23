"""Detached Traefik transactions on a Linux host: stage, launch, run, safe-restore, poll and clean up.

The host side of :mod:`ops_deploy.infra.traefik_tx.transport`. Like the engine it runs as
root, with the standard library only, under ``/usr/bin/python3 -I`` 3.11 or newer. The
controller sends it with every step (a private ``mktemp -d`` directory that the step's
script removes again); ``stage`` copies it, the engine and the request into the
transaction's transport directory, from where the transient unit and the safe-restore
unit run it. Subcommands, each printing one JSON object (exit 0) or
``traefik tx: <reason>`` on stderr (exit 1):

``stage ID SOURCE``
    Copy ``engine.py``, ``runner.py`` and ``request.json`` (``binary``, ``resume`` or
    ``rebaseline``) from SOURCE into ``/var/lib/traefik-transport/ID`` (root, ``0700``); for
    ``binary`` fetch the exact
    release archive from GitHub and check its SHA256; install the safe-restore unit
    template; write ``staged.json`` (the files' SHA256) last.
``start ID SECONDS``
    Launch ``traefik-tx-ID.service`` with ``systemd-run``: ``RuntimeMaxSec=SECONDS``,
    ``--collect``, ``OnFailure=traefik-tx-safe-restore@ID.service``. Returns once the
    unit runs; the transaction no longer depends on the session that started it.
``run ID``
    The unit's program: ``started.json``, the engine on the staged request, ``result.json``.
    It fails the unit (so ``OnFailure=`` starts the safe-restore unit) when the engine
    gave no usable result or the host record is left ``pending``; a stop or timeout fails
    it too.
``safe-restore ID``
    The ``OnFailure=`` unit's program. It acts only when the host record is ``pending``
    for a binary transaction of this very transport (the transaction directory holds
    this request and the record names its controller record as the previous one), the
    transaction directory has the ``original`` binary, and the installed or the running
    binary differs from it: then it puts ``original`` back, restarts Traefik, waits for
    the pre-transaction identity and runs the baseline and cleanup probes, like the
    engine's own rollback. It records ``recovery``, or ``degraded`` when any of that
    fails; never ``clear``. Otherwise it changes nothing. ``safe-restore.json`` says what
    it did.
``poll ID``
    Read-only: the transaction's status (below) with ``result.json`` and
    ``safe-restore.json``, from marker files that did not change while systemd was asked
    about the units.
``cleanup ID``
    Remove the transport directory under the transaction's lock (which ``run`` and
    ``safe-restore`` hold while they run), refused while the transaction is ``running`` or
    ``restoring``.
``inspect SOURCE``
    Read-only, in the foreground: the engine's ``inspect`` on SOURCE's request.

Statuses: ``absent`` (no transport directory), ``incomplete`` (staging did not finish),
``staged`` (never started), ``running``, ``restoring`` (the safe-restore unit runs or is
due), ``finished`` (the engine's result is final), ``interrupted`` (the engine gave no
result; ``safe-restore.json`` says what the safe-restore unit did, if it ran).
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import http.client
import importlib.util
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path
from types import FrameType
from typing import Any, NoReturn, Protocol, cast

PYTHON = "/usr/bin/python3"
ROOT_UID = 0
TRANSPORT_ROOT = Path("/var/lib/traefik-transport")
# Runtime units: gone after a reboot, like every transaction unit.
UNIT_DIR = Path("/run/systemd/system")
SAFE_RESTORE_TEMPLATE = "traefik-tx-safe-restore@.service"
SAFE_RESTORE_TIMEOUT = 600
RUNTIME_MAX = (60, 3600)
RELEASE_URL = "https://github.com/traefik/traefik/releases/download/v{version}/traefik_v{version}_linux_{arch}.tar.gz"
ARCHITECTURES = {"x86_64": "amd64", "aarch64": "arm64"}
MAX_ARCHIVE = 256 * 1024 * 1024
MAX_JSON = 4 * 1024 * 1024
STAGED_ACTIONS = ("binary", "resume", "rebaseline")
ACTIVE = frozenset({"active", "activating", "deactivating", "reloading", "refreshing"})
TRANSACTION_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")

ENGINE, RUNNER, REQUEST, ARCHIVE = "engine.py", "runner.py", "request.json", "release.tar.gz"
STAGED, STARTED, RESULT = "staged.json", "started.json", "result.json"
RESTORE_STARTED, RESTORED, ENGINE_STDERR = "restore-started.json", "safe-restore.json", "engine.stderr"

TEMPLATE = """\
# Written by ops-deploy's Traefik transaction transport. Started as OnFailure= of
# traefik-tx-%i.service: puts the original Traefik binary back after an interrupted
# transaction and records recovery (or degraded), never clear.
[Unit]
Description=Traefik transaction %i safe-restore
CollectMode=inactive-or-failed

[Service]
Type=oneshot
UMask=0077
SyslogIdentifier=traefik-tx
ExecStart={python} -I {root}/%i/runner.py safe-restore %i
TimeoutStartSec={timeout}
"""


class Refused(RuntimeError):
    """A step was refused or failed; the message is a fixed reason without host data."""


class Engine(Protocol):
    """What the safe-restore unit and the runner use of the engine module next to them."""

    @property
    def STATE_ROOT(self) -> Path: ...

    @property
    def LOCK(self) -> Path: ...

    def digest(self, path: Path) -> str: ...

    def atomic(self, path: Path, data: bytes, mode: int = ...) -> None: ...

    def save(self, path: Path, value: Any) -> None: ...

    def trusted_file(self, path: Path) -> None: ...

    def load_state(self, path: Path) -> dict[str, Any] | None: ...

    def validate_policy(self, policy: dict[str, Any]) -> None: ...

    def main_pid(self) -> int: ...

    def identity(self, policy: dict[str, Any]) -> dict[str, Any]: ...

    def check_probe(self, spec: dict[str, Any]) -> None: ...

    def restart_verify(
        self, policy: dict[str, Any], expected: dict[str, Any], probe: dict[str, Any], cleanup: dict[str, Any]
    ) -> dict[str, Any]: ...

    def state_for(self, policy: dict[str, Any], phase: str, live: dict[str, Any], **fields: Any) -> dict[str, Any]: ...


def require(ok: object, message: str) -> None:
    if not ok:
        raise Refused(message)


def fail(message: str) -> NoReturn:
    raise Refused(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_sha256(path: Path) -> str | None:
    try:
        with path.open("rb") as stream:
            return hashlib.file_digest(stream, "sha256").hexdigest()
    except OSError:
        return None


def command(argv: list[str], *, timeout: float | None = 60, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False, cwd="/")
    if check and result.returncode:
        fail(f"command failed: {Path(argv[0]).name} (exit {result.returncode})")
    return result


def require_root() -> None:
    require(os.geteuid() == 0, "root is required")


def private_dir(path: Path, *, parents: bool = True) -> None:
    """``path`` is a real root-owned directory nobody else can enter.

    With ``parents`` its parents must be root-owned and writable by nobody else, too;
    the controller's ``mktemp -d`` directory sits in the sticky ``/tmp`` instead.
    """

    info = path.lstat()
    require(
        stat.S_ISDIR(info.st_mode) and info.st_uid == ROOT_UID and not info.st_mode & 0o077,
        f"not a private root-owned directory: {path}",
    )
    for parent in path.parents if parents else ():
        info = parent.stat()
        require(info.st_uid == ROOT_UID and not info.st_mode & 0o022, f"unsafe parent: {parent}")


def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    """Replace ``path`` with ``data`` through a synced temporary file in the same directory."""

    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            os.fchmod(stream.fileno(), mode)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def write_json(path: Path, value: Any) -> None:
    atomic_write(path, (json.dumps(value, sort_keys=True, indent=2) + "\n").encode())


def read_json(path: Path) -> Any:
    """The JSON in the regular file ``path``, or ``None`` when there is none."""

    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    require(stat.S_ISREG(info.st_mode) and info.st_size <= MAX_JSON, f"not a regular file: {path.name}")
    return json.loads(path.read_bytes())


def check_id(value: str) -> str:
    require(TRANSACTION_ID.fullmatch(value), "invalid transaction id")
    return value


def main_unit(transaction_id: str) -> str:
    return f"traefik-tx-{transaction_id}.service"


def restore_unit(transaction_id: str) -> str:
    return f"traefik-tx-safe-restore@{transaction_id}.service"


def unit_state(unit: str) -> tuple[str, str]:
    """``(LoadState, ActiveState)``; an unknown unit is ``("not-found", "inactive")``."""

    out = command(["systemctl", "show", unit, "-p", "LoadState", "-p", "ActiveState"]).stdout
    values = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
    return values.get("LoadState", ""), values.get("ActiveState", "")


def transport_dir(transaction_id: str) -> Path:
    directory = TRANSPORT_ROOT / check_id(transaction_id)
    try:
        private_dir(directory)
    except FileNotFoundError:
        fail("transaction is not staged")
    return directory


def lock_transport(directory: Path, wait: float) -> int:
    """Take the transaction's own lock, an exclusive ``flock`` on its directory; the descriptor holds it.

    The unit programs hold it while they run, so cleanup never removes a directory one of
    them uses, and a program that gets it only after a cleanup finds the directory gone.
    Waits up to ``wait`` seconds.
    """

    try:
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except FileNotFoundError:
        fail("transaction is not staged")
    deadline = time.monotonic() + wait
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            break
        except BlockingIOError:
            if time.monotonic() >= deadline:
                os.close(fd)
                fail("transaction is busy")
            time.sleep(0.1)
    try:
        current: os.stat_result | None = os.lstat(directory)
    except FileNotFoundError:
        current = None
    if current is None or not os.path.samestat(os.fstat(fd), current):
        os.close(fd)
        fail("transaction is not staged")
    return fd


def load_engine(path: Path) -> Engine:
    """The engine module from ``path`` itself, never from the import path."""

    spec = importlib.util.spec_from_file_location("traefik_tx_engine", path)
    if spec is None or spec.loader is None:
        fail("cannot load the engine")
    module = importlib.util.module_from_spec(spec)
    # No __pycache__ next to the staged engine.
    previous, sys.dont_write_bytecode = sys.dont_write_bytecode, True
    try:
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return cast(Engine, module)


def install_template() -> bool:
    """Write the safe-restore unit template and reload systemd when it is missing or differs."""

    require(UNIT_DIR.is_dir(), "systemd is required")
    path = UNIT_DIR / SAFE_RESTORE_TEMPLATE
    text = TEMPLATE.format(python=PYTHON, root=TRANSPORT_ROOT, timeout=SAFE_RESTORE_TIMEOUT).encode()
    try:
        info = path.lstat()
        if stat.S_ISREG(info.st_mode) and info.st_uid == ROOT_UID and path.read_bytes() == text:
            return False
    except FileNotFoundError:
        pass
    atomic_write(path, text, 0o644)
    command(["systemctl", "daemon-reload"], timeout=120)
    return True


def open_url(url: str) -> Any:
    return urllib.request.urlopen(url, timeout=60)


def fetch_release(release: object, destination: Path) -> str:
    """Download the release archive to ``destination``; it must have exactly the approved SHA256."""

    if not isinstance(release, dict):
        fail("binary transactions need a release")
    version, arch, checksum = release.get("version"), release.get("arch"), release.get("sha256")
    require(isinstance(version, str) and re.fullmatch(r"3\.\d+\.\d+", version), "unsupported release")
    require(isinstance(checksum, str) and re.fullmatch(r"[0-9a-f]{64}", checksum), "exact SHA256 is required")
    require(arch == ARCHITECTURES.get(os.uname().machine), "release architecture is not the host's")
    url = RELEASE_URL.format(version=version, arch=arch)
    partial = destination.with_name(f".{destination.name}.part")
    hasher, size = hashlib.sha256(), 0
    try:
        with open_url(url) as response, partial.open("xb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            require(str(response.geturl()).startswith("https://"), "release download left HTTPS")
            while chunk := response.read(1 << 20):
                size += len(chunk)
                require(size <= MAX_ARCHIVE, "release archive too large")
                hasher.update(chunk)
                stream.write(chunk)
            stream.flush()
            os.fsync(stream.fileno())
    except Refused:
        partial.unlink(missing_ok=True)
        raise
    except (OSError, ValueError, http.client.HTTPException) as exc:
        partial.unlink(missing_ok=True)
        raise Refused(f"release download failed ({type(exc).__name__})") from None
    if hasher.hexdigest() != checksum:
        partial.unlink()
        fail("release archive checksum mismatch")
    os.replace(partial, destination)
    return hasher.hexdigest()


def stage(transaction_id: str, source: Path) -> dict[str, Any]:
    require_root()
    check_id(transaction_id)
    private_dir(source, parents=False)
    request = read_json(source / REQUEST)
    require(isinstance(request, dict), "invalid request")
    action = request.get("action")
    require(action in STAGED_ACTIONS, "only binary, resume and rebaseline transactions run detached")
    engine, runner = (source / ENGINE).read_bytes(), (source / RUNNER).read_bytes()
    TRANSPORT_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    private_dir(TRANSPORT_ROOT)
    directory = TRANSPORT_ROOT / transaction_id
    try:
        directory.mkdir(mode=0o700)
    except FileExistsError:
        fail("transaction id is already staged")
    try:
        atomic_write(directory / ENGINE, engine)
        atomic_write(directory / RUNNER, runner)
        archive = None
        if action == "binary":
            # As the Ansible transport does: the engine reads the archive the transport fetched.
            request["archive_path"] = str(directory / ARCHIVE)
            archive = fetch_release(request.get("release"), directory / ARCHIVE)
        else:
            request.pop("archive_path", None)
        data = (json.dumps(request, sort_keys=True, indent=2) + "\n").encode()
        atomic_write(directory / REQUEST, data)
        install_template()
        staged = {
            "schema": 1,
            "id": transaction_id,
            "action": action,
            "engine_sha256": sha256(engine),
            "runner_sha256": sha256(runner),
            "request_sha256": sha256(data),
            "archive_sha256": archive,
            "staged_at": int(time.time()),
        }
        write_json(directory / STAGED, staged)
    except BaseException:
        shutil.rmtree(directory, ignore_errors=True)
        raise
    return staged


def verify_staged(directory: Path) -> dict[str, Any]:
    """``staged.json``, with every staged file still at its staged SHA256."""

    staged = read_json(directory / STAGED)
    require(
        isinstance(staged, dict) and staged.get("schema") == 1 and staged.get("id") == directory.name,
        "transaction is not staged",
    )
    files = [(ENGINE, "engine_sha256"), (RUNNER, "runner_sha256"), (REQUEST, "request_sha256")]
    if staged.get("action") == "binary":
        files.append((ARCHIVE, "archive_sha256"))
    for name, key in files:
        require(file_sha256(directory / name) == staged.get(key), "staged files changed")
    return dict(staged)


def start(transaction_id: str, runtime_max: int) -> dict[str, Any]:
    require_root()
    require(RUNTIME_MAX[0] <= runtime_max <= RUNTIME_MAX[1], "unsupported RuntimeMaxSec")
    directory = transport_dir(transaction_id)
    verify_staged(directory)
    require(not (directory / STARTED).exists() and not (directory / RESULT).exists(), "transaction already started")
    unit = main_unit(transaction_id)
    require(unit_state(unit)[0] == "not-found", "transaction unit already exists")
    install_template()
    command(
        [
            "systemd-run",
            f"--unit={unit}",
            f"--description=Traefik transaction {transaction_id}",
            "--collect",
            "--quiet",
            "--no-ask-password",
            "--property=Type=exec",
            f"--property=RuntimeMaxSec={runtime_max}",
            "--property=TimeoutStopSec=30",
            "--property=KillMode=control-group",
            f"--property=OnFailure={restore_unit(transaction_id)}",
            "--property=UMask=0077",
            "--property=SyslogIdentifier=traefik-tx",
            "--",
            PYTHON,
            "-I",
            str(directory / RUNNER),
            "run",
            transaction_id,
        ],
        timeout=120,
    )
    return {"schema": 1, "id": transaction_id, "started": True, "unit": unit}


def parse_response(stdout: str) -> dict[str, Any] | None:
    """The engine's one JSON object, or ``None``."""

    try:
        value = json.loads(stdout)
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def host_phase(directory: Path) -> str:
    """The host record's phase, ``absent`` without one, ``unreadable`` when it cannot be loaded."""

    try:
        engine = load_engine(directory / ENGINE)
        state = engine.load_state(engine.STATE_ROOT / "state.json")
    except Exception:
        return "unreadable"
    return "absent" if state is None else str(state["phase"])


def _stopped(signum: int, frame: FrameType | None) -> None:
    raise SystemExit(128 + signum)


def exit_on_stop() -> None:
    """A stop or timeout of the unit (``SIGTERM``) raises ``SystemExit`` instead of ending the process.

    The transaction unit then fails, so ``OnFailure=`` starts the safe-restore unit (a
    plain ``SIGTERM`` death counts as a clean stop); in the safe-restore unit it reaches
    the rollback's handler, which records ``degraded``.
    """

    for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        signal.signal(signum, _stopped)


def run_transaction(transaction_id: str) -> int:
    """The transient unit's program; exit 1 (unit failed, safe-restore due) unless the engine finished."""

    exit_on_stop()
    require_root()
    directory = transport_dir(transaction_id)
    lock = lock_transport(directory, 60)
    try:
        return _run(transaction_id, directory)
    finally:
        os.close(lock)


def _run(transaction_id: str, directory: Path) -> int:
    require(not (directory / STARTED).exists(), "transaction already started")
    verify_staged(directory)
    # Durable before the engine starts: without it the engine never ran.
    write_json(
        directory / STARTED,
        {
            "schema": 1,
            "id": transaction_id,
            "invocation_id": os.environ.get("INVOCATION_ID"),
            "pid": os.getpid(),
            "started_at": int(time.time()),
        },
    )
    process = command(
        [PYTHON, "-I", str(directory / ENGINE), "--request", str(directory / REQUEST)], timeout=None, check=False
    )
    response = parse_response(process.stdout)
    phase = host_phase(directory)
    restore_expected = response is None or process.returncode not in (0, 1, 2) or phase in ("pending", "unreadable")
    write_json(
        directory / RESULT,
        {
            "schema": 1,
            "id": transaction_id,
            "engine_exit": process.returncode,
            "response": response,
            "host_phase": phase,
            "restore_expected": restore_expected,
            "finished_at": int(time.time()),
        },
    )
    print(json.dumps({"id": transaction_id, "engine_exit": process.returncode, "restore_expected": restore_expected}))
    with contextlib.suppress(OSError):
        atomic_write(directory / ENGINE_STDERR, process.stderr.encode()[-65536:])
    with contextlib.suppress(OSError):
        # The engine keeps the candidate in its transaction directory; the archive is not needed any more.
        (directory / ARCHIVE).unlink(missing_ok=True)
    return 1 if restore_expected else 0


def live_digests(engine: Engine, policy: dict[str, Any]) -> tuple[str | None, str | None]:
    """SHA256 of the installed and of the running Traefik binary; ``None`` when there is none."""

    installed = file_sha256(Path(policy["binary_path"]))
    running = None
    try:
        pid = engine.main_pid()
        if pid > 1:
            running = engine.digest(Path(f"/proc/{pid}/exe"))
    except Exception:
        running = None
    return installed, running


def own_transaction(
    engine: Engine, transaction: Path, directory: Path, request: dict[str, Any], state: dict[str, Any]
) -> bool:
    """The pending record belongs to this transport's run: its transaction holds this very request."""

    try:
        if transaction.parent != engine.STATE_ROOT or transaction.is_symlink() or not transaction.is_dir():
            return False
        saved = json.loads((transaction / REQUEST).read_bytes())
    except (OSError, ValueError):
        return False
    supplied = request.get("controller_state")
    return (
        saved == request
        and request.get("archive_path") == str(directory / ARCHIVE)
        and isinstance(supplied, dict)
        and state.get("previous_revision") == supplied.get("revision")
    )


def skipped(reason: str) -> dict[str, Any]:
    return {"acted": False, "reason": reason, "phase": None, "state": None}


def restore(engine: Engine, directory: Path, request: Any, transaction_id: str) -> dict[str, Any]:
    """The safe-restore decision and, when it applies, the restore itself (see the module docstring)."""

    if not isinstance(request, dict) or request.get("action") != "binary":
        return skipped("not_binary")
    policy = request["policy"]
    engine.validate_policy(policy)
    state_path = engine.STATE_ROOT / "state.json"
    with engine.LOCK.open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return skipped("lock_held")
        state = engine.load_state(state_path)
        if state is None:
            return skipped("no_record")
        if state["phase"] != "pending" or state.get("operation") != "binary":
            return skipped("not_pending")
        transaction = Path(str(state.get("transaction")))
        if not own_transaction(engine, transaction, directory, request, state):
            return skipped("not_this_transaction")
        original = transaction / "original"
        try:
            engine.trusted_file(original)
            expected = engine.digest(original)
        except Exception:
            return skipped("no_original")
        installed, running = live_digests(engine, policy)
        if installed == expected and running == expected:
            return skipped("binary_unchanged")
        mode = stat.S_IMODE(original.stat().st_mode)
        recovery = engine.state_for(
            policy,
            "recovery",
            state["identity"],
            owner=state.get("owner"),
            transaction=str(transaction),
            reason="EngineInterrupted",
            review_due=0,
            safe_restore=transaction_id,
        )
        # The engine's own recovery record is due for review an hour after it was written.
        recovery["review_due"] = recovery["updated_at"] + 3600
        try:
            # The engine's rollback order: cleanup probe, original back, restart, baseline and cleanup probes.
            cleanup_failure: BaseException | None = None
            try:
                engine.check_probe(request["cleanup_probe"])
            except BaseException as exc:
                cleanup_failure = exc
            if installed != expected:
                engine.atomic(Path(policy["binary_path"]), original.read_bytes(), mode)
            engine.restart_verify(policy, state["identity"], request["baseline_probe"], request["cleanup_probe"])
            if cleanup_failure is not None:
                raise cleanup_failure
            recovery["identity"] = engine.identity(policy)
        except BaseException as failure:
            recovery["phase"] = "degraded"
            recovery["recovery_error"] = type(failure).__name__
        try:
            engine.save(state_path, recovery)
        except OSError:
            return {"acted": True, "reason": "record_not_saved", "phase": None, "state": None}
        reason = "restored" if recovery["phase"] == "recovery" else "restore_failed"
        return {"acted": True, "reason": reason, "phase": recovery["phase"], "state": recovery}


def safe_restore(transaction_id: str) -> dict[str, Any]:
    """The ``OnFailure=`` unit's program: :func:`restore`, recorded in ``safe-restore.json``."""

    exit_on_stop()
    require_root()
    directory = transport_dir(transaction_id)
    lock = lock_transport(directory, 60)
    try:
        begun = {"schema": 1, "id": transaction_id, "invocation_id": os.environ.get("INVOCATION_ID")}
        write_json(directory / RESTORE_STARTED, {**begun, "started_at": int(time.time())})
        try:
            engine = load_engine(directory / ENGINE)
            outcome = restore(engine, directory, read_json(directory / REQUEST), transaction_id)
        except Exception as exc:
            # Raised before anything was changed: every failure after a change is caught in restore().
            outcome = {**skipped("error"), "error": type(exc).__name__}
        result = {"schema": 1, "id": transaction_id, **outcome, "finished_at": int(time.time())}
        write_json(directory / RESTORED, result)
        return result
    finally:
        os.close(lock)


def classify(
    present: bool,
    main: str,
    restoring: tuple[str, str],
    staged: bool,
    started: bool,
    result: Any,
    restore_started: bool,
    restored: bool,
) -> str:
    """The status from the units' states and the files present (see the module docstring)."""

    if not present:
        return "absent"
    if main in ACTIVE:
        return "running"
    if restoring[1] in ACTIVE:
        return "restoring"
    if isinstance(result, dict) and result.get("restore_expected") is False:
        return "finished"
    if restored:
        return "finished" if isinstance(result, dict) else "interrupted"
    if restore_started:
        # The safe-restore unit ended without an outcome: the host state is unknown.
        return "interrupted"
    if started:
        # Waiting for OnFailure= to start the safe-restore unit, unless there is none to start.
        return "interrupted" if restoring[0] == "not-found" else "restoring"
    return "staged" if staged else "incomplete"


def markers(directory: Path) -> tuple[bool, bool, Any, bool, Any]:
    """``staged``, ``started``, ``result.json``, ``restore-started``, ``safe-restore.json``."""

    return (
        (directory / STAGED).exists(),
        (directory / STARTED).exists(),
        read_json(directory / RESULT),
        (directory / RESTORE_STARTED).exists(),
        read_json(directory / RESTORED),
    )


def poll(transaction_id: str) -> dict[str, Any]:
    directory = TRANSPORT_ROOT / check_id(transaction_id)
    if not os.path.lexists(directory):
        return {
            "schema": 1,
            "id": transaction_id,
            "status": "absent",
            "staged": False,
            "started": False,
            "result": None,
            "safe_restore": None,
        }
    private_dir(directory)
    # A status only from markers that did not change while systemd was asked about the units:
    # otherwise a unit that starts, writes a marker or ends in between is missed.
    status = "running"
    for _ in range(5):
        seen = markers(directory)
        main = unit_state(main_unit(transaction_id))[1]
        restoring = unit_state(restore_unit(transaction_id))
        now = markers(directory)
        if now == seen:
            staged, started, result, restore_started, restored = now
            status = classify(True, main, restoring, staged, started, result, restore_started, restored is not None)
            break
    # Otherwise the transaction moved on during every look: it is still in progress.
    staged, started, result, _, restored = now
    return {
        "schema": 1,
        "id": transaction_id,
        "status": status,
        "staged": staged,
        "started": started,
        "result": result,
        "safe_restore": restored,
    }


def cleanup(transaction_id: str) -> dict[str, Any]:
    require_root()
    directory = TRANSPORT_ROOT / check_id(transaction_id)
    if not os.path.lexists(directory):
        return {"schema": 1, "id": transaction_id, "removed": False}
    private_dir(directory)
    lock = lock_transport(directory, 0)
    try:
        status = poll(transaction_id)["status"]
        require(status not in ("running", "restoring"), "transaction is still running or restoring")
        shutil.rmtree(directory)
    finally:
        os.close(lock)
    return {"schema": 1, "id": transaction_id, "removed": True}


def inspect(source: Path) -> dict[str, Any]:
    private_dir(source, parents=False)
    request = read_json(source / REQUEST)
    require(isinstance(request, dict) and request.get("action") == "inspect", "only inspect runs in the foreground")
    process = command(
        [PYTHON, "-I", str(source / ENGINE), "--request", str(source / REQUEST)], timeout=300, check=False
    )
    response = parse_response(process.stdout)
    require(response is not None, "the engine gave no result")
    return {"schema": 1, "engine_exit": process.returncode, "response": response}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Detached Traefik transactions (host side).")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("run", "safe-restore", "poll", "cleanup"):
        commands.add_parser(name).add_argument("id")
    staging = commands.add_parser("stage")
    staging.add_argument("id")
    staging.add_argument("source", type=Path)
    starting = commands.add_parser("start")
    starting.add_argument("id")
    starting.add_argument("seconds", type=int)
    commands.add_parser("inspect").add_argument("source", type=Path)
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        if args.command == "run":
            return run_transaction(args.id)
        if args.command == "stage":
            result = stage(args.id, args.source)
        elif args.command == "start":
            result = start(args.id, args.seconds)
        elif args.command == "safe-restore":
            result = safe_restore(args.id)
        elif args.command == "poll":
            result = poll(args.id)
        elif args.command == "cleanup":
            result = cleanup(args.id)
        else:
            result = inspect(args.source)
    except Refused as exc:
        print(f"traefik tx: {exc}", file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print(f"traefik tx: unexpected error ({type(exc).__name__})", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
