#!/usr/bin/env python3
"""Process-level parity of software_live.py and the Rust software-live (PLAN.md 6.2).

Runs the Python program (the oracle, ``roles/software_live/files/
software_live.py``, under the image's ``python3`` with python-apt) and the
Rust binary on identical inputs and compares what they produce. Sections
(``--section``, default all):

``validate``
    the policy matrix of ``fixtures/policy.json`` (valid, every invalid rule,
    extra keys, non-ASCII) through ``validate --config``: equal exit codes;
    a ``p3`` case is accepted by Python and refused by Rust (PLAN.md 4.2).
``config``
    the ``serve`` start-up matrix of ``fixtures/serve.json`` ``config``:
    both serve or both exit 1 (``startup-config`` and ``unicode-digits``:
    Python serves, Rust exits 1; 4.2 items 14 and 11).
``endpoint``
    Python ``serve`` and Rust ``serve`` on loopback with the same
    ``htpasswd`` (made with ``htpasswd -niB``, checked by the real
    ``htpasswd -vi`` on the Python side) and state file; every raw request
    of ``fixtures/serve.json`` ``requests`` (paths, query strings, missing,
    malformed and wrong credentials, ``\\n`` in the password, long headers;
    valid, stale, future and malformed states) plus the head limits: equal
    status codes, equal JSON bodies except ``meta.age_seconds`` (P2), the
    contract headers; the P3 items 2 and 4 cases as the fixture records them.
``export``
    ``export-inventory`` on the source files of ``fixtures/export.json``
    (every projection and rejection, unsafe modes and owners, symlinks, hard
    links, FIFO, oversized, missing group) with real root ownership: equal
    exit codes and failure classes, identical projections, mode 0640 and
    group, the prior file kept on failure.
``collect``
    the container cases: the world of ``parity/world.py`` (fake Traefik and
    PostgreSQL processes, shims, the upstream servers over HTTPS with the
    system trust store) on the real APT lists and the fake repositories of
    ``software-live-apt/container/setup-world.sh``. Both programs collect the
    same policies (the scenarios of ``section_collect`` and every valid policy of
    ``fixtures/policy.json``, which also compares ``policy_sha256``) and the
    reports are compared under P1/P2 (``compare.py``;
    ``apt.pending_security_updates`` must be identical). Then the cache
    cross-reads (each program on the other's caches: fresh, stale with the
    upstream down, invalid), the state cross-reads (each ``serve`` on the
    other's state file), ``export-inventory`` of both states by both programs
    and the software_estate reader on the Rust projections.

Runs as root in a throwaway ``ubuntu:24.04`` or ``debian:13`` container
only (``parity/container-run.sh``; ``just rs-software-live-parity`` runs it
in Docker; CI runs it in the ``software-live-apt`` job). The Rust binary's
directory must hold ``software-live-apt`` (root-owned, as on the hosts).
Exit 0 when every check passed, 1 otherwise. Nothing is skipped.
"""

from __future__ import annotations

import argparse
import ast
import base64
import grp
import importlib.util
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

PARITY = Path(__file__).resolve().parent
CRATE = PARITY.parent
FIXTURES = CRATE / "fixtures"
REPO = CRATE.parents[1]
PROGRAM = REPO / "roles" / "software_live" / "files" / "software_live.py"
READER = REPO / "roles" / "software_estate" / "files" / "collect.py"
sys.path.insert(0, str(PARITY))

import compare  # noqa: E402
import world as world_module  # noqa: E402

SECTIONS = ("validate", "config", "endpoint", "export", "collect")
GROUP = "nogroup"  # exists in both images (gid 65534)
OTHER_UID = 65534
SHIFT_WINDOW = 20 * 365 * 86400
EPOCH_TOKEN = re.compile(
    rb'("generated_at_epoch"\s*:\s*)(-?[0-9]+(?:\.[0-9]+)?(?:[eE][-+]?[0-9]+)?)'
)
JSON_STATUSES = {200, 401, 404, 503}
USAGE = re.compile(r"^software-live: usage .*$", re.MULTILINE)


# --------------------------------------------------------------------------
# results


class Results:
    def __init__(self, verbose: bool) -> None:
        self.verbose = verbose
        self.passed = 0
        self.failures: list[str] = []
        self.allowed: dict[str, int] = {}
        self.notes: list[str] = []

    def check(self, name: str, problems: list[str], allowed: str | None = None) -> None:
        if problems:
            for problem in problems:
                self.failures.append(f"{name}: {problem}")
                print(f"FAIL {name}: {problem}", flush=True)
            return
        self.passed += 1
        if allowed:
            self.allowed[allowed] = self.allowed.get(allowed, 0) + 1
        if self.verbose:
            print(f"ok   {name}{f' ({allowed})' if allowed else ''}", flush=True)

    def note(self, text: str) -> None:
        self.notes.append(text)
        print(f"note {text}", flush=True)


# --------------------------------------------------------------------------
# processes


@dataclass
class Run:
    code: int
    stdout: bytes
    stderr: bytes
    maxrss_kib: int = 0

    def json(self) -> Any:
        return json.loads(self.stdout)

    def last_line(self) -> str:
        lines = self.stderr.decode("utf-8", "replace").strip().splitlines()
        return lines[-1] if lines else ""


def run(argv: list[str], env: dict[str, str], timeout: float = 300.0) -> Run:
    """Run to completion; the child's own rusage comes from wait4."""
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        process = subprocess.Popen(  # noqa: S603 - the programs under test
            argv, stdin=subprocess.DEVNULL, stdout=out, stderr=err, env=env
        )
        timer = threading.Timer(timeout, process.kill)
        timer.start()
        try:
            _, status, usage = os.wait4(process.pid, 0)
        finally:
            timer.cancel()
        process.returncode = os.waitstatus_to_exitcode(status)
        out.seek(0)
        err.seek(0)
        return Run(process.returncode, out.read(), err.read(), usage.ru_maxrss)


@dataclass
class Context:
    binary: Path
    python: str
    program: Path
    work: Path
    results: Results
    env: dict[str, str]
    world: world_module.World | None = None
    usage: list[str] = field(default_factory=list)
    own: frozenset[str] = frozenset()

    def py(self, *args: str) -> list[str]:
        return [self.python, str(self.program), *args]

    def rs(self, *args: str) -> list[str]:
        return [str(self.binary), *args]

    def both(self, *args: str, env: dict[str, str] | None = None) -> tuple[Run, Run]:
        environment = env or self.env
        return run(self.py(*args), environment), run(self.rs(*args), environment)

    def dir(self, *parts: str) -> Path:
        path = self.work.joinpath(*parts)
        path.mkdir(parents=True, exist_ok=True)
        return path


def own_messages(program: Path) -> frozenset[str]:
    """Every literal message of a ``raise X("...")`` in the Python program."""
    messages = set()
    for node in ast.walk(ast.parse(program.read_text(encoding="utf-8"))):
        if (
            isinstance(node, ast.Raise)
            and isinstance(node.exc, ast.Call)
            and node.exc.args
            and isinstance(node.exc.args[0], ast.Constant)
            and isinstance(node.exc.args[0].value, str)
        ):
            messages.add(node.exc.args[0].value)
    return frozenset(messages)


def load_fixture(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def write_bytes(path: Path, data: bytes, mode: int = 0o640) -> Path:
    path.write_bytes(data)
    path.chmod(mode)
    return path


def text_bytes(text: str) -> bytes:
    return text.encode("utf-8", "surrogatepass")


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def connectable(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.2):
            return True
    except OSError:
        return False


def stop(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.kill()
    process.wait(timeout=10)


# --------------------------------------------------------------------------
# validate


def section_validate(ctx: Context) -> None:
    folder = ctx.dir("validate")
    for case in load_fixture("policy.json"):
        path = write_bytes(folder / f"{case['id']}.json", text_bytes(case["text"]))
        python, rust = ctx.both("validate", "--config", str(path))
        expected_python = 0 if "policy_sha256" in case else 1
        expected_rust = 1 if case.get("p3") else expected_python
        problems = []
        if python.code != expected_python:
            problems.append(
                f"Python exit {python.code}, the fixture says {expected_python}"
            )
        if rust.code != expected_rust:
            problems.append(
                f"Rust exit {rust.code}, expected {expected_rust}: {rust.last_line()}"
            )
        if rust.stdout or python.stdout:
            problems.append("validate printed to stdout")
        ctx.results.check(f"validate {case['id']}", problems, case.get("p3"))


# --------------------------------------------------------------------------
# serve: start-up configuration


def listening_sockets(pid: int) -> set[tuple[str, int]]:
    """The IPv4 TCP sockets of a process in LISTEN state (``/proc``)."""
    inodes = set()
    try:
        for fd in Path(f"/proc/{pid}/fd").iterdir():
            try:
                target = os.readlink(fd)
            except OSError:
                continue
            if target.startswith("socket:["):
                inodes.add(target[len("socket:[") : -1])
    except OSError:
        return set()
    found = set()
    for line in Path("/proc/net/tcp").read_text(encoding="ascii").splitlines()[1:]:
        fields = line.split()
        if fields[3] != "0A" or fields[9] not in inodes:
            continue
        address, port = fields[1].split(":")
        octets = bytes.fromhex(address)[::-1]
        found.add((".".join(str(octet) for octet in octets), int(port, 16)))
    return found


def start_outcome(
    argv: list[str], env: dict[str, str], address: list[Any] | None
) -> str:
    """``serving``, ``exit <code>`` or ``no listener`` for a ``serve`` start.

    ``serving`` needs a listening socket of the process on the configured
    address (any port for port 0); a connection would not do, as nothing can
    connect to 127.255.255.255."""
    process = subprocess.Popen(  # noqa: S603 - the programs under test
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
    )
    try:
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            code = process.poll()
            if code is not None:
                return f"exit {code}"
            for host, port in listening_sockets(process.pid):
                if address is None or (
                    host == address[0] and (port == address[1] or not address[1])
                ):
                    return "serving"
            time.sleep(0.02)
        return "no listener"
    finally:
        stop(process)


def section_config(ctx: Context) -> None:
    folder = ctx.dir("config")
    fixture = load_fixture("serve.json")
    write_htpasswd(folder / "htpasswd", fixture["constants"])
    for case in fixture["config"]:
        text = case["config"].replace("{dir}", str(folder))
        path = write_bytes(folder / f"{case['id']}.json", text_bytes(text))
        python = start_outcome(
            ctx.py("serve", "--config", str(path)), ctx.env, case["address"]
        )
        rust = start_outcome(
            ctx.rs("serve", "--config", str(path)), ctx.env, case["address"]
        )
        # Python serves when its start-up checks pass; an address the
        # container does not have (Tailscale) fails at bind() in both.
        problems = []
        # A process that neither exits nor listens is a failure on either
        # side, also when both do it.
        for side, outcome in (("Python", python), ("Rust", rust)):
            if outcome == "no listener":
                problems.append(f"{side} runs but does not listen")
        if case["error"] is not None and python != "exit 1":
            problems.append(
                f"Python {python}, the fixture says {case['error']['class']}"
            )
        expected_rust = "exit 1" if case.get("p3") else python
        if case.get("p3") and python != "serving":
            problems.append(f"Python {python}, the fixture says it serves")
        if rust != expected_rust:
            problems.append(f"Rust {rust}, expected {expected_rust}")
        ctx.results.check(f"config {case['id']}", problems, case.get("p3"))


# --------------------------------------------------------------------------
# serve: requests


def write_htpasswd(path: Path, constants: dict[str, Any]) -> None:
    result = subprocess.run(  # noqa: S603 - apache2-utils, as the role does
        ["htpasswd", "-niB", constants["user"]],
        input=constants["password"].encode(),
        capture_output=True,
        check=True,
    )
    write_bytes(path, result.stdout)


def endpoint_config(
    folder: Path, name: str, port: int, constants: dict[str, Any], state: Path
) -> Path:
    config = {
        "auth_user": constants["user"],
        "bind": "127.0.0.1",
        "htpasswd": str(folder / "htpasswd"),
        "path": constants["path"],
        "port": port,
        "state": str(state),
    }
    return write_bytes(folder / f"endpoint-{name}.json", json.dumps(config).encode())


class Servers:
    """Python serve and Rust serve with the same configuration but the port."""

    def __init__(
        self, ctx: Context, folder: Path, constants: dict[str, Any], state: Path
    ) -> None:
        self.ports: dict[str, int] = {}
        self.processes: dict[str, subprocess.Popen[bytes]] = {}
        for name, command in (("python", ctx.py), ("rust", ctx.rs)):
            port = free_port()
            config = endpoint_config(folder, name, port, constants, state)
            self.ports[name] = port
            self.processes[
                name
            ] = subprocess.Popen(  # noqa: S603 - the programs under test
                command("serve", "--config", str(config)),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=ctx.env,
            )
        for name, port in self.ports.items():
            deadline = time.monotonic() + 15
            while not connectable("127.0.0.1", port):
                if (
                    self.processes[name].poll() is not None
                    or time.monotonic() > deadline
                ):
                    raise RuntimeError(f"{name} serve did not start")
                time.sleep(0.02)

    def close(self) -> dict[str, bytes]:
        """Stop both; return what each wrote (nothing is expected: no request logging)."""
        written = {}
        for name, process in self.processes.items():
            stop(process)
            out, err = process.communicate()
            written[name] = out + err
        return written


@dataclass
class Answer:
    status: int
    headers: dict[str, list[str]]
    body: bytes

    def header(self, name: str) -> str | None:
        values = self.headers.get(name.lower())
        return values[0] if values else None

    def document(self) -> Any:
        return json.loads(self.body)


def exchange(port: int, raw: bytes) -> Answer | None:
    data = b""
    with socket.create_connection(("127.0.0.1", port), timeout=20) as sock:
        try:
            sock.sendall(raw)
        except (BrokenPipeError, ConnectionResetError):
            pass
        while True:
            try:
                chunk = sock.recv(65536)
            except ConnectionResetError:
                break
            if not chunk:
                break
            data += chunk
    if not data:
        return None
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    status = int(lines[0].split(" ", 2)[1])
    headers: dict[str, list[str]] = {}
    for line in lines[1:]:
        name, _, value = line.partition(":")
        headers.setdefault(name.strip().lower(), []).append(value.strip())
    return Answer(status, headers, body)


Expected = int | None | tuple[int | None, ...]


def answer_problems(
    python: Answer | None,
    rust: Answer | None,
    expected_python: Expected,
    expected_rust: Expected,
) -> list[str]:
    """``None`` is no answer (closed or reset); a tuple lists the statuses allowed."""
    problems = []
    python_status = python.status if python else None
    rust_status = rust.status if rust else None
    allowed_python = (
        expected_python if isinstance(expected_python, tuple) else (expected_python,)
    )
    allowed_rust = (
        expected_rust if isinstance(expected_rust, tuple) else (expected_rust,)
    )
    if python_status not in allowed_python:
        problems.append(f"Python status {python_status}, expected {expected_python}")
    if rust_status not in allowed_rust:
        problems.append(f"Rust status {rust_status}, expected {expected_rust}")
    if rust is not None:
        # PLAN.md 4.2 item 2: HTTP/1.1, Connection: close, no Server banner.
        if rust.header("server") is not None:
            problems.append("Rust sent a Server header")
        if rust.header("connection") != "close":
            problems.append(f"Rust Connection {rust.header('connection')!r}")
        if (
            rust.status == 501
            and rust.body
            and json.loads(rust.body) != {"error": "unsupported_method"}
        ):
            problems.append(f"Rust 501 body {rust.body!r}")
    if python is None or rust is None or problems:
        return problems
    if python.status in JSON_STATUSES and python.status == rust.status:
        problems.extend(compare.differences(python.document(), rust.document()))
        for name in ("content-type", "cache-control", "www-authenticate"):
            if python.header(name) != rust.header(name):
                problems.append(
                    f"{name}: Python {python.header(name)!r}, Rust {rust.header(name)!r}"
                )
        if (rust.status == 401) != (rust.header("www-authenticate") is not None):
            problems.append("the challenge must come with 401 only")
        if int(rust.header("content-length") or -1) != len(rust.body):
            problems.append("Rust Content-Length does not match the body")
    return problems


def shift_state(data: bytes, fixture_now: float, now: float) -> bytes:
    """Move timestamps near the fixture's frozen clock to the same distance from now."""
    delta = now - fixture_now

    def replace(match: re.Match[bytes]) -> bytes:
        token = match.group(2)
        try:
            value = float(token)
        except OverflowError:
            return match.group(0)
        if abs(value - fixture_now) > SHIFT_WINDOW:
            return match.group(0)
        if re.fullmatch(rb"-?[0-9]+", token):
            shifted = str(int(token) + round(delta)).encode()
        else:
            shifted = repr(value + delta).encode()
        return match.group(1) + shifted

    return EPOCH_TOKEN.sub(replace, data)


def extra_requests(
    path: str, credential: str
) -> list[tuple[str, bytes, Expected, Expected, str | None]]:
    """Head limits (PLAN.md 4.2 item 2): id, raw, Python status, Rust status, P3 tag.

    A server that refuses a head closes with the unread rest of it, so the
    client may see the reset instead of the answer (``None``)."""
    auth = f"Authorization: Basic {credential}\r\n".encode()
    start = f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n".encode()

    def headers(count: int) -> bytes:
        # `count` header lines in all (Host and Authorization included).
        return (
            start
            + auth
            + b"".join(b"X-H%d: v\r\n" % i for i in range(count - 2))
            + b"\r\n"
        )

    refused = (431, None)
    return [
        # Python's http.client takes 99 header lines; the 100th is "Too many headers".
        ("headers_99", headers(99), 200, 200, None),
        ("headers_100", headers(100), 431, 431, None),
        # One header line beyond 64 KiB: Python "Line too long", the Rust head limit.
        (
            "header_line_over_64_kib",
            start + auth + b"X-Long: " + b"x" * 70000 + b"\r\n\r\n",
            refused,
            refused,
            None,
        ),
        # A request line beyond 64 KiB: Python 414, the Rust head limit 431.
        (
            "request_line_over_64_kib",
            f"GET {path}?{'x' * 70000} HTTP/1.1\r\nHost: 127.0.0.1\r\n".encode()
            + auth
            + b"\r\n",
            (414, None),
            refused,
            "framing",
        ),
        # Several header lines, together beyond 64 KiB, each below Python's limit.
        (
            "head_over_64_kib_in_lines",
            start
            + auth
            + b"".join(b"X-H%d: %s\r\n" % (i, b"y" * 20000) for i in range(4))
            + b"\r\n",
            200,
            refused,
            "framing",
        ),
    ]


def section_endpoint(ctx: Context) -> None:
    fixture = load_fixture("serve.json")
    constants = fixture["constants"]
    folder = ctx.dir("endpoint")
    write_htpasswd(folder / "htpasswd", constants)
    state = folder / "state.json"
    servers = Servers(ctx, folder, constants, state)
    try:
        for case in fixture["requests"]:
            if case.get("state") is not None:
                data: bytes | None = text_bytes(case["state"])
            elif case.get("state_hex") is not None:
                data = bytes.fromhex(case["state_hex"])
            else:
                data = None
            if data is None:
                state.unlink(missing_ok=True)
            else:
                write_bytes(state, shift_state(data, case["now"], time.time()))
            raw = bytes.fromhex(case["request_hex"])
            python = exchange(servers.ports["python"], raw)
            rust = exchange(servers.ports["rust"], raw)
            recorded = case["python"]["status"]
            if case.get("p3"):
                problems = answer_problems(python, rust, recorded, case["rust_status"])
            else:
                live = python.status if python else None
                problems = answer_problems(python, rust, live, live)
                if live != recorded:
                    if case["python"].get("htpasswd") is not None:
                        # The fixture replaced htpasswd by a password table;
                        # here the real `htpasswd -vi` decides (Rust follows it).
                        ctx.results.note(
                            f"endpoint {case['id']}: the real htpasswd answers {live}, "
                            f"the fixture's password table {recorded}"
                        )
                    else:
                        problems.append(
                            f"Python status {live}, the fixture recorded {recorded}"
                        )
            ctx.results.check(f"endpoint {case['id']}", problems, case.get("p3"))
        valid = fixture["requests"][0]
        write_bytes(
            state, shift_state(text_bytes(valid["state"]), valid["now"], time.time())
        )
        credential = base64.b64encode(
            f"{constants['user']}:{constants['password']}".encode()
        ).decode()
        for case_id, raw, expected_python, expected_rust, p3 in extra_requests(
            constants["path"], credential
        ):
            python = exchange(servers.ports["python"], raw)
            rust = exchange(servers.ports["rust"], raw)
            problems = answer_problems(python, rust, expected_python, expected_rust)
            ctx.results.check(f"endpoint {case_id}", problems, p3)
    finally:
        written = servers.close()
    for name, output in written.items():
        ctx.results.check(
            f"endpoint {name} logs nothing",
            [f"wrote {output[:200]!r}"] if output else [],
        )


# --------------------------------------------------------------------------
# export-inventory


@dataclass
class Export:
    run: Run
    files: list[str] | None
    document: Any = None
    mode: int | None = None
    owner: tuple[int, int] | None = None
    prior_kept: bool | None = None

    def failure_class(self) -> str | None:
        if self.run.code == 0:
            return None
        line = self.run.last_line()
        if line.startswith("inventory export failed: "):
            return line.removeprefix("inventory export failed: ")
        # A Python traceback's last line: `[module.]Class: message`.
        return line.split(":", 1)[0].rsplit(".", 1)[-1]


def export_once(command: list[str], env: dict[str, str], out: Path | None) -> Export:
    result = run(command, env)
    if out is None or not out.is_dir() or out.is_symlink():
        return Export(result, None)
    files = sorted(path.name for path in out.iterdir())
    target = out / "software-health.json"
    export = Export(result, files)
    if target.exists():
        if result.code == 0:
            info = target.stat()
            export.document = json.loads(target.read_bytes())
            export.mode = stat.S_IMODE(info.st_mode)
            export.owner = (info.st_uid, info.st_gid)
        else:
            export.prior_kept = target.read_bytes() == b"prior"
    return export


def export_problems(
    python: Export, rust: Export, p3: str | None, refused_by_both: bool = False
) -> list[str]:
    problems = []
    if p3 and refused_by_both:
        # Python refuses the value itself, Rust already the JSON (fixtures/export.json).
        if python.run.code != 1 or rust.run.code != 1:
            problems.append(
                f"P3: Python exit {python.run.code} (1 expected), Rust {rust.run.code} (1)"
            )
        if not rust.run.last_line().startswith("inventory export failed: "):
            problems.append(f"Rust stderr {rust.run.last_line()!r}")
        return problems
    if p3:
        if python.run.code != 0 or rust.run.code != 1:
            problems.append(
                f"P3: Python exit {python.run.code} (0 expected), Rust {rust.run.code} (1)"
            )
        if not rust.run.last_line().startswith("inventory export failed: "):
            problems.append(f"Rust stderr {rust.run.last_line()!r}")
        return problems
    if python.run.code != rust.run.code:
        problems.append(
            f"exit Python {python.run.code}, Rust {rust.run.code}: {rust.run.last_line()!r}"
        )
    if python.failure_class() != rust.failure_class():
        problems.append(
            f"failure Python {python.run.last_line()!r}, Rust {rust.run.last_line()!r}"
        )
    if rust.run.code and not rust.run.last_line().startswith(
        "inventory export failed: "
    ):
        problems.append(f"Rust stderr {rust.run.last_line()!r}")
    if python.files != rust.files:
        problems.append(f"export directory Python {python.files}, Rust {rust.files}")
    if python.run.code == 0 and rust.run.code == 0:
        problems.extend(compare.differences(python.document, rust.document))
        if python.mode != 0o640 or rust.mode != 0o640:
            problems.append(f"mode Python {python.mode!r}, Rust {rust.mode!r}")
        if python.owner != rust.owner or rust.owner != (0, grp.getgrnam(GROUP).gr_gid):
            problems.append(f"owner Python {python.owner}, Rust {rust.owner}")
    if python.prior_kept is False or rust.prior_kept is False:
        problems.append(
            f"prior file kept: Python {python.prior_kept}, Rust {rust.prior_kept}"
        )
    if rust.run.stdout:
        problems.append("Rust printed to stdout")
    return problems


def build_export_world(root: Path, case: dict[str, Any], source_data: bytes) -> None:
    """The files of one ``fixtures/export.json`` case (as ``generate.build_export_world``)."""
    out = root / "out"
    if case["directory"] == "dir":
        out.mkdir()
        write_bytes(out / "software-health.json", b"prior", 0o600)
        out.chmod(case["directory_mode"])
        if case["directory_owner"] == "other":
            os.chown(out, OTHER_UID, -1)
    elif case["directory"] == "file":
        (root / "out").write_bytes(b"not a directory")
    elif case["directory"] == "symlink":
        (root / "out-target").mkdir(mode=0o750)
        out.symlink_to("out-target")
    source = root / "state.json"
    kind = case["source"]
    if kind in ("file", "hardlink"):
        write_bytes(source, source_data, case["source_mode"])
        if case["source_owner"] == "other":
            os.chown(source, OTHER_UID, -1)
        if kind == "hardlink":
            os.link(source, root / "alias.json")
    elif kind == "symlink":
        write_bytes(root / "state-target.json", source_data, case["source_mode"])
        source.symlink_to("state-target.json")
    elif kind == "dangling_symlink":
        source.symlink_to("missing.json")
    elif kind == "directory":
        source.mkdir(mode=0o750)
    elif kind == "fifo":
        os.mkfifo(source, 0o640)


def export_pair(
    ctx: Context, name: str, setup: Callable[[Path], tuple[str, str, str]]
) -> tuple[Export, Export]:
    exports = []
    for side, command in (("python", ctx.py), ("rust", ctx.rs)):
        root = ctx.dir("export", name, side)
        root.chmod(0o755)
        source, output, group = setup(root)
        out = Path(output).parent
        exports.append(
            export_once(
                command(
                    "export-inventory",
                    "--config",
                    source,
                    "--output",
                    output,
                    "--group",
                    group,
                ),
                ctx.env,
                out,
            )
        )
    return exports[0], exports[1]


def section_export(ctx: Context) -> None:
    fixture = load_fixture("export.json")
    default_source = fixture["default_source"]
    for case in fixture["files"]:
        data = (
            bytes.fromhex(case["source_hex"])
            if case["source_hex"]
            else text_bytes(default_source)
        )
        if case["pad_to"] is not None:
            data += b" " * (case["pad_to"] - len(data))

        def setup(
            root: Path, case: dict[str, Any] = case, data: bytes = data
        ) -> tuple[str, str, str]:
            build_export_world(root, case, data)
            group = GROUP if case["group"] == "{own}" else case["group"]
            return (
                case["source_path"].replace("{root}", str(root)),
                case["output_path"].replace("{root}", str(root)),
                group,
            )

        python, rust = export_pair(ctx, f"files-{case['id']}", setup)
        problems = export_problems(python, rust, None)
        recorded = case.get("error", {}).get("class") if "error" in case else None
        if python.failure_class() != recorded:
            problems.append(
                f"Python failed with {python.failure_class()}, the fixture says {recorded}"
            )
        if recorded is None and python.document != case["result"]:
            problems.append("the Python projection differs from the fixture")
        ctx.results.check(f"export {case['id']}", problems)
    sources = [
        (f"projection-{c['id']}", text_bytes(c["source"]), c)
        for c in fixture["projection"]
    ]
    sources += [
        (f"bytes-{c['id']}", bytes.fromhex(c["hex"]), c)
        for c in fixture["source_bytes"]
    ]
    for name, data, case in sources:

        def setup(root: Path, data: bytes = data) -> tuple[str, str, str]:
            (root / "out").mkdir(mode=0o750)
            source = write_bytes(root / "state.json", data)
            return str(source), str(root / "out" / "software-health.json"), GROUP

        python, rust = export_pair(ctx, name, setup)
        problems = export_problems(
            python, rust, case.get("p3"), refused_by_both="error" in case
        )
        recorded = case["error"]["class"] if "error" in case else None
        if python.failure_class() != recorded:
            problems.append(
                f"Python failed with {python.failure_class()}, the fixture says {recorded}"
            )
        ctx.results.check(f"export {name}", problems, case.get("p3"))


# --------------------------------------------------------------------------
# collect in the container


@dataclass
class Pair:
    python: Run
    rust: Run
    python_report: Any = None
    rust_report: Any = None


class Collect:
    def __init__(self, ctx: Context) -> None:
        assert ctx.world is not None
        self.ctx = ctx
        self.world = ctx.world
        self.env = ctx.world.env()
        self.count = 0

    def pair(
        self,
        name: str,
        policy: Any,
        *,
        output: bool = True,
        caches: tuple[Path, Path] | None = None,
        config_json: str | None = None,
        usage: bool = False,
    ) -> Pair:
        """Collect with both programs; the reports, or None where a program failed."""
        self.count += 1
        folder = self.ctx.dir("collect", f"{self.count:03d}-{name}")
        text = config_json if config_json is not None else json.dumps(policy)
        runs = []
        for side, command, cache in (
            ("python", self.ctx.py, caches[0] if caches else None),
            ("rust", self.ctx.rs, caches[1] if caches else None),
        ):
            args = ["collect", "--config-json", text]
            state = folder / f"state-{side}.json"
            if output:
                args += ["--output", str(state), "--group", GROUP]
            if cache is not None:
                args += ["--cache", str(cache / "upstream.json")]
            if usage and side == "rust":
                args.append("--report-usage")
            runs.append((run(command(*args), self.env), state))
        pair = Pair(runs[0][0], runs[1][0])
        for index, (result, state) in enumerate(runs):
            report = None
            if result.code == 0:
                report = json.loads(state.read_bytes()) if output else result.json()
            if index == 0:
                pair.python_report = report
            else:
                pair.rust_report = report
        return pair

    def check(
        self,
        name: str,
        pair: Pair,
        expect: Callable[[Any], list[str]] | None = None,
        output: bool = True,
        p3: str | None = None,
    ) -> None:
        problems = []
        if p3:
            if pair.python.code != 0 or pair.rust.code != 1:
                problems.append(
                    f"P3: Python exit {pair.python.code} (0), Rust {pair.rust.code} (1)"
                )
            self.ctx.results.check(f"collect {name}", problems, p3)
            return
        if pair.python.code != 0 or pair.rust.code != 0:
            # Every scenario is a valid policy: both must collect (observation
            # failures are part of the report, never an exit code).
            problems.append(
                f"exit Python {pair.python.code}, Rust {pair.rust.code}: "
                f"{pair.rust.last_line()!r} / {pair.python.last_line()!r}"
            )
        if pair.python.code == 0 and pair.rust.code == 0:
            problems.extend(
                compare.differences(
                    pair.python_report, pair.rust_report, own_messages=self.ctx.own
                )
            )
            problems.extend(
                compare.time_spread(
                    pair.python_report, pair.rust_report, "generated_at_epoch", 300
                )
            )
            if expect is not None:
                problems.extend(f"Python: {p}" for p in expect(pair.python_report))
            if output and (pair.python.stdout or pair.rust.stdout):
                problems.append("collect --output printed to stdout")
            stray = [
                line
                for line in pair.rust.stderr.decode("utf-8", "replace").splitlines()
                if not line.startswith("software-live: usage ")
            ]
            if stray:
                problems.append(f"Rust stderr {stray[:3]}")
        self.ctx.results.check(f"collect {name}", problems)


def report_expectations(**want: Any) -> Callable[[Any], list[str]]:
    """Checks on the Python report, so that a broken world cannot pass as parity."""

    def check(report: Any) -> list[str]:
        problems = []
        for dotted, value in want.items():
            node = report
            for part in dotted.split("__"):
                node = node.get(part) if isinstance(node, dict) else None
            if callable(value):
                if not value(node):
                    problems.append(f"{dotted.replace('__', '.')} is {node!r}")
            elif node != value:
                problems.append(
                    f"{dotted.replace('__', '.')} is {node!r}, expected {value!r}"
                )
        return problems

    return check


def state_file_problems(folder: Path) -> list[str]:
    problems = []
    gid = grp.getgrnam(GROUP).gr_gid
    for side in ("python", "rust"):
        info = (folder / f"state-{side}.json").stat()
        if (
            stat.S_IMODE(info.st_mode) != 0o640
            or info.st_uid != 0
            or info.st_gid != gid
        ):
            problems.append(
                f"{side} state mode {oct(info.st_mode)} owner {info.st_uid}:{info.st_gid}"
            )
    leftovers = [
        p.name for p in folder.iterdir() if p.name.startswith(".software-live-")
    ]
    if leftovers:
        problems.append(f"temporary files left: {leftovers}")
    return problems


def cache_files(folder: Path) -> dict[str, Any]:
    return {
        path.name: json.loads(path.read_bytes())
        for path in sorted(folder.iterdir())
        if not path.name.startswith(".")
    }


def cache_differences(python: dict[str, Any], rust: dict[str, Any]) -> list[str]:
    """Cache files written by a fetch: equal except the fetch time (P2)."""
    problems = []
    for files in (python, rust):
        for name, content in files.items():
            if not isinstance(content, dict) or not compare.is_number(
                content.pop("checked_at_epoch", None)
            ):
                problems.append(f"{name}: no checked_at_epoch")
    return problems + compare.differences(python, rust)


def copy_caches(
    source: Path, target: Path, edit: Callable[[bytes], bytes] | None = None
) -> Path:
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True)
    for path in source.iterdir():
        data = path.read_bytes()
        (target / path.name).write_bytes(edit(data) if edit else data)
    return target


def age_checked_at(data: bytes, seconds: float) -> bytes:
    """Make a cache file stale in place, keeping its writer's formatting."""
    pattern = re.compile(rb'("checked_at_epoch"\s*:\s*)(-?[0-9][0-9.eE+-]*)')
    return pattern.sub(
        lambda m: m.group(1) + repr(float(m.group(2)) - seconds).encode(), data, count=1
    )


def section_collect(ctx: Context) -> None:
    assert ctx.world is not None
    world = ctx.world
    upstream = world.upstream
    assert upstream is not None
    collect = Collect(ctx)
    distro = world.release["ID"]
    other = "debian" if distro == "ubuntu" else "ubuntu"
    base = world.policy()
    pending = lambda count: isinstance(count, int) and count > 0  # noqa: E731

    # 1. The full world with the state file, the group and fresh caches.
    caches = (ctx.dir("caches", "python"), ctx.dir("caches", "rust"))
    pair = collect.pair("observed", base, caches=caches, usage=True)
    collect.check(
        "observed",
        pair,
        report_expectations(
            traefik__status="warning",
            traefik__issues=["outdated_running_version"],
            traefik__running__version=world_module.TRAEFIK_VERSION,
            traefik__upstream__version="3.7.10",
            traefik__upstream__cached=False,
            os__status="ok",
            os__upstream__status="ok",
            os__lifecycle__newest_cycle=world_module.LIFECYCLE[distro][0]["cycle"],
            postgresql__status="warning",
            postgresql__issues=["unexpected_cluster", "outdated_minor"],
            postgresql__server_version=world_module.PG_VERSION,
            apt__status="ok",
            apt__pending_security_count=pending,
            apt__indexes_fresh=True,
            summary__observation_ok=True,
        ),
    )
    folder = ctx.work / "collect" / f"{collect.count:03d}-observed"
    ctx.results.check("collect observed: state files", state_file_problems(folder))
    # Linux keeps a process's RSS high-water mark across exec, so both
    # numbers include this harness's own RSS at the fork (PLAN.md 10).
    for line in USAGE.findall(pair.rust.stderr.decode("utf-8", "replace")):
        ctx.usage.append(f"Rust collect --report-usage: {line}")
    ctx.usage.append(
        f"wait4 maxrss (the larger of the process and its largest child): "
        f"Python {pair.python.maxrss_kib} KiB, Rust {pair.rust.maxrss_kib} KiB"
    )
    files = {
        side: cache_files(cache) for side, cache in zip(("python", "rust"), caches)
    }
    ctx.results.check(
        "collect observed: caches written",
        cache_differences(cache_files(caches[0]), cache_files(caches[1])),
    )
    states = {side: folder / f"state-{side}.json" for side in ("python", "rust")}
    reports = {"python": pair.python_report, "rust": pair.rust_report}

    # 2. The manual mode: stdout with the freshness (no --output, no --cache).
    pair = collect.pair("manual", base, output=False)
    collect.check(
        "manual",
        pair,
        report_expectations(summary__fresh=True, meta__max_age_seconds=1800),
        output=False,
    )

    # 3. Cache cross-reads: both programs on copies of the same cache files.
    for writer in ("python", "rust"):
        source = caches[0] if writer == "python" else caches[1]
        upstream.mode = "error"
        upstream.take_requests()
        pair = collect.pair(
            f"fresh caches written by {writer}",
            base,
            caches=(
                copy_caches(source, ctx.work / "cx" / writer / "fresh" / "python"),
                copy_caches(source, ctx.work / "cx" / writer / "fresh" / "rust"),
            ),
        )
        collect.check(
            f"fresh caches written by {writer}",
            pair,
            report_expectations(
                traefik__upstream__cached=True,
                os__upstream__cached=True,
                postgresql__upstream__cached=True,
                traefik__upstream__checked_at_epoch=files[writer]["upstream.json"][
                    "checked_at_epoch"
                ],
            ),
        )
        requests = upstream.take_requests()
        ctx.results.check(
            f"collect fresh caches written by {writer}: no request",
            [f"requests {requests}"] if requests else [],
        )

        stale = lambda data: age_checked_at(data, 2 * 86400)  # noqa: E731
        pair = collect.pair(
            f"stale caches written by {writer}, upstream down",
            base,
            caches=(
                copy_caches(
                    source, ctx.work / "cx" / writer / "stale" / "python", stale
                ),
                copy_caches(source, ctx.work / "cx" / writer / "stale" / "rust", stale),
            ),
        )
        collect.check(
            f"stale caches written by {writer}, upstream down",
            pair,
            report_expectations(
                traefik__upstream__status="unknown",
                traefik__upstream__error="HTTPError",
                traefik__upstream__last_success=lambda value: isinstance(value, dict),
                os__upstream__status="unknown",
                os__upstream__last_success_checked_at_epoch=lambda v: v is not None,
                traefik__status="unknown",
                summary__observation_ok=True,
            ),
        )
        upstream.mode = "ok"

        invalid = lambda data: b"{not json"  # noqa: E731
        targets = (
            ctx.work / "cx" / writer / "invalid" / "python",
            ctx.work / "cx" / writer / "invalid" / "rust",
        )
        pair = collect.pair(
            f"invalid caches written by {writer}",
            base,
            caches=(
                copy_caches(source, targets[0], invalid),
                copy_caches(source, targets[1], invalid),
            ),
        )
        collect.check(
            f"invalid caches written by {writer}",
            pair,
            report_expectations(
                traefik__upstream__cached=False,
                os__upstream__cached=False,
                postgresql__upstream__cached=False,
            ),
        )
        ctx.results.check(
            f"collect invalid caches written by {writer}: rewritten",
            cache_differences(cache_files(targets[0]), cache_files(targets[1])),
        )

    # 4. Scenarios of the world.
    for mode, error in (("error", "HTTPError"), ("garbage", "JSONDecodeError")):
        upstream.mode = mode
        pair = collect.pair(f"upstream {mode}", base)
        collect.check(
            f"upstream {mode}",
            pair,
            report_expectations(
                traefik__upstream__error=error,
                traefik__status="unknown",
                os__upstream__error=error,
                postgresql__upstream__error=error,
                summary__observation_ok=True,
            ),
        )
    upstream.mode = "ok"

    pair = collect.pair(
        "operating system mismatch",
        world.policy(os__expected_id=other, os__product=other),
    )
    collect.check(
        "operating system mismatch",
        pair,
        report_expectations(
            os__status="unknown",
            os__error="ValueError: operating system does not match policy",
        ),
    )

    world.set_main_pid(0)
    pair = collect.pair("traefik stopped", base)
    collect.check(
        "traefik stopped",
        pair,
        report_expectations(
            traefik__status="unknown",
            traefik__error="ValueError: service stopped or managed binary missing",
        ),
    )
    world.start_traefik()

    world.install_traefik("traefik-3.7.8")
    pair = collect.pair("traefik replaced on disk", base)
    collect.check(
        "traefik replaced on disk",
        pair,
        report_expectations(
            traefik__issues=[
                "deleted_running_executable",
                "installed_running_drift",
                "desired_installed_drift",
            ],
            traefik__running__version=None,
            traefik__installed__version="3.7.8",
        ),
    )
    world.install_traefik("traefik-3.7.9")
    world.start_traefik()

    nothing = world.policy(
        traefik={
            "expected": False,
            "unit": "traefik.service",
            "binary_path": str(world_module.TRAEFIK),
        },
        postgresql={"expected": False},
    )
    pair = collect.pair("not expected but present", nothing)
    collect.check(
        "not expected but present",
        pair,
        report_expectations(
            traefik__issues=["unexpected_installation"],
            traefik__present=True,
            postgresql__issues=["unexpected_cluster"],
            postgresql__present=True,
        ),
    )

    world.set_main_pid(0)
    world.stop("traefik")
    world.install_traefik(None)
    world.set_clusters(None)
    pair = collect.pair("not expected and absent", nothing)
    collect.check(
        "not expected and absent",
        pair,
        report_expectations(
            traefik__status="ok",
            traefik__present=False,
            postgresql__status="ok",
            postgresql__clusters=[],
        ),
    )
    pair = collect.pair("expected but absent", base)
    collect.check(
        "expected but absent",
        pair,
        report_expectations(
            traefik__status="unknown",
            postgresql__status="unknown",
            postgresql__error=lambda text: isinstance(text, str)
            and text.startswith("FileNotFoundError"),
        ),
    )
    world.install_traefik("traefik-3.7.9")
    world.start_traefik()

    world.set_clusters(world_module.CLUSTER_MAIN.replace(" online ", " down ") + "\n")
    pair = collect.pair("postgresql cluster down", base)
    collect.check(
        "postgresql cluster down",
        pair,
        report_expectations(
            postgresql__error="ValueError: expected PostgreSQL cluster is not online"
        ),
    )
    world.set_clusters(f"{world_module.CLUSTER_MAIN}\n")
    pair = collect.pair("postgresql only the expected cluster", base)
    collect.check(
        "postgresql only the expected cluster",
        pair,
        report_expectations(postgresql__issues=["outdated_minor"]),
    )

    # 5. Every valid policy of fixtures/policy.json, also for policy_sha256.
    for case in load_fixture("policy.json"):
        if "policy_sha256" not in case:
            continue
        pair = collect.pair(
            f"policy {case['id']}", None, output=False, config_json=case["text"]
        )
        name = f"policy {case['id']}"
        if case.get("p3"):
            collect.check(name, pair, p3=case["p3"])
            continue
        collect.check(
            name,
            pair,
            report_expectations(policy_sha256=case["policy_sha256"]),
            output=False,
        )

    # 6. State cross-reads: each serve on each state file.
    constants = load_fixture("serve.json")["constants"]
    credential = base64.b64encode(
        f"{constants['user']}:{constants['password']}".encode()
    ).decode()
    request = (
        f"GET {constants['path']} HTTP/1.1\r\nHost: 127.0.0.1\r\n"
        f"Authorization: Basic {credential}\r\n\r\n"
    ).encode()
    for writer, state in states.items():
        serve_folder = ctx.dir("cross-read", writer)
        write_htpasswd(serve_folder / "htpasswd", constants)
        servers = Servers(ctx, serve_folder, constants, state)
        try:
            python = exchange(servers.ports["python"], request)
            rust = exchange(servers.ports["rust"], request)
        finally:
            servers.close()
        problems = answer_problems(python, rust, 200, 200)
        if not problems and python is not None:
            served = python.document()
            served.pop("meta")
            served["summary"].pop("fresh")
            problems.extend(compare.differences(reports[writer], served))
        ctx.results.check(f"cross-read serve of the {writer} state", problems)

    # 7. export-inventory of both states by both programs; the reader on Rust's.
    spec = importlib.util.spec_from_file_location("software_estate_reader", READER)
    assert spec is not None and spec.loader is not None
    reader = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reader)
    for writer, state in states.items():

        def setup(root: Path, state: Path = state) -> tuple[str, str, str]:
            (root / "out").mkdir(mode=0o750)
            source = root / "state.json"
            shutil.copyfile(state, source)
            source.chmod(0o640)
            return str(source), str(root / "out" / "software-health.json"), GROUP

        python, rust = export_pair(ctx, f"collected-{writer}", setup)
        problems = export_problems(python, rust, None)
        if rust.run.code == 0:
            reader.HEALTH_EXPORT = (
                ctx.work
                / "export"
                / f"collected-{writer}"
                / "rust"
                / "out"
                / "software-health.json"
            )
            try:
                read = reader.software_health("parity")
            except Exception as exc:  # noqa: BLE001 - the reader's verdict
                problems.append(
                    f"the software_estate reader refused the Rust projection: {exc!r}"
                )
            else:
                problems.extend(compare.differences(rust.document, read))
        ctx.results.check(
            f"export of the {writer} state, read by software_estate", problems
        )


# --------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--binary", type=Path, required=True, help="the Rust software-live"
    )
    parser.add_argument(
        "--python", default="/usr/bin/python3", help="the Python with python-apt"
    )
    parser.add_argument(
        "--program", type=Path, default=PROGRAM, help="software_live.py"
    )
    parser.add_argument("--section", action="append", choices=SECTIONS)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)
    if os.geteuid() != 0 or not world_module.in_container():
        print(
            "run_parity.py: runs as root in a throwaway container only", file=sys.stderr
        )
        return 2
    helper = args.binary.resolve().parent / "software-live-apt"
    if not helper.is_file():
        print(f"run_parity.py: {helper} is missing", file=sys.stderr)
        return 2
    sections = args.section or list(SECTIONS)
    results = Results(args.verbose)
    work = Path(tempfile.mkdtemp(prefix="software-live-parity-"))
    work.chmod(0o755)
    env = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C.UTF-8",
        "TMPDIR": "/tmp",
        "HOME": "/root",
    }
    ctx = Context(
        args.binary.resolve(), args.python, args.program.resolve(), work, results, env
    )
    ctx.own = own_messages(ctx.program)
    started = time.monotonic()
    try:
        for section in sections:
            print(f"== {section}", flush=True)
            if section == "collect":
                ctx.world = world_module.World(work / "collect-world")
                try:
                    ctx.world.setup()
                    section_collect(ctx)
                finally:
                    ctx.world.close()
            else:
                {
                    "validate": section_validate,
                    "config": section_config,
                    "endpoint": section_endpoint,
                    "export": section_export,
                }[section](ctx)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    release = world_module.os_release()
    print(
        f"== summary ({release.get('PRETTY_NAME')}, {time.monotonic() - started:.0f} s)"
    )
    for line in ctx.usage:
        print(f"usage {line}")
    for tag, count in sorted(results.allowed.items()):
        print(f"allowed P3 difference {tag}: {count} case(s)")
    print(
        f"{results.passed} checks passed, {len(results.failures)} failed, {len(results.notes)} notes"
    )
    return 1 if results.failures else 0


if __name__ == "__main__":
    sys.exit(main())
