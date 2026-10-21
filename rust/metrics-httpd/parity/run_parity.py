#!/usr/bin/env python3
"""Process-level parity of the Python endpoints and metrics-httpd (PLAN.md 8.3).

Starts each rendered Python endpoint script (``python <script> --bind …``)
and the Rust binary (``metrics-httpd <mode> …``) side by side on loopback
with identical inputs, sends both the requests of the fixture matrix over
real sockets and compares the two live answers by the case's ``compare``
mode. Where a case names an allowed difference (``rust_status`` and a D item
of PLAN.md 5.2), the Python side must still answer as the fixture recorded
it and the Rust side as the case expects. On top of the matrix: keep-alive
reuse, a slow client holding a connection while another request arrives
(the D-1 difference: the single-threaded Python scripts stall, Rust
answers; a threaded script shows no difference), concurrent requests, the
SIGTERM exit codes, no credential in any log, and ``shadow_compare.py``
against the live pairs.

Families (``--family``, default all): ``gate`` (``http_common.json``),
``json_file`` (``json_file.json``, the eight variants), ``script``
(``script.json``), ``apt_state`` (``apt_state.json`` ``http``), ``process``
and ``shadow``. The logyard-health payload and the static mode join when
their slices (S2d, S2e) land.

The clock is real: file mtimes (and the epochs inside the apt-state
documents) that the fixtures place relative to the generator's frozen clock
are shifted to the same distance from now, and the time fields of a 200
document (``served_at_epoch``, ``age_seconds``,
``summary.last_success_age_seconds``) may differ by 1 s when the two
requests straddle a second (each case retries up to three times to land in
the same second first; then the bytes must be identical).

Run it with the repository venv (it renders the templates with
``fixtures/generate.py``, which needs jinja2 and PyYAML); the endpoint
scripts run under ``--python`` (the hosts' CPython 3.12 in CI and in ``just
rust-parity-metrics-httpd``). Needs ``htpasswd`` (``apache2-utils``) on
``PATH``, as the Python scripts call it. Exit 0 when every check passed, 1
otherwise; skipped checks are listed.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import http.client
import json
import os
import re
import select
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable

PARITY = Path(__file__).resolve().parent
CRATE = PARITY.parent
FIXTURES = CRATE / "fixtures"
sys.path.insert(0, str(FIXTURES))
sys.path.insert(0, str(PARITY))

import generate  # noqa: E402  (fixtures/generate.py: rendering and case data)
import shadow_compare  # noqa: E402

HTPASSWD = FIXTURES / "htpasswd"
CREDENTIAL = base64.b64encode(b"user:secret").decode("ascii")
OK_AUTH = ("Authorization", f"Basic {CREDENTIAL}")
# Flags the Python scripts take; every other flag is Rust's (PLAN.md 4.9).
PYTHON_FLAGS = {
    "--path",
    "--json-path",
    "--htpasswd-file",
    "--script",
    "--script-timeout",
}
COMPARED_HEADERS = ("Content-Type", "WWW-Authenticate", "Connection")
TIME_PATHS = shadow_compare.TIME_PATHS
# Fixture times within this distance of the generator's clock are relative
# to it and get shifted to now; others (the epoch-0 mtime) stay absolute.
SHIFT_WINDOW = 20 * 365 * 86400
SCRIPT_TIMEOUT = "2"  # Python's --script-timeout is an int
STARTUP_SECONDS = 15.0
REQUEST_SECONDS = 15.0
APT_FLAG_LINE = 'REBOOT_REQUIRED_FLAG = "/var/run/reboot-required"'
LISTENING = re.compile(r" listening on 127\.0\.0\.1:(\d+)$", re.MULTILINE)


# --------------------------------------------------------------------------
# results


class Results:
    def __init__(self, verbose: bool) -> None:
        self.verbose = verbose
        self.passed = 0
        self.failures: list[str] = []
        self.skips: list[str] = []
        self.allowed: dict[str, int] = {}

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

    def skip(self, name: str, reason: str) -> None:
        self.skips.append(f"{name}: {reason}")
        print(f"SKIP {name}: {reason}", flush=True)


# --------------------------------------------------------------------------
# processes


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Endpoint:
    """One running endpoint process (Python or Rust) with its log file."""

    def __init__(
        self, side: str, name: str, command: list[str], env: dict[str, str], log: Path
    ) -> None:
        self.side = side
        self.name = name
        self.command = command
        self.env = env
        self.log = log
        self.process: subprocess.Popen[bytes] | None = None
        self.port = 0

    def log_text(self) -> str:
        try:
            return self.log.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    def _spawn(
        self, command: list[str], env: dict[str, str]
    ) -> subprocess.Popen[bytes]:
        handle = self.log.open("ab")
        try:
            return subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=handle,
                stderr=handle,
                env=env,
            )
        finally:
            handle.close()

    def start(self) -> None:
        if self.side == "rust":
            self._start_rust()
        else:
            self._start_python()

    def _start_rust(self) -> None:
        self.process = self._spawn(self.command, self.env)
        deadline = time.monotonic() + STARTUP_SECONDS
        while time.monotonic() < deadline:
            match = LISTENING.search(self.log_text())
            if match:
                self.port = int(match.group(1))
                return
            if self.process.poll() is not None:
                break
            time.sleep(0.02)
        raise RuntimeError(f"{self.name} rust did not start: {self.log_text()[-2000:]}")

    def _start_python(self) -> None:
        for _attempt in range(5):
            port = free_port()
            command = [part.replace("{port}", str(port)) for part in self.command]
            env = {k: v.replace("{port}", str(port)) for k, v in self.env.items()}
            self.process = self._spawn(command, env)
            deadline = time.monotonic() + STARTUP_SECONDS
            while time.monotonic() < deadline and self.process.poll() is None:
                try:
                    socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
                except OSError:
                    time.sleep(0.02)
                    continue
                self.port = port
                return
            self.process.kill()
            self.process.wait()
        raise RuntimeError(
            f"{self.name} python did not start: {self.log_text()[-2000:]}"
        )

    def terminate(self) -> int | None:
        """SIGTERM; the exit status (negative: killed by that signal)."""
        if self.process is None or self.process.poll() is not None:
            return self.process.returncode if self.process else None
        self.process.send_signal(signal.SIGTERM)
        try:
            return self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
            return None


class Pair:
    """The Python script and the Rust binary for one variant."""

    def __init__(
        self, results: Results, name: str, python: Endpoint, rust: Endpoint
    ) -> None:
        self.results = results
        self.name = name
        self.python = python
        self.rust = rust

    def __enter__(self) -> "Pair":
        self.python.start()
        try:
            self.rust.start()
        except BaseException:
            self.python.terminate()
            raise
        return self

    def __exit__(self, *exc: object) -> None:
        python_status = self.python.terminate()
        rust_status = self.rust.terminate()
        problems = []
        # PLAN.md 4.8: Rust exits 0 after SIGTERM; Python dies by the signal
        # (systemd counts both as a clean stop).
        if rust_status != 0:
            problems.append(f"rust exit status after SIGTERM {rust_status}, expected 0")
        if python_status != -signal.SIGTERM:
            problems.append(
                f"python exit status after SIGTERM {python_status}, expected -15"
            )
        for endpoint in (self.python, self.rust):
            if (
                CREDENTIAL in endpoint.log_text()
                or "secret" in endpoint.log_text().split()
            ):
                problems.append(f"{endpoint.side} log contains the credential")
        self.results.check(f"{self.name}/sigterm-and-logs", problems)


def rust_command(binary: Path, argv: list[str]) -> list[str]:
    return [str(binary), *argv, "--bind", "127.0.0.1", "--port", "0"]


def python_command(python: str, script: Path, argv: list[str]) -> list[str]:
    args = ["--bind", "127.0.0.1", "--port", "{port}"]
    index = 1  # argv[0] is the Rust mode
    while index < len(argv):
        if argv[index] in PYTHON_FLAGS:
            args += argv[index : index + 2]
        index += 2 if argv[index].startswith("--") else 1
    return [python, str(script), *args]


def substitute(argv: list[str], values: dict[str, str]) -> list[str]:
    return [values.get(arg, arg) for arg in argv]


def base_env() -> dict[str, str]:
    env = dict(os.environ)
    for key in [k for k in env if k.startswith(("LOGYARD_", "PYTHON"))]:
        del env[key]
    return env


# --------------------------------------------------------------------------
# HTTP


class Answer:
    def __init__(
        self, status: int, headers: dict[str, str | None], body: bytes
    ) -> None:
        self.status = status
        self.headers = headers
        self.body = body

    def header(self, name: str) -> str | None:
        return self.headers.get(name)

    def json(self) -> Any:
        try:
            return json.loads(self.body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None


RECORDED = (
    "Content-Type",
    "Content-Length",
    "WWW-Authenticate",
    "Connection",
    "Server",
)


def read_answer(sock: socket.socket, method: str) -> Answer | None:
    response = http.client.HTTPResponse(sock, method=method)
    try:
        response.begin()
        body = response.read()
    except (http.client.HTTPException, ConnectionError):
        # The Python handler raised: socketserver closes unanswered (D-2).
        return None
    return Answer(response.status, {n: response.getheader(n) for n in RECORDED}, body)


def exchange(port: int, raw: bytes, method: str) -> Answer | None:
    with socket.create_connection(("127.0.0.1", port), timeout=REQUEST_SECONDS) as sock:
        sock.sendall(raw)
        return read_answer(sock, method)


def raw_request(case: dict[str, Any]) -> bytes:
    return generate.raw_request(case)


def served_second(answer: Answer | None) -> int | None:
    if answer is None or answer.status != 200:
        return None
    document = answer.json()
    if isinstance(document, dict) and isinstance(document.get("meta"), dict):
        value = document["meta"].get("served_at_epoch")
        return value if isinstance(value, int) else None
    return None


def pair_exchange(
    pair: Pair, raw: bytes, method: str
) -> tuple[Answer | None, Answer | None]:
    """Both answers, retried until both 200 documents are served in the same
    second (at most three attempts)."""
    for _attempt in range(3):
        python = exchange(pair.python.port, raw, method)
        rust = exchange(pair.rust.port, raw, method)
        if served_second(python) == served_second(rust):
            break
    return python, rust


def without_style(body: str) -> str:
    start, end = body.find("        <style"), body.find("</style>\n")
    if start >= 0 and end >= 0:
        return body[:start] + body[end + len("</style>\n") :]
    return body


def length_ok(answer: Answer) -> bool:
    return answer.header("Content-Length") == str(len(answer.body))


def compare_live(
    python: Answer | None,
    rust: Answer | None,
    compare: str,
    message_prefix: str | None = None,
    method: str = "GET",
) -> list[str]:
    """Problems between two live answers under a fixture compare mode."""
    if python is None or rust is None:
        side = "python" if python is None else "rust"
        return [f"{side} dropped the connection without an answer"]
    problems = []
    if python.status != rust.status:
        return [f"status python {python.status} rust {rust.status}"]
    for name in COMPARED_HEADERS:
        if python.header(name) != rust.header(name):
            problems.append(
                f"{name}: python {python.header(name)!r} rust {rust.header(name)!r}"
            )
    if method == "HEAD":
        return problems
    if compare == "bytes":
        if python.body == rust.body:
            if python.header("Content-Length") != rust.header("Content-Length"):
                problems.append("Content-Length differs for equal bodies")
        elif served_second(python) is not None and served_second(rust) is not None:
            # The two requests straddled a second three times: ±1 s.
            keys = shadow_compare.compare_documents(python.body, rust.body, TIME_PATHS)
            if keys:
                problems.append(f"body differs at {', '.join(keys)}")
            if not (length_ok(python) and length_ok(rust)):
                problems.append("Content-Length does not match the body")
        else:
            problems.append(
                f"body python {python.body[:200]!r} rust {rust.body[:200]!r}"
            )
    elif compare == "html":
        expected = without_style(python.body.decode("utf-8", "replace"))
        if rust.body.decode("utf-8", "replace") != expected:
            problems.append("send_error page differs")
    elif compare in ("error_type", "error_type_only"):
        # D-3: the parser's or the OS's text after the fixed prefix may differ.
        documents = (python.json(), rust.json())
        for side, document in zip(("python", "rust"), documents):
            if not isinstance(document, dict) or list(document) != [
                "error",
                "error_type",
                "message",
            ]:
                problems.append(f"{side} error body {document!r}")
            elif message_prefix and not str(document["message"]).startswith(
                message_prefix
            ):
                problems.append(
                    f"{side} message does not start with {message_prefix!r}"
                )
        if not problems and documents[0]["error_type"] != documents[1]["error_type"]:
            problems.append("error_type differs")
        for side, answer in (("python", python), ("rust", rust)):
            if not length_ok(answer):
                problems.append(f"{side} Content-Length does not match the body")
    elif compare == "logyard-404":
        if python.body != rust.body:
            problems.append("404 body differs")
        # D-7: Rust adds the Content-Length Python's HTTP/1.0 404 lacks.
        if python.header("Content-Length") is not None or not length_ok(rust):
            problems.append("logyard 404 Content-Length")
    else:
        problems.append(f"unknown compare mode {compare}")
    return problems


def message_line(message: str) -> str:
    escaped = message.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return f"<p>Message: {escaped}.</p>"


def check_rust_expectation(
    case: dict[str, Any], python: Answer | None, rust: Answer | None
) -> list[str]:
    """A case with a named difference: Python answers as recorded, Rust as
    the case expects (status, error_type, message or body)."""
    problems = []
    recorded = case.get("status")
    live = python.status if python is not None else None
    if live != recorded:
        problems.append(f"python answered {live}, the fixture recorded {recorded}")
    if rust is None:
        return problems + ["rust dropped the connection"]
    if rust.status != case["rust_status"]:
        problems.append(
            f"rust status {rust.status}, expected {case['rust_status']} ({case['d']})"
        )
    if "rust_error_type" in case:
        document = rust.json()
        if (
            not isinstance(document, dict)
            or document.get("error") is not True
            or document.get("error_type") != case["rust_error_type"]
        ):
            problems.append(
                f"rust body {rust.body[:200]!r}, expected error_type {case['rust_error_type']}"
            )
        if rust.header("Content-Type") != "application/json":
            problems.append("rust Content-Type")
    if "rust_message" in case:
        if message_line(case["rust_message"]) not in rust.body.decode(
            "utf-8", "replace"
        ):
            problems.append("rust page lacks the expected message")
        if rust.header("Connection") != "close":
            problems.append("rust send_error page without Connection: close")
    if "rust_body_hex" in case and rust.body != bytes.fromhex(case["rust_body_hex"]):
        problems.append("rust body differs from rust_body_hex")
    return problems


def load_fixture(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def unreadable_works(tmp: Path) -> bool:
    probe = tmp / "unreadable-probe"
    probe.write_text("x")
    probe.chmod(0)
    try:
        probe.read_bytes()
        return False  # root
    except OSError:
        return True
    finally:
        probe.chmod(0o600)
        probe.unlink()


# --------------------------------------------------------------------------
# families


class Context:
    def __init__(self, args: argparse.Namespace, results: Results, tmp: Path) -> None:
        self.binary: Path = args.binary
        self.python: str = args.python
        self.results = results
        self.tmp = tmp
        self.unreadable = unreadable_works(tmp)
        self.counter = 0

    def dir(self, name: str) -> Path:
        self.counter += 1
        path = self.tmp / f"{self.counter:03d}-{name}"
        path.mkdir()
        return path

    def pair(
        self,
        name: str,
        script: Path,
        argv: list[str],
        env: dict[str, str] | None = None,
        python_argv: list[str] | None = None,
    ) -> Pair:
        logs = self.dir(f"logs-{name}")
        environment = {**base_env(), **(env or {})}
        python = Endpoint(
            "python",
            name,
            python_command(self.python, script, python_argv or argv),
            environment,
            logs / "python.log",
        )
        rust = Endpoint(
            "rust",
            name,
            rust_command(self.binary, argv),
            environment,
            logs / "rust.log",
        )
        return Pair(self.results, name, python, rust)


def family_gate(ctx: Context) -> None:
    tmp = ctx.dir("gate")
    modules = {v["variant"]: v for v in generate.variants(tmp)}
    for variant in load_fixture("http_common.json"):
        name = variant["variant"]
        script = Path(modules[name]["module"].__file__)
        argv = substitute(
            variant["argv"],
            {
                "{htpasswd}": str(HTPASSWD),
                "{json}": str(tmp / "missing.json"),
                "{script}": str(tmp / "script.sh"),
            },
        )
        env = None
        if name == "logyard":
            env = {
                **variant["env"],
                "LOGYARD_HEALTH_BIND": "127.0.0.1",
                "LOGYARD_HEALTH_PORT": "{port}",
            }
        pair = ctx.pair(f"gate-{name}", script, argv, env)
        if name == "logyard":
            pair.python.command = [ctx.python, str(script)]
            pair.rust.command = [str(ctx.binary), "logyard-health"]
            pair.rust.env = {**pair.rust.env, "LOGYARD_HEALTH_PORT": "0"}
        with pair:
            for case in variant["cases"]:
                raw = raw_request(case)
                python, rust = pair_exchange(pair, raw, case["method"])
                check = f"gate/{name}/{case['id']}"
                if "rust_status" in case:
                    ctx.results.check(
                        check, check_rust_expectation(case, python, rust), case["d"]
                    )
                else:
                    ctx.results.check(
                        check,
                        compare_live(
                            python, rust, case["compare"], method=case["method"]
                        ),
                    )


def shift(value: int, epoch: int, delta: int) -> int:
    return value + delta if abs(value - epoch) <= SHIFT_WINDOW else value


def branch_problems(
    case: dict[str, Any],
    python: Answer | None,
    served: int,
    paths: tuple[tuple[str, ...], ...],
) -> list[str]:
    """The moved clock keeps the case's branch: when Python served the
    document in the second the inputs were moved to, the fields that depend
    on the time and the inputs equal the fixture's recorded answer."""
    if python is None or case.get("compare") != "bytes" or case.get("status") != 200:
        return []
    live, recorded = python.json(), json.loads(case["body"])
    if served_second(python) != served:
        return []  # a second passed in between: parity still holds
    return [
        f"python {'.'.join(path)} {shadow_compare._get(live, path)!r}, "
        f"the fixture recorded {shadow_compare._get(recorded, path)!r}"
        for path in paths
        if shadow_compare._get(live, path) != shadow_compare._get(recorded, path)
    ]


JSON_FILE_BRANCH = (("meta", "age_seconds"),)
APT_BRANCH = (
    ("meta", "age_seconds"),
    ("meta", "state_file_fresh"),
    ("meta", "state_reboot_required"),
    ("reboot_required",),
    ("reboot_required_details", "required"),
    ("reboot_required_details", "reasons"),
    # Not last_success_age_seconds: some cases hold an absolute epoch (true,
    # 0, a huge negative) whose age depends on the real clock.
    ("summary", "last_run_ok"),
    ("summary", "currently_running"),
    ("summary", "last_success_fresh"),
    ("summary", "reboot_required"),
    ("summary", "overall_ok"),
)


def family_json_file(ctx: Context) -> None:
    fixture = load_fixture("json_file.json")
    epoch = fixture["clock_epoch"]
    tmp = ctx.dir("json-file")
    ops_control = generate.ops_control_checkout()
    rendered = {v["variant"]: v for v in generate.json_file_variants(tmp, ops_control)}
    for variant in fixture["variants"]:
        name = variant["variant"]
        if name not in rendered:
            ctx.results.skip(
                f"json_file/{name}",
                f"no ops-control checkout ({generate.OPS_CONTROL_ENV}) for the {variant['repo']} script",
            )
            continue
        base = ctx.dir(f"json-file-{name}")
        json_path = base / "data" / "metrics.json"
        argv = substitute(
            variant["argv"], {"{htpasswd}": str(HTPASSWD), "{json}": str(json_path)}
        )
        script = Path(rendered[name]["module"].__file__)
        expected_server = f"{variant['server_version']} metrics-httpd/"
        with ctx.pair(f"json_file-{name}", script, argv) as pair:
            for case in variant["cases"]:
                check = f"json_file/{name}/{case['id']}"
                state = dict(fixture["states"][case["state"]])
                if state["kind"] == "unreadable" and not ctx.unreadable:
                    ctx.results.skip(
                        check, "running as root: a mode-0 file stays readable"
                    )
                    continue
                delta = int(time.time()) - epoch
                moved = False
                if "mtime_ns" in state:
                    seconds, nanos = divmod(state["mtime_ns"], 10**9)
                    moved = shift(seconds, epoch, delta) != seconds
                    state["mtime_ns"] = shift(seconds, epoch, delta) * 10**9 + nanos
                generate.prepare_state(base, state)
                try:
                    python, rust = pair_exchange(
                        pair, raw_request(case), case["method"]
                    )
                finally:
                    if state["kind"] == "unreadable":
                        (base / "data" / "metrics.json").chmod(0o600)
                problems = []
                # D-7: Server names the variant and the Rust binary.
                if rust is not None and not (rust.header("Server") or "").startswith(
                    expected_server
                ):
                    problems.append(f"rust Server header {rust.header('Server')!r}")
                if "rust_status" in case:
                    problems += check_rust_expectation(case, python, rust)
                    ctx.results.check(check, problems, case["d"])
                else:
                    problems += compare_live(
                        python,
                        rust,
                        case["compare"],
                        case.get("message_prefix"),
                        case["method"],
                    )
                    if moved:
                        problems += branch_problems(
                            case, python, epoch + delta, JSON_FILE_BRANCH
                        )
                    ctx.results.check(check, problems)
            generate.prepare_state(base, {"kind": "absent"})


def family_script(ctx: Context) -> None:
    fixture = load_fixture("script.json")
    tmp = ctx.dir("script")
    module = generate.load_module(
        "parity_metrics", generate.METRICS, generate.PLACEHOLDER_VARS, tmp
    )
    script_path = tmp / "metrics.sh"
    argv = substitute(
        fixture["argv"],
        {
            "{htpasswd}": str(HTPASSWD),
            "{script}": str(script_path),
            "{timeout}": SCRIPT_TIMEOUT,
        },
    )
    request = {
        **fixture["request"],
        "headers": [tuple(h) for h in fixture["request"]["headers"]],
    }
    raw = raw_request(request)
    with ctx.pair("script", Path(module.__file__), argv) as pair:
        for case in fixture["cases"]:
            check = f"script/{case['id']}"
            if case["id"] == "timeout" and "sleep 5" not in (case["script"] or ""):
                ctx.results.check(
                    check, ["the timeout case must outlast --script-timeout"]
                )
                continue
            script_path.unlink(missing_ok=True)
            if case["script"] is not None:
                script_path.write_text(case["script"], encoding="ascii")
                script_path.chmod(int(case["mode"], 8))
            python, rust = pair_exchange(pair, raw, "GET")
            if "rust_status" in case:
                ctx.results.check(
                    check, check_rust_expectation(case, python, rust), case["d"]
                )
            else:
                ctx.results.check(check, compare_live(python, rust, case["compare"]))


APT_INT = re.compile(r"(?<![\w.+-])-?\d+(?![\w.])")


def shift_epochs(text: str, epoch: int, delta: int) -> str:
    """Moves the integer epochs near the generator's clock in a state text."""

    def replace(match: re.Match[str]) -> str:
        value = int(match.group(0))
        return (
            str(shift(value, epoch, delta))
            if abs(value - epoch) <= SHIFT_WINDOW
            else match.group(0)
        )

    return APT_INT.sub(replace, text)


def write_apt_state(path: Path, case: dict[str, Any], epoch: int, release: str) -> int:
    """Writes the case's state with its times moved to now; the shift."""
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.is_dir():
        shutil.rmtree(path)
    row = dict(case)
    delta = int(time.time()) - epoch
    row["mtime_epoch"] = shift(case["mtime_epoch"], epoch, delta)
    if "state_text" in row:
        text = shift_epochs(row["state_text"], epoch, delta)
        # uname().release is real here: the case's release becomes it.
        row["state_text"] = text.replace(
            json.dumps(case["running_release"]), json.dumps(release)
        )
    generate.write_state(path, row)
    return delta


def family_apt_state(ctx: Context) -> None:
    fixture = load_fixture("apt_state.json")
    epoch = fixture["served_at_epoch"]
    tmp = ctx.dir("apt-state")
    module = generate.load_module(
        "parity_apt", generate.APT, generate.PLACEHOLDER_VARS, tmp
    )
    source = Path(module.__file__).read_text(encoding="utf-8")
    flag = tmp / "reboot-required"
    if source.count(APT_FLAG_LINE) != 1:
        ctx.results.check(
            "apt_state/flag-path", [f"{APT_FLAG_LINE!r} not found once in the template"]
        )
        return
    # The script bakes the flag path; the copy reads a temporary one, as
    # Rust does with --reboot-flag.
    script = tmp / "parity_apt_flag.py"
    script.write_text(
        source.replace(
            APT_FLAG_LINE, f"REBOOT_REQUIRED_FLAG = {json.dumps(str(flag))}"
        ),
        encoding="utf-8",
    )
    state = tmp / "state.json"
    argv = substitute(
        fixture["http"]["argv"],
        {"{htpasswd}": str(HTPASSWD), "{json}": str(state), "{reboot_flag}": str(flag)},
    )
    release = os.uname().release
    raw = raw_request(
        {
            "method": "GET",
            "target": "/.well-known/os-apt-maintenance",
            "version": "HTTP/1.1",
            "headers": [OK_AUTH],
        }
    )
    with ctx.pair("apt_state", script, argv) as pair:
        for case in fixture["http"]["cases"]:
            check = f"apt_state/{case['id']}"
            if case.get("state_kind") == "unreadable" and not ctx.unreadable:
                ctx.results.skip(check, "running as root: a mode-0 file stays readable")
                continue
            delta = write_apt_state(state, case, epoch, release)
            if case["flag_present"]:
                flag.write_text("*** System restart required ***\n")
            else:
                flag.unlink(missing_ok=True)
            try:
                python, rust = pair_exchange(pair, raw, "GET")
            finally:
                if case.get("state_kind") == "unreadable":
                    state.chmod(0o600)
            if case["compare"] == "rust_only":
                case = {**case, "status": case.get("status")}
                ctx.results.check(
                    check, check_rust_expectation(case, python, rust), case["d"]
                )
            else:
                problems = compare_live(
                    python, rust, case["compare"], case.get("message_prefix")
                )
                problems += branch_problems(case, python, epoch + delta, APT_BRANCH)
                ctx.results.check(check, problems)


BASIC_STATE = {"kind": "file", "text": generate.BASIC}


def json_file_pair(ctx: Context, name: str, dir_name: str) -> tuple[Pair, Path]:
    """A json-file pair of the named variant serving ``base/data/metrics.json``."""
    tmp = ctx.dir(dir_name)
    rendered = {v["variant"]: v for v in generate.json_file_variants(tmp, None)}
    variant = next(
        v for v in load_fixture("json_file.json")["variants"] if v["variant"] == name
    )
    base = ctx.dir(f"{dir_name}-data")
    json_path = base / "data" / "metrics.json"
    argv = substitute(
        variant["argv"], {"{htpasswd}": str(HTPASSWD), "{json}": str(json_path)}
    )
    generate.prepare_state(
        base, {**BASIC_STATE, "mtime_ns": (int(time.time()) - 30) * 10**9}
    )
    return ctx.pair(dir_name, Path(rendered[name]["module"].__file__), argv), json_path


def request_bytes(path: str, auth: bool = True) -> bytes:
    return raw_request(
        {
            "method": "GET",
            "target": path,
            "version": "HTTP/1.1",
            "headers": [OK_AUTH] if auth else [],
        }
    )


def wait_readable(sock: socket.socket, seconds: float) -> bool:
    readable, _, _ = select.select([sock], [], [], seconds)
    return bool(readable)


def slow_client(pair: Pair, path: str, expect_stall: bool) -> list[str]:
    """A client sends half a request; another client arrives meanwhile."""
    problems = []
    answers: dict[str, list[Answer | None]] = {}
    for endpoint in (pair.python, pair.rust):
        slow = socket.create_connection(
            ("127.0.0.1", endpoint.port), timeout=REQUEST_SECONDS
        )
        other = socket.create_connection(
            ("127.0.0.1", endpoint.port), timeout=REQUEST_SECONDS
        )
        try:
            slow.sendall(f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n".encode())
            time.sleep(0.3)
            other.sendall(request_bytes(path))
            stalled = not wait_readable(other, 2.0)
            slow.sendall(f"{OK_AUTH[0]}: {OK_AUTH[1]}\r\n\r\n".encode())
            slow_answer = read_answer(slow, "GET")
            # HTTP/1.1 keep-alive: the single-threaded script keeps serving
            # the slow connection until its client closes it.
            slow.close()
            if not wait_readable(other, REQUEST_SECONDS):
                problems.append(
                    f"{endpoint.side}: the second client got no answer at all"
                )
                continue
            answers[endpoint.side] = [slow_answer, read_answer(other, "GET")]
        finally:
            slow.close()
            other.close()
        should_stall = expect_stall and endpoint.side == "python"
        if stalled != should_stall:
            problems.append(
                f"{endpoint.side}: second client {'stalled' if stalled else 'answered'} while the slow "
                f"client held its connection (expected {'a stall' if should_stall else 'an answer'})"
            )
    if len(answers) == 2:
        for index, label in enumerate(("slow client", "second client")):
            for problem in compare_live(
                answers["python"][index], answers["rust"][index], "bytes"
            ):
                problems.append(f"{label}: {problem}")
    return problems


def keep_alive(pair: Pair, path: str) -> list[str]:
    problems = []
    answers: dict[str, list[Answer | None]] = {}
    for endpoint in (pair.python, pair.rust):
        with socket.create_connection(
            ("127.0.0.1", endpoint.port), timeout=REQUEST_SECONDS
        ) as sock:
            got = []
            for _ in range(3):
                sock.sendall(request_bytes(path))
                got.append(read_answer(sock, "GET"))
            answers[endpoint.side] = got
    for index in range(3):
        python, rust = answers["python"][index], answers["rust"][index]
        problems += [
            f"request {index + 1}: {p}" for p in compare_live(python, rust, "bytes")
        ]
        for side, answer in (("python", python), ("rust", rust)):
            if (
                answer is not None
                and (answer.header("Connection") or "").lower() == "close"
            ):
                problems.append(
                    f"request {index + 1}: {side} closes the keep-alive connection"
                )
    return problems


def concurrent_requests(pair: Pair, path: str, count: int = 4) -> list[str]:
    """``count`` simultaneous requests per side, all answered alike. Four
    stay within the listen backlog (5) of the Python scripts' TCPServer:
    beyond it Linux drops and macOS resets the extra connections."""
    problems = []
    raw = request_bytes(path)
    results: dict[str, list[Answer | None]] = {}
    for endpoint in (pair.python, pair.rust):
        with concurrent.futures.ThreadPoolExecutor(max_workers=count) as pool:
            port = endpoint.port
            results[endpoint.side] = list(
                pool.map(lambda _: exchange(port, raw, "GET"), range(count))
            )
    for index in range(count):
        problems += [
            f"request {index + 1}: {p}"
            for p in compare_live(
                results["python"][index], results["rust"][index], "bytes"
            )
        ]
    return problems


def idle_sigterm(pair: Pair, path: str) -> list[str]:
    """SIGTERM with an idle keep-alive connection open: Rust exits 0 at
    once (PLAN.md 4.8); Python dies by the signal."""
    problems = []
    for endpoint in (pair.rust,):
        sock = socket.create_connection(
            ("127.0.0.1", endpoint.port), timeout=REQUEST_SECONDS
        )
        try:
            sock.sendall(request_bytes(path))
            if read_answer(sock, "GET") is None:
                problems.append("no answer before SIGTERM")
            started = time.monotonic()
            status = endpoint.terminate()
            elapsed = time.monotonic() - started
        finally:
            sock.close()
        if status != 0:
            problems.append(f"rust exit status {status} after SIGTERM, expected 0")
        if elapsed > 6:
            problems.append(
                f"rust took {elapsed:.1f} s to exit with an idle connection open"
            )
    return problems


def family_process(ctx: Context) -> None:
    pair, _ = json_file_pair(ctx, "backup", "process-backup")
    path = "/.well-known/backup"
    with pair:
        ctx.results.check("process/keep-alive", keep_alive(pair, path))
        ctx.results.check("process/concurrent", concurrent_requests(pair, path))
        # D-1: the single-threaded Python script stalls behind the slow client.
        ctx.results.check(
            "process/slow-client-single-threaded", slow_client(pair, path, True), "D-1"
        )
        # Rust stops here (the pair's exit then reads its status again);
        # Python's exit status is checked when the pair stops.
        ctx.results.check("process/sigterm-idle-keep-alive", idle_sigterm(pair, path))
    dns_pair, _ = json_file_pair(ctx, "dns", "process-dns")
    with dns_pair:
        # The threaded dns script answers too: no difference.
        ctx.results.check(
            "process/slow-client-threaded",
            slow_client(dns_pair, "/.well-known/dns", False),
        )


def family_shadow(ctx: Context) -> None:
    """shadow_compare.py against live pairs (PLAN.md 10.3)."""
    pair, json_path = json_file_pair(ctx, "backup", "shadow-backup")
    tmp = ctx.dir("shadow")
    password = tmp / "password"
    password.write_text("secret\n")
    report = tmp / "report.jsonl"
    with pair:
        config = {
            "host": "parity",
            "user": "user",
            "password_file": str(password),
            "report": str(report),
            "endpoints": [
                {
                    "name": "backup",
                    "mode": "json-file",
                    "path": "/.well-known/backup",
                    "realm": "backup-metrics",
                    "python": f"127.0.0.1:{pair.python.port}",
                    "rust": f"127.0.0.1:{pair.rust.port}",
                }
            ],
        }
        config_path = tmp / "shadow.json"
        config_path.write_text(json.dumps(config))

        def run(expect_exit: int, label: str) -> dict[str, Any] | None:
            code = shadow_compare.main(["run", "--config", str(config_path)])
            lines = report.read_text().splitlines()
            line = json.loads(lines[-1])
            problems = []
            if code != expect_exit:
                problems.append(
                    f"exit {code}, expected {expect_exit}: {line['endpoints']}"
                )
            text = report.read_text()
            if "secret" in text or CREDENTIAL in text or "parity-marker" in text:
                problems.append("the report contains the credential or payload text")
            ctx.results.check(f"shadow/{label}", problems)
            return line

        marker = '{"note": "parity-marker", "v": 1}'
        generate.prepare_state(
            json_path.parent.parent,
            {"kind": "file", "text": marker, "mtime_ns": time.time_ns()},
        )
        run(0, "documents-equal")
        generate.prepare_state(
            json_path.parent.parent,
            {"kind": "file", "text": '{"v": NaN}', "mtime_ns": time.time_ns()},
        )
        line = run(0, "d4-allowed")
        if line is not None and line["allowed"] != {"D-4": 1}:
            ctx.results.check("shadow/d4-counted", [f"allowed {line['allowed']}"])
        generate.prepare_state(
            json_path.parent.parent,
            {"kind": "file", "text": "[1]", "mtime_ns": time.time_ns()},
        )
        line = run(0, "d2-allowed")
        if line is not None and line["allowed"] != {"D-2": 1}:
            ctx.results.check("shadow/d2-counted", [f"allowed {line['allowed']}"])
        password.write_text("wrong\n")
        line = run(1, "auth-401-counted")
        if (
            line is not None
            and "get: auth_401" not in line["endpoints"]["backup"]["differing"]
        ):
            ctx.results.check("shadow/auth-401-key", [str(line["endpoints"])])
        password.write_text("secret\n")
        generate.prepare_state(
            json_path.parent.parent,
            {"kind": "file", "text": marker, "mtime_ns": time.time_ns()},
        )
        code = shadow_compare.main(["preflight", "--config", str(config_path)])
        ctx.results.check(
            "shadow/preflight", [] if code == 0 else [f"preflight exit {code}"]
        )


FAMILIES: dict[str, Callable[[Context], None]] = {
    "gate": family_gate,
    "json_file": family_json_file,
    "script": family_script,
    "apt_state": family_apt_state,
    "process": family_process,
    "shadow": family_shadow,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--binary", type=Path, required=True, help="the metrics-httpd binary"
    )
    parser.add_argument(
        "--python",
        default=sys.executable,
        help="interpreter for the endpoint scripts (default: this one)",
    )
    parser.add_argument(
        "--family", action="append", choices=sorted(FAMILIES), help="run only these"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="print every passing check"
    )
    args = parser.parse_args(argv)
    if not args.binary.is_file():
        parser.error(f"{args.binary}: not a file (cargo build -p metrics-httpd)")
    args.binary = args.binary.resolve()
    if shutil.which("htpasswd") is None:
        parser.error(
            "htpasswd is not on PATH (apache2-utils); the Python scripts need it"
        )
    version = subprocess.run(
        [args.python, "-c", "import sys; print(sys.version.split()[0])"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    rust_version = subprocess.run(
        [str(args.binary), "--version"], capture_output=True, text=True, check=True
    )
    print(
        f"parity: Python {version} endpoints vs {rust_version.stdout.strip()}",
        flush=True,
    )
    results = Results(args.verbose)
    with tempfile.TemporaryDirectory(prefix="metrics-httpd-parity-") as tmp_name:
        ctx = Context(args, results, Path(tmp_name))
        for name in args.family or list(FAMILIES):
            started = time.monotonic()
            try:
                FAMILIES[name](ctx)
            except Exception as error:  # a crashed family is a failure, not a pass
                results.check(f"{name}", [f"{type(error).__name__}: {error}"])
            print(
                f"family {name} done in {time.monotonic() - started:.1f} s", flush=True
            )
    print(
        f"parity: {results.passed} checks passed, {len(results.failures)} failed, "
        f"{len(results.skips)} skipped; allowed differences {dict(sorted(results.allowed.items()))}"
    )
    for skip in results.skips:
        print(f"  skipped {skip}")
    return 1 if results.failures else 0


if __name__ == "__main__":
    sys.exit(main())
