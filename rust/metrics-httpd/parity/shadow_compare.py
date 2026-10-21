#!/usr/bin/env python3
"""Compare the Python and Rust shadow endpoints of one host (PLAN.md 10.3).

The shadow run (slice S7) starts, for every endpoint of a host, the deployed
Python script and the Rust binary side by side on loopback, both reading the
production JSON/state files and a shadow htpasswd file with a throwaway
credential. A transient timer runs this script every 5 minutes as root. Each
run sends the same probes to both sides of every endpoint, compares the
answers by the rules of PLAN.md sections 4 and 5.2 and appends one JSON line
to the report: counts, probe names, status codes and the *keys* that differ,
never a payload, a header value or the credential.

Stdlib only (it is copied to the hosts, which run CPython 3.12 and 3.13).

Commands:

``run --config F``
    One comparison round; appends one line to the report file named in the
    config (``--report`` overrides it). Exit 0 when no difference outside
    PLAN.md 5.2 was found, 1 otherwise, 2 for a configuration error.
``preflight --config F``
    The setup assertion of PLAN.md 10.3: every authenticated endpoint
    answers an authenticated request on both sides with something other than
    401, every other endpoint answers at all. Exit 0 or 1 (2: configuration).
``summary --report F [F ...]``
    Totals over report files (runs, differences per endpoint and key,
    allowed differences per D item, memory maxima); exit 0 iff there was at
    least one run and no difference.

Configuration (JSON, root-only: it names the throwaway password file)::

    {
      "host": "macmini",
      "user": "shadow",
      "password_file": "/run/metrics-httpd-shadow/secret/password",
      "report": "/var/lib/metrics-httpd-shadow/report.jsonl",
      "endpoints": [
        {"name": "backup", "mode": "json-file", "path": "/.well-known/backup",
         "realm": "backup-metrics",
         "python": "127.0.0.1:39000", "rust": "127.0.0.1:39001",
         "python_unit": "metrics-httpd-shadow-py-backup.service",
         "rust_unit": "metrics-httpd-shadow-rs-backup.service"},
        {"name": "benchmarks-static", "mode": "static", "paths": ["/", "/index.html"],
         "python": "127.0.0.1:39032", "rust": "127.0.0.1:39033"}
      ]
    }

``mode`` is one of ``json-file``, ``apt-state``, ``script`` (authenticated:
``path`` and ``realm`` required), ``logyard-health`` (``path``) and
``static`` (``paths``). ``timeout`` (seconds, default 10, 30 for
logyard-health) bounds each request. ``python_unit``/``rust_unit`` are
optional; when set, every run records ``MemoryCurrent``/``MemoryPeak`` of the
unit and ``VmRSS``/``RssAnon``/``RssFile``/``Threads`` of its main process
(PLAN.md section 9).

Comparison rules (PLAN.md 5.2 items the comparer accepts, counted per item
under ``allowed``):

- D-2: the Python side drops the connection without an answer and Rust
  answers (json-file/apt-state: a 5xx JSON error; script: any answer).
- D-3: the text after ``Invalid JSON in …: ``/``Cannot read …: `` of a 502
  ``invalid_json`` / 503 ``read_error`` message; ``send_error`` HTML pages
  (only status and ``Content-Type`` are compared); logyard error texts.
- D-4: Python serves a 200 whose document Rust refuses (``NaN``,
  ``Infinity``, an overflowing float, a lone surrogate, nesting deeper than
  127, the ``$serde_json::private::Number`` key) and Rust answers 502
  ``invalid_json``.
- D-7: the ``Server`` header is never compared.
- D-11: static ``Content-Type`` (MIME guessing); status, body and the four
  security headers must be equal.
- Time: ``meta.served_at_epoch``, ``meta.age_seconds``,
  ``summary.last_success_age_seconds`` and logyard ``generated_at`` may
  differ by 1 s; logyard's Loki window counts are sampled at different
  moments and are compared by type only.

Any other difference, any 401 on an authenticated probe and an unreachable
side count as differences. A probe with a difference is repeated once after a
second (the collector timer may have replaced the file between the two
requests); only a difference that persists counts, the first one is counted
as ``transient``.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import json
import math
import os
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any

AUTH_MODES = ("json-file", "apt-state", "script")
MODES = AUTH_MODES + ("logyard-health", "static")
NOT_FOUND_PATH = "/.well-known/metrics-httpd-shadow-probe"
RETRY_DELAY_SECONDS = 1.0
# Fixed message prefixes of the json-file and apt-state errors (D-3).
MESSAGE_PREFIXES = (
    "Invalid JSON in metrics file: ",
    "Cannot read metrics file: ",
    "Invalid JSON in state file: ",
    "Cannot read state file: ",
)
TIME_PATHS = (
    ("meta", "served_at_epoch"),
    ("meta", "age_seconds"),
    ("summary", "last_success_age_seconds"),
)
LOGYARD_TIME_PATHS = (("generated_at",),)
LOGYARD_VOLATILE_PATHS = (
    ("ingest", "warning_window_entries"),
    ("ingest", "critical_window_entries"),
)
STATIC_HEADERS = (
    "Cache-Control",
    "Referrer-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
)
# serde_json's recursion limit (PLAN.md D-4): 128 nested containers fail.
MAX_DEPTH = 127
RESERVED_KEY = "$serde_json::private::Number"


class ConfigError(Exception):
    pass


# --------------------------------------------------------------------------
# configuration


def parse_address(value: Any, field: str) -> tuple[str, int]:
    if not isinstance(value, str) or ":" not in value:
        raise ConfigError(f"{field}: expected 'host:port', got {value!r}")
    host, _, port = value.rpartition(":")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        number = int(port)
    except ValueError:
        raise ConfigError(f"{field}: invalid port in {value!r}") from None
    if not host or not 0 < number < 65536:
        raise ConfigError(f"{field}: invalid address {value!r}")
    return host, number


def load_config(path: str) -> dict[str, Any]:
    try:
        with open(path, encoding="utf-8") as handle:
            config = json.load(handle)
    except (OSError, ValueError) as error:
        raise ConfigError(f"{path}: {error}") from None
    if not isinstance(config, dict):
        raise ConfigError(f"{path}: the configuration must be a JSON object")
    endpoints = config.get("endpoints")
    if not isinstance(endpoints, list) or not endpoints:
        raise ConfigError("endpoints: a non-empty list is required")
    names = set()
    needs_auth = False
    for index, endpoint in enumerate(endpoints):
        where = f"endpoints[{index}]"
        if not isinstance(endpoint, dict):
            raise ConfigError(f"{where}: must be an object")
        name = endpoint.get("name")
        if not isinstance(name, str) or not name or name in names:
            raise ConfigError(f"{where}: a unique non-empty name is required")
        names.add(name)
        mode = endpoint.get("mode")
        if mode not in MODES:
            raise ConfigError(f"{name}: mode must be one of {', '.join(MODES)}")
        endpoint["python_addr"] = parse_address(
            endpoint.get("python"), f"{name}.python"
        )
        endpoint["rust_addr"] = parse_address(endpoint.get("rust"), f"{name}.rust")
        if mode == "static":
            paths = endpoint.get("paths", ["/"])
            if (
                not isinstance(paths, list)
                or not paths
                or not all(isinstance(p, str) and p.startswith("/") for p in paths)
            ):
                raise ConfigError(
                    f"{name}: paths must be a list of paths starting with /"
                )
            endpoint["paths"] = paths
        else:
            path = endpoint.get("path")
            if not isinstance(path, str) or not path.startswith("/"):
                raise ConfigError(f"{name}: path must start with /")
        if mode in AUTH_MODES:
            needs_auth = True
            realm = endpoint.get("realm")
            if not isinstance(realm, str) or not realm:
                raise ConfigError(f"{name}: realm is required for mode {mode}")
        timeout = endpoint.get("timeout", 30 if mode == "logyard-health" else 10)
        if (
            not isinstance(timeout, (int, float))
            or isinstance(timeout, bool)
            or not 0 < timeout <= 300
        ):
            raise ConfigError(
                f"{name}: timeout must be a number of seconds in (0, 300]"
            )
        endpoint["timeout"] = float(timeout)
        for key in ("python_unit", "rust_unit"):
            unit = endpoint.get(key)
            if unit is not None and (not isinstance(unit, str) or not unit):
                raise ConfigError(f"{name}: {key} must be a unit name")
    if needs_auth:
        user = config.get("user")
        if not isinstance(user, str) or not user or ":" in user:
            raise ConfigError("user: a user name without ':' is required")
        if not isinstance(config.get("password_file"), str):
            raise ConfigError("password_file is required for authenticated endpoints")
    return config


def authorization(config: dict[str, Any]) -> str | None:
    """The Basic header for the throwaway credential (never logged)."""
    if "password_file" not in config:
        return None
    try:
        with open(config["password_file"], encoding="utf-8") as handle:
            password = handle.read().rstrip("\r\n")
    except OSError as error:
        raise ConfigError(f"password_file: {error.strerror}") from None
    return authorization_for(config["user"], password)


def authorization_for(user: str, password: str) -> str:
    token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
    return f"Basic {token}"


# --------------------------------------------------------------------------
# HTTP


class Answer:
    """One response: status, headers (first value per name) and body."""

    def __init__(self, status: int, headers: dict[str, str], body: bytes) -> None:
        self.status = status
        self.headers = headers
        self.body = body

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())


class Unreachable(Exception):
    pass


def request(
    addr: tuple[str, int],
    method: str,
    path: str,
    headers: dict[str, str],
    timeout: float,
) -> Answer | None:
    """Sends one request on a new connection; None when the server closed the
    connection without an answer (Python's handler raised)."""
    connection = http.client.HTTPConnection(addr[0], addr[1], timeout=timeout)
    try:
        try:
            connection.connect()
        except OSError as error:
            raise Unreachable(type(error).__name__) from None
        try:
            connection.request(method, path, headers=headers)
            response = connection.getresponse()
            body = response.read()
        except (http.client.HTTPException, ConnectionError):
            return None
        except socket.timeout:
            raise Unreachable("timeout") from None
        values: dict[str, str] = {}
        for name, value in response.getheaders():
            values.setdefault(name.lower(), value)
        return Answer(response.status, values, body)
    finally:
        connection.close()


# --------------------------------------------------------------------------
# document comparison


def _reject_constant(name: str) -> Any:
    raise ValueError(name)


def rust_refuses(body: bytes) -> bool:
    """True when the document Python served is one Rust refuses (D-4)."""
    try:
        document = json.loads(body.decode("utf-8"), parse_constant=_reject_constant)
    except (ValueError, RecursionError):
        return True
    stack: list[tuple[Any, int]] = [(document, 0)]
    while stack:
        value, depth = stack.pop()
        if isinstance(value, (dict, list)):
            if depth + 1 > MAX_DEPTH:
                return True
            items = value.items() if isinstance(value, dict) else enumerate(value)
            for key, item in items:
                if isinstance(key, str) and (
                    key == RESERVED_KEY or _has_surrogate(key)
                ):
                    return True
                stack.append((item, depth + 1))
        elif isinstance(value, str) and _has_surrogate(value):
            return True
        elif isinstance(value, float) and not math.isfinite(value):
            return True  # an overflowing float (1e400) that no later key replaced
    return False


def _has_surrogate(text: str) -> bool:
    return any("\ud800" <= ch <= "\udfff" for ch in text)


def _get(document: Any, path: tuple[str, ...]) -> Any:
    for key in path:
        if not isinstance(document, dict) or key not in document:
            return None
        document = document[key]
    return document


def _set(document: Any, path: tuple[str, ...], value: Any) -> None:
    for key in path[:-1]:
        document = document[key]
    document[path[-1]] = value


def _close_int(a: Any, b: Any) -> bool:
    return (
        isinstance(a, int)
        and isinstance(b, int)
        and not isinstance(a, bool)
        and not isinstance(b, bool)
        and abs(a - b) <= 1
    )


def _close_iso(a: Any, b: Any) -> bool:
    try:
        first = datetime.fromisoformat(a)
        second = datetime.fromisoformat(b)
    except (TypeError, ValueError):
        return False
    return abs((first - second).total_seconds()) <= 1


def diff_keys(python: Any, rust: Any, prefix: str = "") -> list[str]:
    """Dotted key paths where two parsed documents differ (no values)."""
    if isinstance(python, dict) and isinstance(rust, dict):
        out = []
        for key in sorted(set(python) | set(rust)):
            name = f"{prefix}.{key}" if prefix else str(key)
            if key not in python or key not in rust:
                out.append(name)
            else:
                out += diff_keys(python[key], rust[key], name)
        return out
    if isinstance(python, list) and isinstance(rust, list):
        if len(python) != len(rust):
            return [prefix or "(root)"]
        out = []
        for index, (a, b) in enumerate(zip(python, rust)):
            out += diff_keys(a, b, f"{prefix}[{index}]")
        return out
    if type(python) is not type(rust) or python != rust:
        return [prefix or "(root)"]
    return []


def compare_documents(
    python_body: bytes,
    rust_body: bytes,
    time_paths: tuple[tuple[str, ...], ...],
    iso_paths: tuple[tuple[str, ...], ...] = (),
    volatile_paths: tuple[tuple[str, ...], ...] = (),
    text_paths: tuple[tuple[str, ...], ...] = (),
    check_bytes: bool = True,
) -> list[str]:
    """Differences between two 200 JSON documents, with the time and volatile
    fields of the mode neutralised; also requires Rust's bytes to be Python's
    ``json.dumps(..., sort_keys=True)`` of the same document."""
    try:
        python = json.loads(python_body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return ["body.python_not_json"]
    try:
        rust = json.loads(rust_body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return ["body.rust_not_json"]
    if not isinstance(python, dict) or not isinstance(rust, dict):
        return diff_keys(python, rust, "body")
    # Rust's bytes must be Python's json.dumps(..., sort_keys=True) of the
    # document they encode (D-5: separators, escapes, number formatting).
    rust_canonical = json.dumps(rust, sort_keys=True).encode("utf-8") == rust_body
    for path in time_paths:
        a, b = _get(python, path), _get(rust, path)
        if a != b and _close_int(a, b):
            _set(rust, path, a)
    for path in iso_paths:
        a, b = _get(python, path), _get(rust, path)
        if a != b and _close_iso(a, b):
            _set(rust, path, a)
    for path in volatile_paths:
        a, b = _get(python, path), _get(rust, path)
        number = (int, float)
        if (
            isinstance(a, number)
            and isinstance(b, number)
            and not isinstance(a, bool)
            and not isinstance(b, bool)
            and type(a) is type(b)
        ):
            _set(rust, path, a)
    for path in text_paths:
        a, b = _get(python, path), _get(rust, path)
        if isinstance(a, str) and isinstance(b, str):
            _set(rust, path, a)
    keys = diff_keys(python, rust, "body")
    if keys or not check_bytes:
        return keys
    if (
        not rust_canonical
        or json.dumps(rust, sort_keys=True).encode("utf-8") != python_body
    ):
        # Same document, other bytes (number or escape formatting, D-5).
        return ["body.bytes"]
    return []


def logyard_text_paths(python: Any, rust: Any) -> tuple[tuple[str, ...], ...]:
    """Error texts of the logyard payload (D-2/D-3): compared by presence."""
    paths: list[tuple[str, ...]] = [("ingest", "error")]
    if (
        _get(python, ("loki", "ready")) is False
        and _get(rust, ("loki", "ready")) is False
    ):
        paths.append(("loki", "ready_body"))
    for document in (python, rust):
        units = _get(document, ("units",))
        if isinstance(units, dict):
            paths += [("units", key, "error") for key in units if isinstance(key, str)]
    return tuple(paths)


# --------------------------------------------------------------------------
# probes


class Outcome:
    def __init__(self) -> None:
        self.keys: list[str] = []
        self.allowed: str | None = None
        self.statuses: list[Any] = [None, None]

    @property
    def clean(self) -> bool:
        return not self.keys


def _json_error(answer: Answer) -> dict[str, Any] | None:
    if answer.header("Content-Type") != "application/json":
        return None
    try:
        body = json.loads(answer.body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    if isinstance(body, dict) and body.get("error") is True:
        return body
    return None


def _message_matches(python: Any, rust: Any) -> bool:
    if python == rust:
        return True
    for prefix in MESSAGE_PREFIXES:
        if isinstance(python, str) and isinstance(rust, str):
            if python.startswith(prefix) and rust.startswith(prefix):
                return True
    return False


def judge(
    mode: str,
    probe: str,
    python: Answer | None,
    rust: Answer | None,
    authenticated: bool,
) -> Outcome:
    """Compares one probe's answers (PLAN.md 4 and 5.2)."""
    out = Outcome()
    out.statuses = [
        python.status if python else "no-answer",
        rust.status if rust else "no-answer",
    ]
    if authenticated and any(a is not None and a.status == 401 for a in (python, rust)):
        out.keys.append("auth_401")
        return out
    if rust is None:
        out.keys.append("rust_no_answer")
        return out
    if python is None:
        # D-2: Python's handler raised and closed the connection.
        rust_error = _json_error(rust)
        if mode == "script" or (rust.status >= 500 and rust_error is not None):
            out.allowed = "D-2"
        else:
            out.keys.append("python_no_answer")
        return out
    if python.status != rust.status:
        rust_error = _json_error(rust)
        if (
            mode in ("json-file", "apt-state")
            and python.status == 200
            and rust.status == 502
            and rust_error is not None
            and rust_error.get("error_type") == "invalid_json"
            and rust_refuses(python.body)
        ):
            out.allowed = "D-4"
        else:
            out.keys.append("status")
        return out
    for name in ("Content-Type", "WWW-Authenticate"):
        if mode == "static" and name == "Content-Type":
            continue
        if python.header(name) != rust.header(name):
            out.keys.append(f"header.{name}")
    if mode == "static":
        for name in STATIC_HEADERS:
            if python.header(name) != rust.header(name):
                out.keys.append(f"header.{name}")
        if hashlib.sha256(python.body).digest() != hashlib.sha256(rust.body).digest():
            out.keys.append("body")
        if not out.keys and python.header("Content-Type") != rust.header(
            "Content-Type"
        ):
            out.allowed = "D-11"
        return out
    content_type = python.header("Content-Type") or ""
    if content_type.startswith("text/html"):
        # send_error pages: texts and layout may differ (D-3).
        return out
    if python.status == 200 and mode in ("json-file", "apt-state"):
        out.keys += compare_documents(python.body, rust.body, TIME_PATHS)
        return out
    if python.status == 200 and mode == "logyard-health":
        try:
            parsed = (json.loads(python.body), json.loads(rust.body))
        except ValueError:
            parsed = (None, None)
        out.keys += compare_documents(
            python.body,
            rust.body,
            (),
            iso_paths=LOGYARD_TIME_PATHS,
            volatile_paths=LOGYARD_VOLATILE_PATHS,
            text_paths=logyard_text_paths(*parsed),
            check_bytes=False,
        )
        return out
    python_error, rust_error = _json_error(python), _json_error(rust)
    if (
        mode in ("json-file", "apt-state")
        and python_error is not None
        and rust_error is not None
    ):
        if list(python_error) != list(rust_error):
            out.keys.append("body.keys")
        if python_error.get("error_type") != rust_error.get("error_type"):
            out.keys.append("body.error_type")
        if not _message_matches(python_error.get("message"), rust_error.get("message")):
            out.keys.append("body.message")
        return out
    if python.body != rust.body:
        out.keys.append("body")
    elif python.header("Content-Length") != rust.header("Content-Length") and not (
        mode == "logyard-health" and python.header("Content-Length") is None
    ):
        out.keys.append("header.Content-Length")
    return out


def probes(
    endpoint: dict[str, Any], auth: str | None
) -> list[tuple[str, str, str, dict[str, str], bool]]:
    """(probe name, method, path, headers, authenticated)."""
    mode = endpoint["mode"]
    if mode == "static":
        return [(f"get:{path}", "GET", path, {}, False) for path in endpoint["paths"]]
    path = endpoint["path"]
    if mode == "logyard-health":
        return [
            ("get", "GET", path, {}, False),
            ("not-found", "GET", NOT_FOUND_PATH, {}, False),
        ]
    assert auth is not None
    return [
        ("get", "GET", path, {"Authorization": auth}, True),
        ("no-auth", "GET", path, {}, False),
        ("not-found", "GET", NOT_FOUND_PATH, {}, False),
        ("head", "HEAD", path, {}, False),
    ]


def run_probe(
    endpoint: dict[str, Any], probe: tuple[str, str, str, dict[str, str], bool]
) -> Outcome:
    name, method, path, headers, authenticated = probe
    answers: list[Answer | None] = []
    unreachable = []
    for side in ("python", "rust"):
        try:
            answers.append(
                request(
                    endpoint[f"{side}_addr"], method, path, headers, endpoint["timeout"]
                )
            )
        except Unreachable:
            answers.append(None)
            unreachable.append(side)
    if unreachable:
        out = Outcome()
        out.keys = [f"{side}_unreachable" for side in unreachable]
        out.statuses = [
            "unreachable"
            if side in unreachable
            else (answer.status if answer else "no-answer")
            for side, answer in zip(("python", "rust"), answers)
        ]
        return out
    out = judge(endpoint["mode"], name, answers[0], answers[1], authenticated)
    if name == "no-auth" and not out.keys:
        python = answers[0]
        assert python is not None
        if python.status != 401:
            out.keys.append("no_auth_not_401")
        elif python.header("WWW-Authenticate") != f'Basic realm="{endpoint["realm"]}"':
            out.keys.append("header.WWW-Authenticate")
    return out


# --------------------------------------------------------------------------
# memory (PLAN.md section 9)


def unit_memory(unit: str) -> dict[str, Any]:
    try:
        result = subprocess.run(
            [
                "systemctl",
                "show",
                "--property=MemoryCurrent,MemoryPeak,MainPID",
                "--",
                unit,
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"error": type(error).__name__}
    if result.returncode != 0:
        return {"error": f"systemctl exit {result.returncode}"}
    values = dict(
        line.split("=", 1) for line in result.stdout.splitlines() if "=" in line
    )
    out: dict[str, Any] = {}
    for key in ("MemoryCurrent", "MemoryPeak"):
        value = values.get(key, "")
        out[key] = int(value) if value.isdigit() else None
    pid = values.get("MainPID", "0")
    if pid.isdigit() and int(pid) > 0:
        try:
            with open(
                f"/proc/{pid}/status", encoding="ascii", errors="replace"
            ) as handle:
                for line in handle:
                    field, _, rest = line.partition(":")
                    if field in ("VmRSS", "RssAnon", "RssFile"):
                        out[f"{field}_kB"] = int(rest.split()[0])
                    elif field == "Threads":
                        out["Threads"] = int(rest.split()[0])
        except (OSError, ValueError, IndexError):
            out["proc"] = "unavailable"
    return out


# --------------------------------------------------------------------------
# commands


def compare_endpoint(endpoint: dict[str, Any], auth: str | None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "mode": endpoint["mode"],
        "probes": 0,
        "differences": 0,
        "differing": [],
        "allowed": {},
        "transient": 0,
        "statuses": {},
    }
    for probe in probes(endpoint, auth):
        result["probes"] += 1
        outcome = run_probe(endpoint, probe)
        if not outcome.clean:
            time.sleep(RETRY_DELAY_SECONDS)
            outcome = run_probe(endpoint, probe)
            if outcome.clean:
                result["transient"] += 1
        result["statuses"][probe[0]] = outcome.statuses
        if outcome.keys:
            result["differences"] += 1
            result["differing"] += [f"{probe[0]}: {key}" for key in outcome.keys]
        if outcome.allowed:
            result["allowed"][outcome.allowed] = (
                result["allowed"].get(outcome.allowed, 0) + 1
            )
    for side in ("python", "rust"):
        unit = endpoint.get(f"{side}_unit")
        if unit:
            result.setdefault("memory", {})[side] = unit_memory(unit)
    return result


def compare_round(config: dict[str, Any]) -> dict[str, Any]:
    auth = authorization(config)
    endpoints = {
        endpoint["name"]: compare_endpoint(endpoint, auth)
        for endpoint in config["endpoints"]
    }
    allowed: dict[str, int] = {}
    for result in endpoints.values():
        for item, count in result["allowed"].items():
            allowed[item] = allowed.get(item, 0) + count
    return {
        "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "host": config.get("host"),
        "differences": sum(r["differences"] for r in endpoints.values()),
        "allowed": allowed,
        "endpoints": endpoints,
    }


def append_report(path: str, line: dict[str, Any]) -> None:
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, mode=0o700, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(line, sort_keys=True) + "\n")


def command_run(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    report = args.report or config.get("report")
    if not isinstance(report, str) or not report:
        raise ConfigError("report: a report file is required (config or --report)")
    line = compare_round(config)
    append_report(report, line)
    print(
        f"shadow_compare: {len(line['endpoints'])} endpoints, "
        f"{line['differences']} differences, allowed {line['allowed'] or {}}"
    )
    return 0 if line["differences"] == 0 else 1


def command_preflight(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    auth = authorization(config)
    failed = 0
    for endpoint in config["endpoints"]:
        mode = endpoint["mode"]
        path = endpoint["paths"][0] if mode == "static" else endpoint["path"]
        headers = {"Authorization": auth} if mode in AUTH_MODES and auth else {}
        for side in ("python", "rust"):
            try:
                answer = request(
                    endpoint[f"{side}_addr"], "GET", path, headers, endpoint["timeout"]
                )
                status: Any = answer.status if answer else "no-answer"
            except Unreachable as error:
                status = f"unreachable ({error})"
            bad = not isinstance(status, int) or (mode in AUTH_MODES and status == 401)
            # A dropped connection is a valid file-state answer of Python (D-2).
            if status == "no-answer" and side == "python":
                bad = False
            failed += bad
            print(f"{endpoint['name']} {side}: {status}{' FAIL' if bad else ''}")
    return 1 if failed else 0


def command_summary(args: argparse.Namespace) -> int:
    runs = 0
    first = last = None
    total = 0
    allowed: dict[str, int] = {}
    endpoints: dict[str, dict[str, Any]] = {}
    for path in args.report:
        try:
            with open(path, encoding="utf-8") as handle:
                lines = handle.read().splitlines()
        except OSError as error:
            raise ConfigError(f"{path}: {error.strerror}") from None
        for number, text in enumerate(lines, 1):
            if not text.strip():
                continue
            try:
                line = json.loads(text)
            except ValueError:
                raise ConfigError(f"{path}:{number}: not JSON") from None
            runs += 1
            first = first or line.get("time")
            last = line.get("time")
            total += line.get("differences", 0)
            for item, count in line.get("allowed", {}).items():
                allowed[item] = allowed.get(item, 0) + count
            for name, result in line.get("endpoints", {}).items():
                entry = endpoints.setdefault(
                    name,
                    {
                        "differences": 0,
                        "differing": {},
                        "transient": 0,
                        "memory_max": {},
                    },
                )
                entry["differences"] += result.get("differences", 0)
                entry["transient"] += result.get("transient", 0)
                for key in result.get("differing", []):
                    entry["differing"][key] = entry["differing"].get(key, 0) + 1
                for side, memory in result.get("memory", {}).items():
                    maxima = entry["memory_max"].setdefault(side, {})
                    for field, value in memory.items():
                        if isinstance(value, int) and not isinstance(value, bool):
                            maxima[field] = max(maxima.get(field, value), value)
    summary = {
        "runs": runs,
        "first": first,
        "last": last,
        "differences": total,
        "allowed": allowed,
        "endpoints": endpoints,
        "pass": runs > 0 and total == 0,
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["pass"] else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser(
        "run", help="one comparison round, appended to the report"
    )
    run.add_argument("--config", required=True)
    run.add_argument("--report", help="report file (default: the config's report)")
    preflight = commands.add_parser(
        "preflight", help="the setup assertion of PLAN.md 10.3"
    )
    preflight.add_argument("--config", required=True)
    summary = commands.add_parser("summary", help="totals over report files")
    summary.add_argument("--report", required=True, nargs="+")
    args = parser.parse_args(argv)
    handler = {
        "run": command_run,
        "preflight": command_preflight,
        "summary": command_summary,
    }
    try:
        return handler[args.command](args)
    except ConfigError as error:
        print(f"shadow_compare: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
