#!/usr/bin/env python3
"""Generate the Layer-1 decision fixtures of the Rust guard port (PLAN.md 7.2).

The Python guard (roles/echoport_remote_command_guard/files/...) is the
oracle: every expected decision in ``fixtures/`` is what its ``check()`` (or
``load_policy()``) returns for that command, policy and environment.

Two steps:

``record``
    Needs the repo venv (ansible-core, jinja2): imports
    ``tests/test_echoport_remote_command_guard.py`` and writes its inputs to
    ``fixtures/policies/{production,staging}.json`` (the test policies),
    ``fixtures/corpus/runner.jsonl`` (every command each remote runner sends
    for a backup and a restore, from the tests' ``RecordingHosts`` harness)
    and ``fixtures/corpus/unit.jsonl`` (every ``check()`` and
    ``Policy.from_dict()`` call the guard's unit tests make, with the lstat,
    realpath and user lookups each call made).

``generate``
    Stdlib only, runs under the hosts' Pythons (3.12, 3.13): reads the
    policies and the corpus and writes ``fixtures/<source>.jsonl`` for the
    sources runner, journal, unit, mutation, fs and policy, plus
    ``fixtures/GUARD_SHA256`` and ``fixtures/manifest.json``.

``check [--record]`` regenerates into a temporary directory and fails on any
difference to the committed fixtures (the drift check). ``all`` runs record
and generate in place.

The output is deterministic: the generator re-executes itself with
``PYTHONHASHSEED=0`` (set iteration only decides which of several invalid
policy values an error names) and never depends on the clock or the machine.
"""

from __future__ import annotations

import argparse
import contextlib
import filecmp
import hashlib
import io
import json
import math
import os
import re
import shlex
import sys
import tempfile
import unittest
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

if __name__ == "__main__" and sys.flags.hash_randomization:
    # -I/-E would ignore PYTHONHASHSEED: keep what they stand for (-s -P and no
    # other PYTHON* variables) instead.
    if os.environ.get("ECHOPORT_GEN_FIXTURES_REEXEC"):
        sys.exit("gen_fixtures: cannot turn off hash randomization (PYTHONHASHSEED=0)")
    _env = dict(os.environ)
    _flags = []
    if sys.flags.isolated or sys.flags.ignore_environment:
        _env = {k: v for k, v in _env.items() if not k.startswith("PYTHON")}
        _flags = ["-s", "-P"]
    os.execve(sys.executable, [sys.executable, *_flags, *sys.argv],
              {**_env, "PYTHONHASHSEED": "0", "ECHOPORT_GEN_FIXTURES_REEXEC": "1"})

sys.path.insert(0, str(Path(__file__).resolve().parent))
import oracle  # noqa: E402
from oracle import GUARD, OTHER_UID, USERS, Scenario  # noqa: E402

FIXTURES = oracle.FIXTURES
TESTS = oracle.REPO / "tests"
SOURCES = ("runner", "journal", "unit", "mutation", "fs")
MAX = GUARD.MAX_COMMAND_LENGTH

# What a fixture says about the 4.1/4.2 refusals of the Rust guard (PLAN.md 4.4):
P3_PREFILTER = "prefilter"  # a printable-ASCII-and-tab-only, no `\`/`#` command filter
P3_INVALID_UTF8 = "invalid-utf8"
P3_POLICY_TYPE = "policy-type"
P3_POLICY_NEWLINE = "policy-trailing-newline"
P3_PYTHON_ERROR = "python-error"  # check() raises (the tar shape's unguarded shlex.split)

# The hosts as the runners leave them: their mktemp dirs exist, nothing else
# (tests' lstat_runner_view, with the guard running as root).
_RUNNER_DIRS = re.compile(
    r"^(?:/var/tmp/(?:gotosocial-echoport|django-chat-db-restore)\.[A-Za-z0-9]+|/tmp/echoport-pp-private-media\.[A-Za-z0-9]+)$"
)


def runner_view_lstat(path: str) -> Any:
    if _RUNNER_DIRS.match(path):
        return oracle.make_stat("dir", 0o700, oracle.DEFAULT_EUID, 2)
    raise oracle.lstat_error("ENOENT")


def runner_view() -> Scenario:
    return Scenario(lstat=runner_view_lstat, realpath=os.path.normpath)


class GeneratorError(RuntimeError):
    pass


def printable_ascii(command: str) -> bool:
    return all(c == "\t" or " " <= c <= "~" for c in command)


def prefilter_refuses(command: str) -> bool:
    """PLAN.md 4.1: what the Rust prefilter refuses after Python's pre-checks."""
    return not printable_ascii(command) or "\\" in command or "#" in command


def python_prechecks_pass(command: str) -> bool:
    return bool(command) and len(command) <= MAX and not any(c in command for c in "\n\r\0")


def short_hash(*parts: str) -> str:
    return hashlib.sha256("\0".join(parts).encode("utf-8", "surrogatepass")).hexdigest()[:12]


def dumps(value: Any) -> str:
    text = json.dumps(value, ensure_ascii=True, separators=(",", ":"))
    # Lone surrogates would make the file unreadable for serde_json.
    json.dumps(value, ensure_ascii=False).encode("utf-8")
    return text


# --- step 1: record (repo venv) -------------------------------------------------


def _import_tests() -> Any:
    sys.path.insert(0, str(oracle.REPO))
    import importlib

    return importlib.import_module("tests.test_echoport_remote_command_guard")


RUNNER_HOSTS = {"wersdoerfer.de": "production", "staging.wersdoerfer.de": "staging", "staging.example.org": "staging"}
# Runner stamps that come from the clock: replaced by synthetic ones.
_CLOCK_STAMPS = (
    (re.compile(r"(?<![0-9])20[0-9]{2}[01][0-9][0-3][0-9]T[0-9]{6}Z"), "20261015T020000Z"),
    (re.compile(r"(?<![0-9])20[0-9]{2}[01][0-9][0-3][0-9][0-9]{6}(?![0-9])"), "20261015020000"),
)


def _synthetic_stamps(command: str) -> str:
    for pattern, stamp in _CLOCK_STAMPS:
        command = pattern.sub(stamp, command)
    return command


def _run_tests(cls: type, names: Iterable[str]) -> None:
    suite = unittest.TestSuite(cls(name) for name in names)
    result = unittest.TestResult()
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        suite.run(result)
    if not result.wasSuccessful():
        details = "\n".join(text for _, text in result.failures + result.errors)
        raise GeneratorError(f"{cls.__name__} failed while recording:\n{details}")


def _test_names(cls: type) -> list[str]:
    return sorted(name for name in dir(cls) if name.startswith("test_"))


def record_runner_corpus(testmod: Any) -> list[dict[str, Any]]:
    cls = testmod.RunnerCommandsAreAllowlisted
    recorded: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    current: list[str] = []

    def record(self: Any, hosts: Any, expected_hosts: set[str]) -> None:
        if not hosts.commands:
            raise AssertionError("runner sent no remote commands")
        for host, command in hosts.commands:
            if host not in RUNNER_HOSTS:
                raise GeneratorError(f"runner host without a policy: {host}")
            entry = (RUNNER_HOSTS[host], _synthetic_stamps(command))
            if entry not in seen:
                seen.add(entry)
                recorded.append({"test": current[0], "host": host, "policy": entry[0], "command": entry[1]})

    original = cls.assert_all_allowed
    cls.assert_all_allowed = record
    try:
        for name in _test_names(cls):
            current[:] = [name]
            _run_tests(cls, [name])
    finally:
        cls.assert_all_allowed = original
    return recorded


# GuardRedirects and GuardMain test the process (S4); test_scp_against_a_real_tree
# needs a real tree (Layer 2, PLAN.md 7.5).
UNIT_CLASSES = ("GuardAllowsRunnerShapes", "GuardRefusals")
UNIT_SKIP = {"GuardRefusals.test_scp_against_a_real_tree"}


def record_unit_corpus(testmod: Any, policies: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    from unittest import mock

    guard = testmod.GUARD
    named = {name: oracle.normalize_policy(guard.Policy.from_dict(json.loads(json.dumps(data))))
             for name, data in policies.items()}
    entries: list[dict[str, Any]] = []
    current: list[str] = []
    original_check = guard.check
    original_from_dict = guard.Policy.from_dict.__func__

    def absent(path: str) -> Any:
        raise FileNotFoundError(path)

    def recording_check(command: str, policy: Any, realpath: Any = os.path.realpath, lstat: Any = os.lstat) -> Any:
        if realpath is os.path.realpath:
            raise GeneratorError(f"{current[0]} uses the real realpath; it belongs to Layer 2")
        fingerprint = oracle.normalize_policy(policy)
        names = [name for name, value in named.items() if value == fingerprint]
        if len(names) != 1:
            raise GeneratorError(f"{current[0]} checks against an unknown policy: {fingerprint}")
        recorder = oracle.Recorder(Scenario(lstat=absent if lstat is os.lstat else lstat, realpath=realpath))
        outcome = "allowed"
        with mock.patch("pwd.getpwnam", recorder.getpwnam):
            try:
                return original_check(command, policy, realpath=recorder.realpath, lstat=recorder.lstat)
            except guard.Refused:
                outcome = "refused"
                raise
            finally:
                entries.append({"test": current[0], "kind": "check", "policy": names[0], "command": command,
                                "env": recorder.env(), "outcome": outcome})

    def recording_from_dict(cls: Any, data: dict) -> Any:
        entries.append({"test": current[0], "kind": "policy", "policy_text": json.dumps(data)})
        return original_from_dict(cls, data)

    guard.check = recording_check
    guard.Policy.from_dict = classmethod(recording_from_dict)
    try:
        # The tests build their stat results with os.geteuid(): the hosts' guard runs as root.
        with mock.patch("os.geteuid", return_value=oracle.DEFAULT_EUID):
            for class_name in UNIT_CLASSES:
                cls = getattr(testmod, class_name)
                for name in _test_names(cls):
                    test_id = f"{class_name}.{name}"
                    if test_id in UNIT_SKIP:
                        continue
                    current[:] = [test_id]
                    # setUp builds the policies through from_dict: not a test case.
                    guard.Policy.from_dict = classmethod(original_from_dict)
                    instance = cls(name)
                    instance.setUp()
                    guard.Policy.from_dict = classmethod(recording_from_dict)
                    try:
                        getattr(instance, name)()
                    finally:
                        instance.doCleanups()
    finally:
        guard.check = original_check
        guard.Policy.from_dict = classmethod(original_from_dict)
    return entries


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(dumps(row) + "\n")
            count += 1
    return count


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    with open(path, encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def record(out: Path) -> None:
    testmod = _import_tests()
    policies = {"production": testmod.PRODUCTION_POLICY, "staging": testmod.STAGING_POLICY}
    (out / "policies").mkdir(parents=True, exist_ok=True)
    for name, data in policies.items():
        (out / "policies" / f"{name}.json").write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    runner = record_runner_corpus(testmod)
    if record_runner_corpus(testmod) != runner:
        raise GeneratorError("the runner corpus differs between two recordings (clock or random input?)")
    write_jsonl(out / "corpus" / "runner.jsonl", runner)
    write_jsonl(out / "corpus" / "unit.jsonl", record_unit_corpus(testmod, policies))


# --- step 2: generate (stdlib) --------------------------------------------------


class Cases:
    """The cases of one source, deduplicated, with stable ids."""

    def __init__(self, source: str, policies: dict[str, Any]) -> None:
        self.source = source
        self.policies = policies
        self.rows: list[dict[str, Any]] = []
        self.keys: set[str] = set()

    def add(self, label: str, policy: str, command: str | bytes, scenario: Scenario,
            expect: str | None = None) -> dict[str, Any] | None:
        if isinstance(command, bytes):
            text = command.decode("utf-8", "surrogateescape")
            payload: dict[str, Any] = {"command_hex": command.hex()}
            try:
                command.decode("utf-8")
                raise GeneratorError(f"{label}: byte commands are for invalid UTF-8 only")
            except UnicodeDecodeError:
                pass
            p3 = [P3_INVALID_UTF8]
        else:
            text = command
            payload = {"command": command}
            p3 = [P3_PREFILTER] if python_prechecks_pass(command) and prefilter_refuses(command) else []
        expected, env = oracle.run_check(self.policies[policy], text, scenario)
        replay = oracle.run_check(self.policies[policy], text, Scenario.from_env(env))
        if replay != (expected, env):
            raise GeneratorError(f"{label}: the recorded env does not reproduce the decision: {text!r}")
        if expected["verdict"] == "error":
            # check() raised something main() does not catch: Python exits 1 with
            # a traceback, logs nothing and runs nothing (PLAN.md 4.2).
            if expected["error_type"] != "ValueError":
                raise GeneratorError(f"{label}: check() raised {expected['error_type']}: {text!r}")
            p3 = [*p3, P3_PYTHON_ERROR]
        if expected["verdict"] == "allowed" and not (isinstance(command, str) and printable_ascii(command)):
            raise GeneratorError(f"{label}: Python accepts a command outside printable ASCII and tab: {text!r}")
        if expect is not None and expected["verdict"] != expect:
            raise GeneratorError(f"{label}: expected {expect}, Python says {expected}: {text!r}")
        key = dumps([policy, payload, env])
        if key in self.keys:
            return None
        self.keys.add(key)
        row: dict[str, Any] = {
            "id": f"{self.source}/{label}/{policy}/{short_hash(key)}",
            "source": self.source,
            "policy": policy,
            **payload,
            "env": env,
            "expected": expected,
        }
        if p3:
            row["p3"] = p3
        self.rows.append(row)
        return row


# --- journal: the shapes seen live (PLAN.md 3.4), synthetic stamps --------------

GTS_TMP = "/var/tmp/gotosocial-echoport.Ab12Cd"
PP_TMP = "/tmp/echoport-pp-private-media.Ab12Cd34"
CHAT_TMP = "/var/tmp/django-chat-db-restore.Ab12Cd34"
DUMP_STAMP = "2026-10-15T02-00-00"
RESTORE_STAMP = "20261015020000"
RSYNC_DOWNLOAD = "rsync --server --sender -logDtpre.iLsfxCIvu --safe-links ."
RSYNC_UPLOAD = "rsync --server -logtpre.iLsfxCIvu ."
RSYNC_UPLOAD_DELETE = "rsync --server -logtpre.iLsfxCIvu --delete ."
PP_MEDIA = "/home/python-podcast/site/private_media"
PP_PROBE = (
    f"sh -c 'if test -L {PP_MEDIA}; then echo symlink; elif test -d {PP_MEDIA}; then echo present; "
    f"elif test -e {PP_MEDIA}; then echo notdir; else echo missing; fi'"
)

JOURNAL: dict[str, list[str]] = {
    "production": [
        f"cat {GTS_TMP}/sqlite.db",
        f"chown gotosocial:gotosocial {GTS_TMP}",
        f"du -sb -- {PP_MEDIA}",
        "mktemp -d /tmp/echoport-pp-private-media.XXXXXXXX",
        "mktemp -d /var/tmp/gotosocial-echoport.XXXXXX",
        f"rm -f /tmp/echoport_homepage_dump_{DUMP_STAMP}.dump",
        f"rm -f /tmp/echoport_pp_dump_{DUMP_STAMP}.dump",
        f"rm -rf -- {PP_TMP}",
        f"rm -rf -- {GTS_TMP}",
        f"{RSYNC_DOWNLOAD} /var/lib/gotosocial/storage/",
        ("runuser -u gotosocial -- sqlite3 /var/lib/gotosocial/sqlite.db "
         f"'.backup '\"'\"'{GTS_TMP}/sqlite.db'\"'\"''"),
        f"runuser -u gotosocial -- sqlite3 {GTS_TMP}/sqlite.db 'PRAGMA integrity_check;'",
        "scp -f /etc/gotosocial/config.yaml",
        f"scp -f {PP_TMP}/private_media.tar.gz",
        f"scp -f /tmp/echoport_homepage_dump_{DUMP_STAMP}.dump",
        f"scp -f /tmp/echoport_pp_dump_{DUMP_STAMP}.dump",
        "scp -f /var/lib/gotosocial/.ops-domain-layout",
        PP_PROBE,
        (f"sudo -u postgres pg_dump --format=custom --file=/tmp/echoport_homepage_dump_{DUMP_STAMP}.dump "
         "--dbname=homepage"),
        (f"sudo -u postgres pg_dump --format=custom --file=/tmp/echoport_pp_dump_{DUMP_STAMP}.dump "
         "--dbname=python-podcast"),
        "test -d /var/lib/gotosocial/storage",
        "test -f /var/lib/gotosocial/sqlite.db",
        f"umask 077 && tar -C /home/python-podcast/site -czf {PP_TMP}/private_media.tar.gz -- private_media",
        "id",
    ],
    "staging": [
        "readlink -f /home/marina/site/db.sqlite3",
        "readlink -f /home/villakunterbunt/data/db.sqlite3",
        "readlink -f /home/villakunterbunt/data/media",
        "readlink -f /home/villakunterbunt/data/private_media",
        f"rm -f /tmp/echoport_homepage_restore_{RESTORE_STAMP}.dump",
        f"rm -f /tmp/echoport_pp_restore_{RESTORE_STAMP}.dump",
        f"{RSYNC_DOWNLOAD} /home/villakunterbunt/data/media/",
        f"{RSYNC_DOWNLOAD} /home/villakunterbunt/data/private_media/",
        "runuser -u postgres -- pg_dump --format=custom --dbname=django-chat",
        "runuser -u postgres -- psql -X -v ON_ERROR_STOP=1 -qAt -d django-chat -c 'SHOW server_version;'",
        "scp -f /home/marina/site/db.sqlite3",
        "scp -f /home/marina/site/db.sqlite3-shm",
        "scp -f /home/marina/site/db.sqlite3-wal",
        "scp -f /home/villakunterbunt/data/db.sqlite3",
        "scp -f /home/villakunterbunt/data/db.sqlite3-shm",
        "scp -f /home/villakunterbunt/data/db.sqlite3-wal",
        f"scp -t /tmp/echoport_homepage_restore_{RESTORE_STAMP}.dump",
        f"scp -t /tmp/echoport_pp_restore_{RESTORE_STAMP}.dump",
        "sudo -u postgres createdb --owner=homepage homepage",
        "sudo -u postgres createdb --owner=python-podcast python-podcast",
        "sudo -u postgres dropdb --if-exists --force homepage",
        "sudo -u postgres dropdb --if-exists --force python-podcast",
        ("sudo -u postgres pg_restore --exit-on-error --dbname=homepage --no-owner --role=homepage "
         f"/tmp/echoport_homepage_restore_{RESTORE_STAMP}.dump"),
        ("sudo -u postgres pg_restore --exit-on-error --dbname=python-podcast --no-owner --role=python-podcast "
         f"/tmp/echoport_pp_restore_{RESTORE_STAMP}.dump"),
        "sudo -u postgres psql -d homepage -c 'SELECT 1'",
        "sudo -u postgres psql -d python-podcast -c 'SELECT 1'",
        "systemctl show --property=LoadState --value homepage-db-worker",
        "systemctl show --property=LoadState --value python-podcast-db-worker",
        *(f"systemctl {verb} {unit}" for verb in ("start", "stop") for unit in (
            "homepage-db-worker", "homepage.service", "marina.service", "python-podcast-db-worker",
            "python-podcast.service", "villakunterbunt-django.service", "villakunterbunt-next.service")),
        "test -d /home/villakunterbunt/data/media",
        "test -d /home/villakunterbunt/data/private_media",
        "test -e /home/villakunterbunt/data/media",
        "test -e /home/villakunterbunt/data/private_media",
    ],
}
JOURNAL_REFUSED = {"id"}


# --- mutation (PLAN.md 7.2 item 4) ----------------------------------------------

APPENDS = ("; id", "&& id", "| id", "$(id)", "`id`", "#x", "\\")
ODD_CHARS = (
    "\x1b", "\x1c", "\x1f", "\x0b", "\x0c", "\x7f", "\x85", "\xa0", "\u200b", "\u2028", "\ufeff",
    "\u0430",  # CYRILLIC SMALL LETTER A, looks like "a"
    "\uff0f",  # FULLWIDTH SOLIDUS, looks like "/"
    "\u2215",  # DIVISION SLASH
    "\xe9",
)
_SIMPLE_TOKEN = re.compile(r"^[A-Za-z0-9._/=:@,+-]+$")
_PATH = re.compile(r"/[A-Za-z0-9._/-]*[A-Za-z0-9._-]")


def _vocabulary(policies: dict[str, dict[str, Any]]) -> dict[str, list[str]]:
    vocab: dict[str, set[str]] = {}

    def add(category: str, values: Iterable[str]) -> None:
        vocab.setdefault(category, set()).update(values)

    for data in policies.values():
        pg = data.get("postgres") or {}
        add("database", pg.get("dump_databases") or [])
        add("database", pg.get("restore_databases") or {})
        add("database", (pg.get("restore_databases") or {}).values())
        add("prefix", pg.get("temp_file_prefixes") or [])
        add("unit", data.get("units") or [])
        add("path", (p.rstrip("/") for p in data.get("private_media_paths") or []))
        add("path", (r["path"].rstrip("/") for r in data.get("path_roots") or []))
        add("path", data.get("read_files") or [])
        add("path", (s["database"] for s in data.get("sqlite_snapshots") or []))
        add("owner", (r["owner"] for r in data.get("path_roots") or []))
        add("owner", (s["owner"] for s in data.get("sqlite_snapshots") or []))
        add("template", data.get("temp_dirs") or [])
        add("template", (s["temp_dir"] for s in data.get("sqlite_snapshots") or []))
        add("url", data.get("ready_urls") or [])
    # Values no policy lists.
    add("database", ["postgres", "template1", "homepage2"])
    add("prefix", ["mail"])
    add("unit", ["ssh.service", "gotosocial2"])
    add("path", ["/var/lib/postgresql", "/home/marina/site2", "/etc/shadow"])
    add("owner", ["root:root", "postgres:postgres"])
    add("template", ["/var/tmp/other.XXXXXX"])
    add("url", ["http://127.0.0.1:10071/readyz"])
    add("user", ["root", "postgres", "gotosocial", "marina", "nobody"])
    return {category: sorted(values) for category, values in vocab.items()}


def _replace_vocabulary(command: str, vocab: dict[str, list[str]]) -> Iterator[tuple[str, str]]:
    for category, values in vocab.items():
        if category == "user":
            for user in values:
                for flag in ("-u ",):
                    for found in re.finditer(re.escape(flag) + r"([a-z_-]+)", command):
                        yield f"vocab-{category}", command[:found.start(1)] + user + command[found.end(1):]
            continue
        # Longest first, so /var/lib/gotosocial/sqlite.db wins over /var/lib/gotosocial.
        for value in sorted(values, key=len, reverse=True):
            if value not in command:
                continue
            for other in values:
                if other != value:
                    yield f"vocab-{category}", command.replace(value, other)
            break


def _token_edits(command: str) -> Iterator[tuple[str, str]]:
    parts = command.split(" ")
    for i in range(len(parts)):
        yield "drop", " ".join(parts[:i] + parts[i + 1:])
        yield "duplicate", " ".join(parts[:i + 1] + parts[i:])
        if i + 1 < len(parts):
            yield "swap", " ".join(parts[:i] + [parts[i + 1], parts[i]] + parts[i + 2:])
        if _SIMPLE_TOKEN.match(parts[i]):
            for quoted in (f"'{parts[i]}'", f'"{parts[i]}"', f"{parts[i]}''"):
                yield "requote", " ".join(parts[:i] + [quoted] + parts[i + 1:])


def _whitespace_edits(command: str) -> Iterator[tuple[str, str]]:
    yield "whitespace", command.replace(" ", "\t")
    yield "whitespace", command.replace(" ", "\t", 1)
    yield "whitespace", command.replace(" ", "  ")
    yield "whitespace", " " + command
    yield "whitespace", command + " "
    yield "whitespace", "\t" + command
    yield "whitespace", command + "\t"


def _odd_char_edits(command: str, index: int) -> Iterator[tuple[str, str]]:
    last = command.rfind(" ") + 1
    middle = last + max(1, (len(command) - last) // 2)
    # Five of the characters per command, rotating, so every character meets
    # every shape family without multiplying the fixtures by 15.
    for char in (ODD_CHARS[(index * 5 + k) % len(ODD_CHARS)] for k in range(5)):
        yield "char", command + char
        yield "char", command.replace(" ", char, 1)
        yield "char", command[:middle] + char + command[middle:]
    if "a" in command[last:]:
        yield "lookalike", command[:last] + command[last:].replace("a", "\u0430", 1)
    if "/" in command:
        yield "lookalike", command.replace("/", "\uff0f", 1)


def _append_edits(command: str) -> Iterator[tuple[str, str]]:
    for suffix in APPENDS:
        yield "append", f"{command} {suffix}"
        yield "append", f"{command}{suffix}"


def _path_edits(command: str) -> Iterator[tuple[str, str]]:
    for found in _PATH.finditer(command):
        path = found.group(0)
        if path.count("/") < 1:
            continue
        head, _, tail = path.rpartition("/")
        variants = [
            path + "/",
            path + "/.",
            path + "/..",
            f"{head}/./{tail}" if head else f"/./{tail}",
            f"{head}/../{tail}" if head else f"/../{tail}",
            f"{head}//{tail}" if head else f"//{tail}",
            "/" + path,
            f"{head}/x/../{tail}" if head else f"/x/../{tail}",
        ]
        for variant in variants:
            yield "path", command[:found.start()] + variant + command[found.end():]


def mutants(command: str, vocab: dict[str, list[str]], index: int) -> Iterator[tuple[str, str]]:
    yield from _token_edits(command)
    yield from _replace_vocabulary(command, vocab)
    yield from _append_edits(command)
    yield from _whitespace_edits(command)
    yield from _odd_char_edits(command, index)
    yield from _path_edits(command)


def per_tool_commands() -> dict[str, list[tuple[str, str]]]:
    """Hand-made variants per tool: (label, command) for each policy."""
    production: list[tuple[str, str]] = []
    staging: list[tuple[str, str]] = []
    # rsync: each allowed tuple with one option more or fewer, and in other places.
    extras = ("--sender", "--safe-links", "--delete", "--remove-source-files", "-L", "--copy-unsafe-links",
              "-logDtpLre.iLsfxCIvu", "--no-implied-dirs", "--server", ".", "-e.iLsfxCIvu")
    for allowed in sorted(GUARD.RSYNC_SERVER_ARGS):
        options = list(allowed)
        for target, out in (("/home/marina/site/media/", staging), ("/var/lib/gotosocial/storage/", production)):
            out.append(("rsync", " ".join(["rsync", *options, ".", target])))
            for i in range(len(options)):
                out.append(("rsync-fewer", " ".join(["rsync", *options[:i], *options[i + 1:], ".", target])))
            for extra in extras:
                out.append(("rsync-more", " ".join(["rsync", *options, extra, ".", target])))
                out.append(("rsync-more", " ".join(["rsync", extra, *options, ".", target])))
            out.append(("rsync-path", " ".join(["rsync", *options, ".", target.rstrip("/")])))
            out.append(("rsync-path", " ".join(["rsync", *options, ".", target, target])))
            out.append(("rsync-path", " ".join(["rsync", *options, target])))
            out.append(("rsync-path", " ".join(["rsync", *options, "..", target])))
    # scp: other flags and argument counts.
    for flags in ("-r -t", "-p -t", "-d -t", "-t -r", "-r -f", "-p -f", "-d -f", "-v -f", "-f -f", "-t -t", "-pt",
                  "-rt", "-f", "-t", ""):
        staging.append(("scp", f"scp {flags} /home/marina/site/db.sqlite3.tmp".replace("  ", " ")))
        production.append(("scp", f"scp {flags} /var/lib/gotosocial/sqlite.db.restore-tmp".replace("  ", " ")))
    staging.append(("scp", "scp -t /home/marina/site/a.tmp /home/marina/site/b.tmp"))
    staging.append(("scp", "scp -t"))
    staging.append(("scp", "scp"))
    # psql: SQL variants.
    psql = "runuser -u postgres -- psql -X -v ON_ERROR_STOP=1 -qAt -d"
    for sql in (
        "SHOW server_version;", "SHOW server_version", "SHOW server_version; DROP TABLE x;", "show server_version;",
        "SELECT 1 FROM pg_database WHERE datname = 'django_chat_restore_42';",
        "SELECT 1 FROM pg_database WHERE datname = 'django_chat_restore_42'; DROP DATABASE homepage;",
        "SELECT 1 FROM pg_database WHERE datname = 'homepage';",
        "SELECT count(*) FROM public.auth_user;", "SELECT count(*) FROM public.auth_user; DROP TABLE x;",
        "SELECT count(*) FROM auth_user;", "SELECT count(*) FROM public.Auth_user;", "SELECT 1; DROP TABLE x;",
        "SELECT 1", "COPY x TO PROGRAM 'id';", "\\! id",
    ):
        for database in ("django-chat", "postgres", "django_chat_restore_42", "homepage"):
            staging.append(("psql", f"{psql} {database} -c {shlex.quote(sql)}"))
    for sql in ("SELECT 1", "SELECT 1; DROP TABLE x", "SELECT 2", "select 1", "SELECT 1 "):
        staging.append(("psql", f"sudo -u postgres psql -d homepage -c {shlex.quote(sql)}"))
    # sqlite3 .timeout and .backup (PLAN.md 7.1, test_sqlite_backup_runners.py).
    sqlite = "runuser -u gotosocial -- sqlite3 /var/lib/gotosocial/sqlite.db"
    backup = shlex.quote(f".backup '{GTS_TMP}/sqlite.db'")
    for timeout in ("1", "30000", "999999", "0", "1000000", "01", "-1", "30000 ", " 30000", "3e4", "", "30000;"):
        production.append(("sqlite-timeout", f"{sqlite} {shlex.quote('.timeout ' + timeout)} {backup}"))
    production.append(("sqlite-timeout", f"{sqlite} '.timeout  30000' {backup}"))
    production.append(("sqlite-timeout", f"{sqlite} '.timeout' {backup}"))
    production.append(("sqlite-timeout", f"{sqlite} '.timeout 30000'"))
    production.append(("sqlite-timeout", f"{sqlite} '.timeout 30000' 'PRAGMA integrity_check;'"))
    production.append(("sqlite-timeout", f"{sqlite} '.timeout 30000' '.timeout 30000' {backup}"))
    production.append(("sqlite-timeout", f"{sqlite} {backup} '.timeout 30000'"))
    for spec in (f".backup '{GTS_TMP}/sqlite.db'", f".backup {GTS_TMP}/sqlite.db", f'.backup "{GTS_TMP}/sqlite.db"',
                 f".backup main '{GTS_TMP}/sqlite.db'", f".backup '{GTS_TMP}/sub/sqlite.db'",
                 f".backup '{GTS_TMP}/'", ".backup '/var/tmp/gotosocial-echoport.Ab12/sqlite.db'",
                 f".backup  '{GTS_TMP}/sqlite.db'", f".backup '{GTS_TMP}/sqlite.db' ", f".backup '{GTS_TMP}/.db'",
                 f".backup '{GTS_TMP}/-x'", f".backup '{GTS_TMP}/../sqlite.db'", ".backup '/tmp/x.db'",
                 f".backup '{GTS_TMP}/sqlite.db'; .shell id", f".restore '{GTS_TMP}/sqlite.db'"):
        production.append(("sqlite-backup", f"{sqlite} {shlex.quote(spec)}"))
        production.append(("sqlite-backup", f"{sqlite} '.timeout 30000' {shlex.quote(spec)}"))
    # The regex shapes: their groups are split without a guard against
    # unbalanced quotes or escapes.
    tar = f"umask 077 && tar -C /home/python-podcast/site -czf {PP_TMP}/private_media.tar.gz -- private_media"
    for old, new in (("site", "site'"), ("site", 'site"'), ("private_media.tar.gz", "private_media.tar.gz'"),
                     ("-- private_media", "-- 'private_media'"), ("-C /home", "-C '/home"),
                     ("site -czf", "site' -czf"), ("-- private_media", "-- private_media''"),
                     ("tar -C", "tar  -C"), ("umask 077", "umask 0077"), ("-czf", "-cvzf"), ("tar -C", "tar -C -C")):
        production.append(("tar", tar.replace(old, new, 1)))
    cat = f"umask 077 && cat > {CHAT_TMP}/django-chat.dump"
    for old, new in (("> ", "> '"), ("dump", "dump'"), ("> ", ">"), ("cat >", "cat >>"), ("cat", "cat -u"),
                     ("umask 077 && ", "umask 077 &&  ")):
        staging.append(("cat-to-file", cat.replace(old, new, 1)))
    return {"production": production, "staging": staging}


INVALID_UTF8_SUFFIXES = (b"\xff", b"\xc3", b"\xc0\xaf", b"\xed\xa0\x80")


# --- fs (PLAN.md 7.2 item 5) ----------------------------------------------------

FS_BASES: dict[str, list[str]] = {
    "production": [
        f"scp -f /tmp/echoport_pp_dump_{DUMP_STAMP}.dump",
        f"scp -f {PP_TMP}/private_media.tar.gz",
        "scp -f /etc/gotosocial/config.yaml",
        "scp -f /var/lib/gotosocial/.ops-domain-layout",
        "scp -t /var/lib/gotosocial/sqlite.db.restore-tmp",
        f"umask 077 && tar -C /home/python-podcast/site -czf {PP_TMP}/private_media.tar.gz -- private_media",
        f"chown gotosocial:gotosocial {GTS_TMP}",
        "chown -R gotosocial:gotosocial /var/lib/gotosocial/storage",
        "test -f /var/lib/gotosocial/sqlite.db",
        "mv /var/lib/gotosocial/sqlite.db /var/lib/gotosocial/sqlite.db.pre-restore-20261015T020000Z",
        "mv /var/lib/gotosocial/storage.tmp /var/lib/gotosocial/storage",
        "mkdir -p /var/lib/gotosocial/storage",
        "chmod 0600 /var/lib/gotosocial/sqlite.db",
        f"{RSYNC_DOWNLOAD} /var/lib/gotosocial/storage/",
        f"{RSYNC_UPLOAD_DELETE} /var/lib/gotosocial/storage/",
        "rm -f /var/lib/gotosocial/sqlite.db-wal /var/lib/gotosocial/sqlite.db-shm",
    ],
    "staging": [
        f"scp -t /tmp/echoport_homepage_restore_{RESTORE_STAMP}.dump",
        "scp -f /home/marina/site/db.sqlite3",
        "scp -t /home/marina/site/db.sqlite3.tmp",
        "scp -f /home/villakunterbunt/data/db.sqlite3-wal",
        f"{RSYNC_DOWNLOAD} /home/marina/site/media/",
        f"{RSYNC_UPLOAD} /home/marina/site/media/",
        f"{RSYNC_UPLOAD_DELETE} /home/villakunterbunt/data/media/",
        "readlink -f /home/marina/site/db.sqlite3",
        "test -d /home/villakunterbunt/data/media",
        "mv /home/marina/site/db.sqlite3.tmp /home/marina/site/db.sqlite3",
        "mv /home/marina/site/a /home/marina/site/b",
        "mkdir -p /home/marina/site/media",
        "chown -R marina:marina /home/marina/site/media",
        "chmod 0700 /home/marina/site/media",
        f"sha256sum {CHAT_TMP}/django-chat.dump",
        "rm -f /home/marina/site/db.sqlite3-wal /home/marina/site/db.sqlite3-shm",
    ],
}
SERVICE_UID = {"production": USERS["gotosocial"], "staging": USERS["marina"]}


def lstat_states(policy: str) -> list[tuple[str, dict[str, Any]]]:
    me = oracle.DEFAULT_EUID
    states: list[tuple[str, dict[str, Any]]] = []
    for kind, mode in (("reg", 0o600), ("lnk", 0o777), ("fifo", 0o600), ("sock", 0o600), ("chr", 0o600),
                       ("blk", 0o600)):
        states.append((kind, {"kind": kind, "mode": mode, "uid": me, "nlink": 1}))
    states.append(("reg-nlink2", {"kind": "reg", "mode": 0o600, "uid": me, "nlink": 2}))
    for owner, uid in (("other", OTHER_UID), ("postgres", USERS["postgres"]), ("service", SERVICE_UID[policy])):
        states.append((f"reg-{owner}", {"kind": "reg", "mode": 0o600, "uid": uid, "nlink": 1}))
    for mode in (0o700, 0o750, 0o777):
        for owner, uid in (("root", me), ("other", OTHER_UID), ("service", SERVICE_UID[policy])):
            states.append((f"dir-{mode:o}-{owner}", {"kind": "dir", "mode": mode, "uid": uid, "nlink": 2}))
    states.append(("absent", {"absent": True}))
    for name in ("ENOTDIR", "EACCES", "ELOOP"):
        states.append((name.lower(), {"errno": name, "strerror": oracle.STRERROR[name]}))
    return states


def realpath_states(path: str, data: dict[str, Any]) -> list[tuple[str, str]]:
    roots = [r["path"].rstrip("/") for r in data.get("path_roots") or []]
    normal = os.path.normpath(path)
    states = [("outside", "/etc/hostname"), ("tmp", "/tmp/x"), ("slash", "/"), ("deeper", normal + "/sub")]
    for i, root in enumerate(roots):
        states.append((f"root{i}", root))
        states.append((f"root{i}-sibling", root + "evil/x"))
        states.append((f"root{i}-inside", root + "/other"))
    return [(label, value) for label, value in states if value != normal]


def _override(base: Scenario, lstat: dict[str, dict[str, Any]] | None = None,
              realpath: dict[str, str] | None = None) -> Scenario:
    base_lstat = base.lstat or runner_view_lstat
    base_realpath = base.realpath or os.path.normpath

    def lstat_fn(path: str) -> Any:
        if lstat and path in lstat:
            return oracle.decode_lstat(lstat[path])
        return base_lstat(path)

    def realpath_fn(path: str) -> str:
        if realpath and path in realpath:
            return realpath[path]
        return base_realpath(path)

    return Scenario(euid=base.euid, users=dict(base.users), lstat=lstat_fn, realpath=realpath_fn)


# --- policy (PLAN.md 7.2 item 6) ------------------------------------------------

_KNOWN_LISTS = ("units", "private_media_paths", "temp_dirs", "read_files", "ready_urls")
_KNOWN_PG_LISTS = ("dump_databases", "temp_file_prefixes", "scratch_restore_prefixes")
_ENTRY_FIELDS = {"path_roots": ("path", "owner"), "sqlite_snapshots": ("database", "owner", "temp_dir")}


class _Strict:
    def __init__(self) -> None:
        self.tags: set[str] = set()

    def pairs(self, pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        keys = [k for k, _ in pairs]
        if len(keys) != len(set(keys)):
            self.tags.add(P3_POLICY_TYPE)
        return dict(pairs)

    def constant(self, name: str) -> float:
        self.tags.add(P3_POLICY_TYPE)
        return float(name.replace("Infinity", "inf"))

    def number(self, text: str) -> float | int:
        """A number outside the double range (serde_json refuses it, Python keeps inf or the int)."""
        value: float | int = int(text) if re.fullmatch(r"-?[0-9]+", text) else float(text)
        try:
            if math.isinf(float(value)):
                self.tags.add(P3_POLICY_TYPE)
        except OverflowError:
            self.tags.add(P3_POLICY_TYPE)
        return value


def _walk_strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield k
            yield from _walk_strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from _walk_strings(v)


def policy_p3(data: bytes) -> list[str]:
    """The 4.2 classes this policy document falls into (the Rust guard refuses those)."""
    strict = _Strict()
    try:
        text = data.decode("utf-8")
        document = json.loads(text, object_pairs_hook=strict.pairs, parse_constant=strict.constant,
                              parse_float=strict.number, parse_int=strict.number)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return []  # both guards refuse a file that is not JSON
    tags = strict.tags
    for value in _walk_strings(document):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            tags.add(P3_POLICY_TYPE)  # a lone surrogate escape
    if not isinstance(document, dict):
        return sorted(tags)

    def string_list(value: Any) -> bool:
        return value is None or (isinstance(value, list) and all(isinstance(v, str) for v in value))

    def check_strings(values: Iterable[Any]) -> None:
        for value in values:
            if isinstance(value, str) and value.endswith("\n"):
                tags.add(P3_POLICY_NEWLINE)

    postgres = document.get("postgres")
    if postgres is not None and not isinstance(postgres, dict):
        tags.add(P3_POLICY_TYPE)
    elif isinstance(postgres, dict):
        for key in _KNOWN_PG_LISTS:
            if key in postgres:
                if not string_list(postgres[key]):
                    tags.add(P3_POLICY_TYPE)
                else:
                    check_strings(postgres[key] or [])
        if "restore_databases" in postgres:
            restore = postgres["restore_databases"]
            if restore is not None and not (isinstance(restore, dict)
                                            and all(isinstance(v, str) for v in restore.values())):
                tags.add(P3_POLICY_TYPE)
            elif isinstance(restore, dict):
                check_strings(restore)
                check_strings(restore.values())
    for key in _KNOWN_LISTS:
        if key in document:
            if not string_list(document[key]):
                tags.add(P3_POLICY_TYPE)
            else:
                check_strings(document[key] or [])
    for key, fields in _ENTRY_FIELDS.items():
        if key not in document or document[key] is None:
            continue
        entries = document[key]
        if not isinstance(entries, list):
            tags.add(P3_POLICY_TYPE)
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                tags.add(P3_POLICY_TYPE)
                continue
            for name in fields:
                if name in entry and not isinstance(entry[name], str):
                    tags.add(P3_POLICY_TYPE)
                elif name in entry:
                    check_strings([entry[name]])
    return sorted(tags)


def policy_documents(policies: dict[str, dict[str, Any]]) -> list[tuple[str, bytes]]:
    """(label, file bytes) for the --check-policy cases."""
    prod, stage = policies["production"], policies["staging"]
    docs: list[tuple[str, Any]] = [("production", prod), ("staging", stage), ("empty", {})]

    def with_(base: dict[str, Any], **changes: Any) -> dict[str, Any]:
        out = json.loads(json.dumps(base))
        out.update(changes)
        return out

    def pg(**changes: Any) -> dict[str, Any]:
        return {"postgres": changes}

    docs.append(("all-null", {k: None for k in ("postgres", "units", "private_media_paths", "path_roots",
                                                 "temp_dirs", "sqlite_snapshots", "read_files", "ready_urls")}))
    docs.append(("pg-null", pg(dump_databases=None, restore_databases=None, temp_file_prefixes=None,
                               scratch_restore_prefixes=None)))
    docs.append(("all-empty", {"postgres": {"dump_databases": [], "restore_databases": {}, "temp_file_prefixes": [],
                                            "scratch_restore_prefixes": []}, "units": [], "private_media_paths": [],
                               "path_roots": [], "temp_dirs": [], "sqlite_snapshots": [], "read_files": [],
                               "ready_urls": []}))
    docs.append(("unknown-top-key", with_(stage, extra={"anything": [1, 2]})))
    docs.append(("unknown-pg-key", pg(dump_databases=["homepage"], future_key=["x"])))
    docs.append(("unknown-entry-key", {"path_roots": [{"path": "/home/x", "owner": "x:x", "mode": "0700"}]}))
    docs.append(("root-trailing-slash", {"path_roots": [{"path": "/home/x/", "owner": "x:x"}],
                                         "private_media_paths": ["/home/x/media/"]}))
    docs.append(("ordered-roots", {"path_roots": [{"path": "/home/b", "owner": "b:b"},
                                                  {"path": "/home/a", "owner": "a:a"},
                                                  {"path": "/home/b/inner", "owner": "c:c"}]}))
    # Each validator: passes and fails.
    for name in ("homepage", "a", "A0", "x.y@z-1", "db;id", "-x", "a b", "", ".x", "x/y", "\xfc"):
        docs.append((f"dump-db-{name!r}", pg(dump_databases=[name])))
        docs.append((f"restore-db-{name!r}", pg(restore_databases={name: "owner"})))
        docs.append((f"restore-role-{name!r}", pg(restore_databases={"db": name})))
        docs.append((f"unit-{name!r}", {"units": [name]}))
    for prefix in ("pp", "a_1", "0", "../x", "A", "a-b", "", "a b"):
        docs.append((f"temp-prefix-{prefix!r}", pg(temp_file_prefixes=[prefix])))
    for prefix in ("django_chat_restore", "x", "x;y", "1x", "_x", "X", ""):
        docs.append((f"scratch-prefix-{prefix!r}", pg(scratch_restore_prefixes=[prefix])))
    for path in ("/home/x/media", "/home/x", "/tmp", "/", "/home/x/../y", "relative/x", "/home//x", "/home/x/.",
                 "/home/x y", "/home/x;y", "/home/x/", "/home/x//", "//home/x"):
        docs.append((f"media-{path!r}", {"private_media_paths": [path]}))
        docs.append((f"root-{path!r}", {"path_roots": [{"path": path, "owner": "x:x"}]}))
        docs.append((f"read-file-{path!r}", {"read_files": [path]}))
        docs.append((f"sqlite-db-{path!r}", {"sqlite_snapshots": [{"database": path, "owner": "x:x",
                                                                   "temp_dir": "/var/tmp/x.XXXXXX"}]}))
    for owner in ("x:x", "a_b-1:c", "root:root", "root:x", "x:root", "root", "X:x", "x", "x:x:x", "1x:x", "_x:_y",
                  ""):
        docs.append((f"owner-{owner!r}", {"path_roots": [{"path": "/home/x", "owner": owner}]}))
        docs.append((f"sqlite-owner-{owner!r}", {"sqlite_snapshots": [{"database": "/var/lib/x/db", "owner": owner,
                                                                       "temp_dir": "/var/tmp/x.XXXXXX"}]}))
    for template in ("/var/tmp/x.XXXXXX", "/tmp/x.XXXXXXXX", "/var/tmp/x.XXX", "/root/x.XXXXXX", "/srv/x.XXXXXX",
                     "/var/tmp/X.XXXXXX", "/var/tmp/x", "/var/tmp/x.XXXXXXY", "/var/tmp/.x.XXXXXX",
                     "/var/tmp/a-b_c.d.XXXXXX", "/var/tmp/x/y.XXXXXX"):
        docs.append((f"temp-dir-{template!r}", {"temp_dirs": [template]}))
        docs.append((f"sqlite-temp-{template!r}", {"sqlite_snapshots": [{"database": "/var/lib/x/db", "owner": "x:x",
                                                                         "temp_dir": template}]}))
    for url in ("http://127.0.0.1:10070/readyz", "http://127.0.0.1:1/a", "http://127.0.0.1:123456/readyz",
                "http://example.org/readyz", "https://127.0.0.1:10070/readyz", "http://127.0.0.1:10070/ready-z",
                "http://127.0.0.1:10070/Readyz", "http://127.0.0.1/readyz"):
        docs.append((f"ready-url-{url!r}", {"ready_urls": [url]}))
    # Missing entry fields (KeyError in Python).
    docs.append(("root-missing-owner", {"path_roots": [{"path": "/home/x"}]}))
    docs.append(("root-missing-path", {"path_roots": [{"owner": "x:x"}]}))
    docs.append(("sqlite-missing-temp", {"sqlite_snapshots": [{"database": "/var/lib/x/db", "owner": "x:x"}]}))
    # Types Python coerces or accepts and the Rust guard refuses (PLAN.md 4.2).
    docs.append(("type-units-string", {"units": "abc"}))
    docs.append(("type-units-number", {"units": 5}))
    docs.append(("type-units-number-list", {"units": [5]}))
    docs.append(("type-read-files-string", {"read_files": "x"}))
    falsy: Any
    for falsy in (False, 0, "", {}):
        docs.append((f"type-units-falsy-{falsy!r}", {"units": falsy}))
        docs.append((f"type-postgres-falsy-{falsy!r}", {"postgres": falsy}))
        docs.append((f"type-roots-falsy-{falsy!r}", {"path_roots": falsy}))
    docs.append(("type-dump-dbs-number", pg(dump_databases=[1])))
    docs.append(("type-restore-pairs", pg(restore_databases=[["homepage", "homepage"]])))
    docs.append(("type-restore-number", pg(restore_databases={"homepage": 1})))
    docs.append(("type-root-path-number", {"path_roots": [{"path": 5, "owner": "x:x"}]}))
    docs.append(("type-root-entry-string", {"path_roots": ["/home/x"]}))
    docs.append(("type-roots-object", {"path_roots": {"path": "/home/x", "owner": "x:x"}}))
    docs.append(("type-postgres-list", {"postgres": ["homepage"]}))
    docs.append(("type-sqlite-owner-list", {"sqlite_snapshots": [{"database": "/var/lib/x/db", "owner": ["x:x"],
                                                                  "temp_dir": "/var/tmp/x.XXXXXX"}]}))
    top: Any
    for top in ([], "x", 5, None, True):
        docs.append((f"top-{top!r}", top))
    # Trailing newlines (Python's `$` accepts them where it uses re.match).
    docs.append(("newline-unit", {"units": ["x.service\n"]}))
    docs.append(("newline-dump-db", pg(dump_databases=["homepage\n"])))
    docs.append(("newline-role", pg(restore_databases={"db": "role\n"})))
    docs.append(("newline-prefix", pg(temp_file_prefixes=["pp\n"])))
    docs.append(("newline-scratch", pg(scratch_restore_prefixes=["x\n"])))
    docs.append(("newline-media", {"private_media_paths": ["/home/x/media\n"]}))
    docs.append(("newline-root", {"path_roots": [{"path": "/home/x\n", "owner": "x:x"}]}))
    docs.append(("newline-owner", {"path_roots": [{"path": "/home/x", "owner": "x:x\n"}]}))
    docs.append(("newline-template", {"temp_dirs": ["/var/tmp/x.XXXXXX\n"]}))
    docs.append(("newline-read-file", {"read_files": ["/etc/x/y\n"]}))
    docs.append(("newline-url", {"ready_urls": ["http://127.0.0.1:10070/readyz\n"]}))
    docs.append(("newline-sqlite", {"sqlite_snapshots": [{"database": "/var/lib/x/db\n", "owner": "x:x",
                                                          "temp_dir": "/var/tmp/x.XXXXXX"}]}))
    docs.append(("newline-middle", {"units": ["x\ny"]}))
    out: list[tuple[str, bytes]] = [(label, json.dumps(doc).encode("utf-8")) for label, doc in docs]
    # Raw documents: syntax, encoding, duplicates, non-standard JSON.
    out += [
        ("raw-not-json", b"{not json"),
        ("raw-empty-file", b""),
        ("raw-whitespace", b" \n"),
        ("raw-bom", b"\xef\xbb\xbf{}"),
        ("raw-invalid-utf8", b'{"units": ["\xff"]}'),
        ("raw-latin1", '{"units": ["caf\xe9"]}'.encode("latin-1")),
        ("raw-trailing-garbage", b"{} x"),
        ("raw-two-documents", b"{}{}"),
        ("raw-duplicate-top", b'{"units": ["a"], "units": ["b"]}'),
        ("raw-duplicate-restore", b'{"postgres": {"restore_databases": {"a": "a", "a": "b"}}}'),
        ("raw-duplicate-unknown", b'{"extra": 1, "extra": 2}'),
        ("raw-nan-unknown", b'{"extra": NaN}'),
        ("raw-infinity-unit", b'{"units": [Infinity]}'),
        ("raw-lone-surrogate-unknown", b'{"extra": "\\ud800"}'),
        ("raw-lone-surrogate-unit", b'{"units": ["\\udcff"]}'),
        ("raw-escaped-unit", b'{"units": ["\\u0061"]}'),
        ("raw-big-number", b'{"extra": 1e400}'),
        ("raw-big-integer", b'{"extra": 1' + b"0" * 400 + b"}"),
        ("raw-crlf", b'{\r\n"units": ["a"]\r\n}\r\n'),
        ("raw-nul", b'{"units": ["a\\u0000"]}'),
    ]
    return out


def generate_policy_cases(policies: dict[str, dict[str, Any]], unit_policy_texts: list[tuple[str, str]]
                          ) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[bytes] = set()
    # The unit tests' documents first, so a document both list is attributed to its test.
    items = [("unit", label, text.encode("utf-8")) for label, text in unit_policy_texts]
    # GuardMain's documents (process tests, S4).
    for text in ("{not json", "[]", json.dumps({"units": ["a b"]}), json.dumps({"path_roots": [{"path": "/"}]})):
        items.append(("unit", "GuardMain", text.encode("utf-8")))
    items += [("policy", label, data) for label, data in policy_documents(policies)]
    for source, label, data in items:
        if data in seen:
            continue
        seen.add(data)
        try:
            payload: dict[str, Any] = {"policy_text": data.decode("utf-8")}
            json.dumps(payload, ensure_ascii=False).encode("utf-8")
        except (UnicodeDecodeError, UnicodeEncodeError):
            payload = {"policy_hex": data.hex()}
        row: dict[str, Any] = {
            "id": f"{source}/{label}/{short_hash(data.hex())}",
            "source": source,
            **payload,
            "expected": oracle.check_policy_bytes(data),
        }
        p3 = policy_p3(data)
        if p3:
            row["p3"] = p3
        rows.append(row)
    return rows


def load_policies(base: Path) -> dict[str, dict[str, Any]]:
    return {name: json.loads((base / "policies" / f"{name}.json").read_text(encoding="utf-8"))
            for name in ("production", "staging")}


def generate(out: Path, inputs: Path) -> dict[str, int]:
    policies_json = load_policies(inputs)
    policies = {name: GUARD.Policy.from_dict(data) for name, data in policies_json.items()}
    runner_corpus = read_jsonl(inputs / "corpus" / "runner.jsonl")
    unit_corpus = read_jsonl(inputs / "corpus" / "unit.jsonl")
    sources = {name: Cases(name, policies) for name in SOURCES}

    for entry in runner_corpus:
        sources["runner"].add(entry["test"], entry["policy"], entry["command"], runner_view(), expect="allowed")
    for policy, commands in JOURNAL.items():
        for command in commands:
            sources["journal"].add("live", policy, command, runner_view(),
                                   expect="refused" if command in JOURNAL_REFUSED else "allowed")
    unit_policy_texts: list[tuple[str, str]] = []
    for entry in unit_corpus:
        if entry["kind"] == "policy":
            unit_policy_texts.append((entry["test"], entry["policy_text"]))
            continue
        sources["unit"].add(entry["test"], entry["policy"], entry["command"], Scenario.from_env(entry["env"]),
                            expect=entry["outcome"])

    # Mutations of every accepted command, against the base's policy.
    vocab = _vocabulary(policies_json)
    bases: list[tuple[str, str]] = []
    for name in ("runner", "journal", "unit"):
        for row in sources[name].rows:
            pair = (row["policy"], row["command"])
            if row["expected"]["verdict"] == "allowed" and pair not in bases:
                bases.append(pair)
    mutation = sources["mutation"]
    other = {"production": "staging", "staging": "production"}
    for index, (policy, command) in enumerate(bases):
        mutation.add("cross-host", other[policy], command, runner_view())
        base_expected, _ = oracle.run_check(policies[policy], command, runner_view())
        for op, mutant in mutants(command, vocab, index):
            mutation.add(op, policy, mutant, runner_view())
            # Quoting and whitespace between plain tokens never change a decision
            # (the regex shapes `umask 077 && ...` match the raw string instead).
            if op in ("requote", "whitespace") and not command.startswith("umask ") and not any(
                    q in command for q in "'\""):
                got, _ = oracle.run_check(policies[policy], mutant, runner_view())
                if got != base_expected:
                    raise GeneratorError(f"{op} changed the decision of {command!r}: {mutant!r} -> {got}")
    for policy, labelled in per_tool_commands().items():
        for label, command in labelled:
            mutation.add(label, policy, command, runner_view())
    for policy, command in bases[:3] + [b for b in bases if b[1].startswith("umask ")][:1]:
        for length in (MAX - 1, MAX, MAX + 1):
            for pad in (" ", "\t"):
                mutation.add(f"length-{length}", policy, command + pad * (length - len(command)), runner_view(),
                             expect="refused" if length > MAX else None)
        mutation.add("length-non-ascii", policy, command + " " * (MAX - 1 - len(command)) + "\xe9", runner_view())
        for suffix in INVALID_UTF8_SUFFIXES:
            data = command.encode("utf-8")
            mutation.add("invalid-utf8", policy, data + suffix, runner_view(), expect="refused")
            mutation.add("invalid-utf8", policy, data[:5] + suffix + data[5:], runner_view(), expect="refused")
    for policy in policies:
        for command in ("", " ", "\t", "a\nb", "a\rb", "a\0b", "''", "'", '"', "\\", "#", "x" * (MAX + 1)):
            mutation.add("edge", policy, command, runner_view())

    # Filesystem states for every path a shape looks at.
    fs = sources["fs"]
    for policy, fs_commands in FS_BASES.items():
        for command in fs_commands:
            base_row = fs.add("base", policy, command, runner_view())
            assert base_row is not None
            for path in base_row["env"]["lstat"]:
                for label, entry in lstat_states(policy):
                    fs.add(f"lstat-{label}", policy, command, _override(runner_view(), lstat={path: entry}))
            for path in base_row["env"]["realpath"]:
                for label, resolved in realpath_states(path, policies_json[policy]):
                    fs.add(f"realpath-{label}", policy, command, _override(runner_view(), realpath={path: resolved}))

    for stale in generated_files(out):
        (out / stale).unlink()
    files: dict[str, list[dict[str, Any]]] = {}
    for name, cases in sources.items():
        if name == "mutation":
            for row in cases.rows:
                files.setdefault(f"mutation/{mutation_file(row['id'].split('/')[1])}.jsonl", []).append(row)
        else:
            files[f"{name}.jsonl"] = cases.rows
    files["policy.jsonl"] = generate_policy_cases(policies_json, unit_policy_texts)
    counts = {name: write_jsonl(out / name, rows) for name, rows in sorted(files.items())}
    all_rows = [row for rows in files.values() for row in rows]
    if len({row["id"] for row in all_rows}) != len(all_rows):
        raise GeneratorError("duplicate case ids")
    for name in counts:
        if (out / name).stat().st_size > MAX_FILE_BYTES:
            raise GeneratorError(f"{name} is larger than the repository's 1000 KB file limit; split it")
    (out / "GUARD_SHA256").write_text(oracle.guard_sha256() + "\n", encoding="utf-8")
    decisions = [row for name, rows in files.items() if name != "policy.jsonl" for row in rows]
    manifest = {
        "guard": str(oracle.GUARD_PATH.relative_to(oracle.REPO)),
        "guard_sha256": oracle.guard_sha256(),
        "decision_files": sorted(name for name in counts if name != "policy.jsonl"),
        "policy_files": ["policy.jsonl"],
        "cases": counts,
        "total": sum(counts.values()),
        "accepted": {name: sum(1 for row in rows if row.get("expected", {}).get("verdict") == "allowed")
                     for name, rows in sorted(files.items()) if name != "policy.jsonl"},
        "p3": {tag: sum(1 for row in all_rows if tag in row.get("p3", []))
               for tag in (P3_PREFILTER, P3_INVALID_UTF8, P3_PYTHON_ERROR, P3_POLICY_TYPE, P3_POLICY_NEWLINE)},
        "decisions": len(decisions),
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return counts


def mutation_file(label: str) -> str:
    """The file under fixtures/mutation/ a mutation case goes to (each stays under 1000 KB)."""
    if label in ("drop", "duplicate", "swap"):
        return "tokens"
    if label.startswith("vocab-") or label == "cross-host":
        return "vocabulary"
    if label in ("char", "lookalike"):
        return "characters"
    if label.startswith("length-") or label in ("invalid-utf8", "edge"):
        return "edges"
    if label in ("requote", "append", "whitespace", "path"):
        return {"path": "paths"}.get(label, label)
    return "tools"


# --- drift check ----------------------------------------------------------------

MAX_FILE_BYTES = 1000 * 1024  # .pre-commit-config.yaml check-added-large-files
RECORDED_DIRS = ("corpus", "policies")


def _files(base: Path) -> list[str]:
    return sorted(str(p.relative_to(base)) for p in base.rglob("*") if p.is_file())


def generated_files(base: Path) -> list[str]:
    """What `generate` writes (everything but the recorded inputs)."""
    if not base.exists():
        return []
    return [name for name in _files(base) if name.split("/", 1)[0] not in RECORDED_DIRS]


def check(with_record: bool) -> int:
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        inputs = FIXTURES
        if with_record:
            record(work)
            inputs = work
        generate(work, inputs)
        expected = _files(FIXTURES) if with_record else generated_files(FIXTURES)
        actual = _files(work)
        drift = sorted(set(expected) ^ set(actual))
        drift += [name for name in sorted(set(expected) & set(actual))
                  if not filecmp.cmp(FIXTURES / name, work / name, shallow=False)]
    if drift:
        print("fixture drift (regenerate with `just echoport-command-guard-fixtures`): " + ", ".join(drift),
              file=sys.stderr)
        return 1
    print(f"fixtures match ({len(actual)} files, Python {'.'.join(map(str, sys.version_info[:3]))})")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("record", help="record the test policies and corpus (repo venv)")
    sub.add_parser("generate", help="generate the fixtures from the recorded inputs (stdlib)")
    sub.add_parser("all", help="record, then generate")
    check_parser = sub.add_parser("check", help="fail on any drift from the committed fixtures")
    check_parser.add_argument("--record", action="store_true", help="also re-record the corpus (repo venv)")
    args = parser.parse_args(argv)
    try:
        if args.cmd in ("record", "all"):
            record(FIXTURES)
        if args.cmd in ("generate", "all"):
            counts = generate(FIXTURES, FIXTURES)
            print(json.dumps(counts))
        if args.cmd == "check":
            return check(args.record)
    except GeneratorError as exc:
        print(f"gen_fixtures: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
