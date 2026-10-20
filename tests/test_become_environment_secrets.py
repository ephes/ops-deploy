"""No secrets or check payloads in the environment or arguments of commands run as another user.

Deploys connect as root and drop privileges per command with
``runuser -u <user> -- env NAME=value ... <argv>`` (``helpers.python._as_user``,
``graphyard._common.runuser`` and the callers that spell it out). The whole
command, assignments included, is the argument list of the remote shell, of
``runuser`` and of ``env``: every local user can read it from
``/proc/<pid>/cmdline`` (``ps``) while it runs, pyinfra prints it in debug
output and failure reports, and the values then sit in the target process's
``/proc/<pid>/environ``. pyinfra's ``_env`` global argument is no better: it
prefixes ``export NAME=value &&`` to the command. ``_sudo``/``_su_user`` are
banned in ``test_policy.py`` (sudo also logs the command).

Secrets therefore travel on stdin (``secret_stdin``, ``probe(..., stdin=...)``)
or in a root-only 0600 file (``secret_file``); a host script may read them
there and export them to its own child, which keeps them off every command
line. As in the ops-control and ops-library guards of the same name,
structured payloads count as secret: environment names ending in ``_JSON``,
``_DATA`` or ``_SPEC`` (Nyxmon check data can carry a monitor login without a
secret-looking name).

Scanned:

- Python sources: no ``_env`` keyword argument anywhere. In every function
  that builds a command run as another user (it spells ``runuser`` itself or
  calls, at any depth, a function that does), no dict literal outside a stdin or secret-file
  builder has a secret-looking or payload key, and no string starts with an
  assignment of such a name (an ``env`` argv word).
- Python string constants and the shell and template sources: no
  ``env NAME=``, ``docker exec -e NAME``, ``systemd-run --setenv=NAME`` or
  ``sudo``/``su``/``runuser``/``setpriv``/``doas`` command with a ``NAME=``
  assignment of such a name.

The per-service tests complement this with the fixture secrets: a secret
value never appears in any recorded command (``FakeRun.all_text()``).
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator
from pathlib import Path

import pytest

PACKAGE = Path(__file__).resolve().parents[1] / "src" / "ops_deploy"
PYTHON_SOURCES = sorted(PACKAGE.rglob("*.py"))
SHELL_SOURCES = sorted(path for path in PACKAGE.rglob("*") if path.suffix in {".sh", ".j2"})

# Environment variable names that hold secrets.
SECRET_ENV_NAME = re.compile(
    r"(SECRET|SECRET_KEY|ACCESS_KEY|PASSWORD|PASSWD|TOKEN|API_KEY|AUTH|SIGNING_KEYS?|PRIVATE_KEY"
    r"|DATABASE_URL|DSN|CREDENTIALS?)$"
)
# Environment variable names that carry structured payloads.
PAYLOAD_ENV_NAME = re.compile(r"_(JSON|DATA|SPEC)$")
ENV_NAME = re.compile(r"^[A-Z_][A-Z0-9_]*$")
# Calls whose arguments are stdin or secret-file content, never an environment.
CONTENT_BUILDERS = frozenset({"SecretContent", "stdin_env", "_stdin_env", "_stdin_lines", "payload"})
# Operations whose ``content`` (second positional) argument is stdin or file content;
# their other arguments, the command above all, are scanned.
CONTENT_OPERATIONS = frozenset({"secret_stdin", "secret_file"})
SWITCH_WORDS = frozenset({"runuser", "sudo", "su", "setpriv", "doas"})

_NAME = r"[A-Za-z_][A-Za-z0-9_]*"
_ENV_COMMAND = re.compile(r"(?:^|[\s;&|(`\"'\[/])env\s+((?:-\S+\s+)*(?:\"?" + _NAME + r"=\S*\s+)*)")
_ASSIGNMENT = re.compile(r"\"?(" + _NAME + r")=")
_LEADING_ASSIGNMENT = re.compile(r"^(" + _NAME + r")=")
# One simple command: from its program word to the next command separator.
_DOCKER_EXEC = re.compile(r"\bdocker\s+(?:compose\s+)?exec\b[^\n;|&]*")
_DOCKER_ENV = re.compile(r"\s(?:-e|--env)(?:\s+|=)\"?(" + _NAME + ")")
_SYSTEMD_RUN = re.compile(r"\bsystemd-run\b[^\n;|&]*")
_SETENV = re.compile(r"--setenv(?:\s+|=)\"?(" + _NAME + ")")
_SHORT_SETENV = re.compile(r"\s-E\s*\"?(" + _NAME + ")")
_SWITCH = re.compile(r"\b(?:sudo|su|runuser|setpriv|doas)\s[^\n;|&]*")
_SWITCH_ASSIGNMENT = re.compile(r"(?<![\w-])[\"']?(" + _NAME + r")=")

# (path relative to src/ops_deploy, variable name) -> why it is not a secret.
# Keep empty unless a finding is provably not a secret.
ALLOWED: dict[tuple[str, str], str] = {}


def forbidden(name: str) -> bool:
    return bool(SECRET_ENV_NAME.search(name) or PAYLOAD_ENV_NAME.search(name))


def shell_assignments(text: str) -> list[str]:
    """Names assigned in the argv of ``env``, ``docker exec -e``, ``systemd-run`` or a user switch."""

    names = []
    for match in _ENV_COMMAND.finditer(text):
        names += _ASSIGNMENT.findall(match.group(1))
    names += _SETENV.findall(text)
    for command, options in (
        (_DOCKER_EXEC, (_DOCKER_ENV,)),
        (_SYSTEMD_RUN, (_SHORT_SETENV,)),
        (_SWITCH, (_SWITCH_ASSIGNMENT,)),
    ):
        for segment in command.findall(text):
            for option in options:
                names += option.findall(segment)
    return names


def _called(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def _spells_a_switch(function: ast.AST) -> bool:
    for node in ast.walk(function):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            words = node.value.split()
            if words and words[0] in SWITCH_WORDS:
                return True
    return False


def _functions(tree: ast.AST) -> Iterator[ast.FunctionDef | ast.AsyncFunctionDef]:
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            yield node


def switch_builders(trees: dict[str, ast.AST]) -> set[str]:
    """Names of the functions that spell out a user switch (``runuser -u ...``) or call one that does.

    Matched by name across the package, so a same-named function elsewhere is
    scanned too; that only widens the scan.
    """

    functions = [function for tree in trees.values() for function in _functions(tree)]
    builders = {function.name for function in functions if _spells_a_switch(function)}
    calls = {id(f): {_called(n) for n in ast.walk(f) if isinstance(n, ast.Call)} for f in functions}
    while True:
        grown = builders | {function.name for function in functions if calls[id(function)] & builders}
        if grown == builders:
            return builders
        builders = grown


def _dicts_of_content(node: ast.AST) -> Iterator[ast.Dict]:
    """Dicts that are part of a content value: never those inside a call that builds something else."""

    if isinstance(node, ast.Call) and _called(node) not in CONTENT_BUILDERS:
        return
    if isinstance(node, ast.Dict):
        yield node
    for child in ast.iter_child_nodes(node):
        yield from _dicts_of_content(child)


def _content_dicts(function: ast.AST) -> set[int]:
    inside: set[int] = set()
    for node in ast.walk(function):
        if not isinstance(node, ast.Call):
            continue
        name = _called(node)
        values: list[ast.AST] = []
        if name in CONTENT_BUILDERS:
            values = [*node.args, *(keyword.value for keyword in node.keywords)]
        elif name in CONTENT_OPERATIONS:
            values = [*node.args[1:2], *(keyword.value for keyword in node.keywords if keyword.arg == "content")]
        for value in values:
            inside |= {id(found) for found in _dicts_of_content(value)}
    return inside


def environment_findings(tree: ast.AST, builders: set[str]) -> list[tuple[int, str]]:
    """(line, name) of secret or payload keys in environments of user-switched commands."""

    found: list[tuple[int, str]] = []
    seen: set[tuple[int, str]] = set()
    for function in _functions(tree):
        if function.name not in builders:
            continue
        content = _content_dicts(function)
        names: list[tuple[int, str]] = []
        for node in ast.walk(function):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                names += [(node.lineno, name) for name in _LEADING_ASSIGNMENT.findall(node.value)]
            if isinstance(node, ast.Dict) and id(node) not in content:
                names += [
                    (key.lineno, key.value)
                    for key in node.keys
                    if isinstance(key, ast.Constant) and isinstance(key.value, str) and ENV_NAME.match(key.value)
                ]
        for line, name in names:
            if forbidden(name) and (line, name) not in seen:
                seen.add((line, name))
                found.append((line, name))
    return found


def env_keyword_findings(tree: ast.AST) -> list[int]:
    return [node.lineno for node in ast.walk(tree) if isinstance(node, ast.keyword) and node.arg == "_env"]


def string_constants(tree: ast.AST) -> Iterator[tuple[int, str]]:
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            yield node.lineno, node.value
        elif isinstance(node, ast.JoinedStr):
            # The literal parts with a placeholder for each value, so a value cannot hide a name.
            text = "".join(str(part.value) if isinstance(part, ast.Constant) else "X" for part in node.values)
            yield node.lineno, text


def text_findings(text: str) -> list[str]:
    return sorted({name for name in shell_assignments(text) if forbidden(name)})


def _relative(path: Path) -> str:
    return str(path.relative_to(PACKAGE))


def _trees() -> dict[str, ast.AST]:
    return {_relative(path): ast.parse(path.read_text(), filename=str(path)) for path in PYTHON_SOURCES}


def package_findings() -> list[tuple[str, str, str]]:
    """(file, name, problem) for every offending place in the package."""

    trees = _trees()
    builders = switch_builders(trees)
    problems: list[tuple[str, str, str]] = []
    for relative, tree in trees.items():
        for line in env_keyword_findings(tree):
            problems.append((relative, "_env", f"line {line}: pyinfra _env puts values on the command line"))
        for line, name in environment_findings(tree, builders):
            problems.append((relative, name, f"line {line}: in the environment of a user-switched command"))
        for line, text in string_constants(tree):
            for name in text_findings(text):
                problems.append((relative, name, f"line {line}: assigned on a command line"))
    for path in SHELL_SOURCES:
        for number, source_line in enumerate(path.read_text().splitlines(), start=1):
            for name in text_findings(source_line):
                problems.append((_relative(path), name, f"line {number}: assigned on a command line"))
    return problems


def test_no_secret_or_payload_reaches_a_command_line_or_a_switched_environment() -> None:
    offending = []
    seen_allowed = set()
    for relative, name, problem in package_findings():
        if (relative, name) in ALLOWED:
            seen_allowed.add((relative, name))
            continue
        offending.append(f"{relative}: {name}: {problem}")
    assert offending == []
    assert set(ALLOWED) - seen_allowed == set(), "stale allowlist entries"


def test_the_user_switching_builders_are_found() -> None:
    # Discovery must keep seeing the helpers every deploy uses, or the scan goes blind.
    builders = switch_builders(_trees())
    assert {"_as_user", "runuser", "_nyxmon_command", "site_checks_command", "_psql"} <= builders
    assert len(SHELL_SOURCES) > 5


STUBS = """
def _as_user(user, home, env, argv):
    return shlex.join(["runuser", "-u", user, "--", "env", *argv])

def runuser(user, argv, *, env=None):
    return shlex.join(["runuser", "-u", user, "--", *argv])

def _site_shell(cfg, script):
    return _as_user(cfg.user, cfg.home, {}, ["sh", "-c", script])
"""

LEAKING = (
    STUBS
    + """
def a(cfg):
    return shlex.join(["runuser", "-u", cfg.user, "--", "env", "X_TOKEN=" + t, "python3"])

def b(cfg):
    env = {"NYXMON_DB_PATH": "/db", "NYXMON_CHECKS_JSON": checks}
    return _as_user("nyxmon", home, env, ["python3"])

def c(cfg):
    return runuser(cfg.user, ["manage.py"], env={"HOME": "/h", "ADMIN_PASSWORD": p})

def d(cfg):
    def command(apply):
        return _as_user(cfg.user, home, {**env, "METRIC_SPEC": spec}, argv)
    return command(True)

def e(cfg):
    server.shell(commands=["x"], _env={"HOME": "/h"})

def f(cfg):
    secret_stdin(command=_as_user(cfg.user, home, {"HOME": "/h", "API_TOKEN": t}, argv), content=SecretContent(x))

def g(cfg):
    secret_stdin(_site_shell(cfg, x), _stdin_env({"A": _as_user(u, h, {"SIGNING_KEY_DATA": k}, argv)}))
"""
)


def test_the_guard_catches_each_python_leak_shape() -> None:
    tree = ast.parse(LEAKING)
    builders = switch_builders({"x": tree})
    assert {"a", "b", "c", "d", "command", "f", "g"} <= builders
    assert "e" not in builders
    names = {name for _, name in environment_findings(tree, builders)}
    assert names == {"X_TOKEN", "NYXMON_CHECKS_JSON", "ADMIN_PASSWORD", "METRIC_SPEC", "API_TOKEN", "SIGNING_KEY_DATA"}
    assert len(env_keyword_findings(tree)) == 1


@pytest.mark.parametrize(
    ("text", "name"),
    [
        ("runuser -u app -- env HOME=/h DJANGO_SECRET_KEY=$k python3", "DJANGO_SECRET_KEY"),
        ('as_postgres env "PGPASSWORD=$pw" pg_dump', "PGPASSWORD"),
        ("docker exec -e INFLUX_TOKEN=$t influx ping", "INFLUX_TOKEN"),
        ("docker compose exec --env=GRAFANA_PASSWORD app true", "GRAFANA_PASSWORD"),
        ("systemd-run --uid=app --setenv=HA_TOKEN=$t x", "HA_TOKEN"),
        ("systemd-run -E CHECK_DATA=$d x", "CHECK_DATA"),
        ("sudo -u app API_KEY=$k ./run", "API_KEY"),
        ("su app -c 'REDISCLI_AUTH=$a redis-cli'", "REDISCLI_AUTH"),
        ("ExecStart=/usr/bin/env SERVICE_CREDENTIALS=x /bin/app", "SERVICE_CREDENTIALS"),
        # A harmless assignment or option first must not hide the secret one.
        ("docker exec -e HOME=/h -e API_TOKEN=x app true", "API_TOKEN"),
        ("docker exec -i -e HOME=/h --env GRAFANA_PASSWORD app true", "GRAFANA_PASSWORD"),
        ("systemd-run -E HOME=/h -E CHECK_DATA=x true", "CHECK_DATA"),
        ("systemd-run --setenv=HOME=/h --setenv=HA_TOKEN=x true", "HA_TOKEN"),
        ("sudo -u app HOME=/h API_TOKEN=x true", "API_TOKEN"),
        ("runuser -u app -- env HOME=/h -- LANG=C METRIC_SPEC=x true", "METRIC_SPEC"),
    ],
)
def test_the_guard_catches_each_shell_leak_shape(text: str, name: str) -> None:
    assert text_findings(text) == [name]


SAFE = (
    STUBS
    + """
def a(cfg):
    env = {"NYXMON_DB_PATH": str(cfg.db), "NYXMON_SERVICE_NAME": cfg.name}
    secret_stdin(command=_as_user("nyxmon", home, env, ["python3"]), content=SecretContent(checks))

def b(cfg):
    content = _stdin_env({**env, "CHESSLAB_ADMIN_PASSWORD": p})
    secret_stdin(command=_site_shell(cfg, script), content=_stdin_env({"ADMIN_PASSWORD": p}))

def rendered(cfg):
    # Not a user-switched command: an env file's content.
    return {"DJANGO_SECRET_KEY": key, "WEEKNOTES_HOME_API_TOKEN": token}
"""
)


def test_the_guard_accepts_safe_shapes() -> None:
    tree = ast.parse(SAFE)
    builders = switch_builders({"x": tree})
    assert {"a", "b"} <= builders
    assert environment_findings(tree, builders) == []
    for text in [
        "IFS= read -r GRAPHYARD_BOOTSTRAP_PASSWORD; export GRAPHYARD_BOOTSTRAP_PASSWORD; exec manage.py",
        'IFS= read -r REDISCLI_AUTH && export REDISCLI_AUTH && [ "$(redis-cli PING)" = PONG ]',
        '[ -n "$PGPW" ] && export PGPASSWORD="$PGPW"',
        'passfile_env=(env "PGPASSFILE=$pgpass_dir/pgpass")',
        "runuser -u nyxmon -- env HOME=/home/nyxmon NYXMON_DB_PATH=/db python3 -I -c x check",
        "docker exec -i grafana grafana cli admin reset-admin-password --password-from-stdin",
        "# runuser keeps the environment apart from HOME, SHELL, USER and LOGNAME.",
    ]:
        assert text_findings(text) == [], text
