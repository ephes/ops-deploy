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

"At any depth" follows calls by function name within one program
(``switch_builders``). The package is one program: its modules plus every
host script one of them imports or loads as a module, all of them seeing all
of its names. Each other host script (``files/*.py``, uploaded by a deploy
and run by the host on its own) is a program of its own, which sees the
package only if it imports it. So a package module that loads a host script
still reaches that script's user switch (and the script the package's),
while a name two separate programs merely share (``run``, ``update``) links
nothing. A load by a module loader (``importlib``, ``runpy``, ``exec``; under
any name it is imported or assigned as) is followed through the script's
name in a string of the loading file; a file whose loader names no host
script must be listed in ``LOADS_NO_HOST_SCRIPT`` with what it loads
instead. Not followed, as before: a function passed as a value and called
under another name (an injected runner).

The per-service tests complement this with the fixture secrets: a secret
value never appears in any recorded command (``FakeRun.all_text()``).
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterable, Iterator
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
# Calls that load a Python file or module by a path or name given at run time.
MODULE_LOADERS = frozenset(
    {
        "spec_from_file_location",
        "spec_from_loader",
        "find_spec",
        "module_from_spec",
        "exec_module",
        "load_module",
        "SourceFileLoader",
        "SourcelessFileLoader",
        "load_source",
        "import_module",
        "__import__",
        "resolve_name",
        "importfile",
        "run_path",
        "run_module",
        "exec",
        "eval",
    }
)

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
# Path relative to src/ops_deploy -> what its module loader loads instead of a host script under files/.
LOADS_NO_HOST_SCRIPT: dict[str, str] = {
    "infra/traefik_tx/retention.py": "engine.py next to it (infra/traefik_tx/engine.py, a package module)",
    "infra/traefik_tx/runner.py": "the staged copy of infra/traefik_tx/engine.py (a package module)",
    "services/fastdeploy/files/ensure_token_user.py": "FastDeploy's own commands.py in the site directory",
}


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


def _host_script(relative: str) -> bool:
    """A program under a ``files/`` directory: a deploy uploads it and the host runs it on its own."""

    return "files" in Path(relative).parts[:-1]


def _module(relative: str) -> str:
    """``base/files/x.py`` -> ``ops_deploy.base.files.x``; ``base/__init__.py`` -> ``ops_deploy.base``."""

    parts = Path(relative).with_suffix("").parts
    return ".".join(("ops_deploy", *(parts[:-1] if parts[-1] == "__init__" else parts)))


def _imported(relative: str, tree: ast.AST) -> set[str]:
    """Every module an import in ``relative`` may name, relative imports resolved (``from a import b``: a, a.b)."""

    package = _module(relative).split(".")
    if not relative.endswith("__init__.py"):
        package = package[:-1]
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names |= {alias.name for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                base = ".".join([*package[: max(0, len(package) + 1 - node.level)], *([base] if base else [])])
            names |= {base} | {f"{base}.{alias.name}" for alias in node.names}
    return names


def _uses_a_loader(tree: ast.AST) -> bool:
    """Whether ``tree`` calls a module loader, imports one (also under another name) or takes one as a value."""

    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in MODULE_LOADERS:
            return True
        if isinstance(node, ast.Attribute) and node.attr in MODULE_LOADERS:
            return True
        if isinstance(node, ast.ImportFrom) and any(alias.name in MODULE_LOADERS for alias in node.names):
            return True
    return False


def _named(tree: ast.AST, scripts: Iterable[str]) -> set[str]:
    """The host scripts a string in ``tree`` names (``"x.py"``, ``".../files/x.py"``, ``"ops_deploy....files.x"``)."""

    words = {word for _, text in string_constants(tree) for word in re.findall(r"\w+", text)}
    return {script for script in scripts if Path(script).stem in words}


def _links(trees: dict[str, ast.AST]) -> dict[str, set[str]]:
    """Per file, the other files whose functions it can call by name.

    The modules it imports by their full name. A host script also through an
    import by a bare or partial name (``import x`` next to it, ``from files
    import x``), and through a module loader (``spec_from_file_location``,
    ``import_module``, ``run_path``, ...) in a file that names the script.
    """

    modules = {_module(relative): relative for relative in trees}
    scripts = {relative: _module(relative) for relative in trees if _host_script(relative)}
    links: dict[str, set[str]] = {}
    for relative, tree in trees.items():
        imported = _imported(relative, tree)
        found = {modules[name] for name in imported if name in modules}
        found |= {script for script, module in scripts.items() if any(module.endswith(f".{n}") for n in imported)}
        if _uses_a_loader(tree):
            found |= _named(tree, scripts)
        links[relative] = found - {relative}
    return links


def switch_builders(trees: dict[str, ast.AST]) -> dict[str, set[str]]:
    """Per file, the names of the functions that spell out a user switch (``runuser -u ...``) or call one that does.

    Calls are matched by name, so a same-named function is scanned too; that
    only widens the scan. A file sees the names of every file it reaches
    through ``_links``; a package module (outside ``files/``) also reaches
    every package module, so the package and every host script it imports or
    loads form one program, and each of its files sees all of its names. Any
    other host script sees its own names and those of what it imports or
    loads (the whole package's once that reaches a package module); its own
    names reach other files only through such a link.
    """

    package = {relative for relative in trees if not _host_script(relative)}
    links = _links(trees)

    def reach(start: set[str]) -> set[str]:
        reached: set[str] = set()
        new = set(start)
        while new:
            reached |= new
            new = set[str]().union(*(links[relative] for relative in new), package if new & package else ()) - reached
        return reached

    shared = reach(package)
    sees = {relative: shared if relative in shared else reach({relative}) for relative in trees}
    functions = {relative: list(_functions(tree)) for relative, tree in trees.items()}
    calls = {
        id(function): {_called(node) for node in ast.walk(function) if isinstance(node, ast.Call)}
        for found in functions.values()
        for function in found
    }
    builders = {relative: {f.name for f in functions[relative] if _spells_a_switch(f)} for relative in trees}
    while True:
        names = set[str]().union(*(builders[relative] for relative in shared))
        scopes = {
            relative: names if sees[relative] is shared else set[str]().union(*(builders[r] for r in sees[relative]))
            for relative in trees
        }
        grown = {
            relative: builders[relative] | {f.name for f in functions[relative] if calls[id(f)] & scopes[relative]}
            for relative in trees
        }
        if grown == builders:
            return scopes
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


def python_findings(trees: dict[str, ast.AST]) -> list[tuple[str, str, str]]:
    """(file, name, problem) for every offending place in Python sources keyed by their path under the package."""

    scopes = switch_builders(trees)
    problems: list[tuple[str, str, str]] = []
    for relative, tree in trees.items():
        for line in env_keyword_findings(tree):
            problems.append((relative, "_env", f"line {line}: pyinfra _env puts values on the command line"))
        for line, name in environment_findings(tree, scopes[relative]):
            problems.append((relative, name, f"line {line}: in the environment of a user-switched command"))
        for line, text in string_constants(tree):
            for name in text_findings(text):
                problems.append((relative, name, f"line {line}: assigned on a command line"))
    return problems


def package_findings() -> list[tuple[str, str, str]]:
    """(file, name, problem) for every offending place in the package."""

    problems = python_findings(_trees())
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
    scopes = switch_builders(_trees())
    assert {"_as_user", "runuser", "_nyxmon_command", "site_checks_command", "_psql"} <= scopes["helpers/python.py"]
    # A host script that switches users itself is scanned in its own scope.
    assert "config_test" in scopes["base/files/stale_exe_restart.py"]
    assert len(SHELL_SOURCES) > 5


def test_every_module_loader_names_its_host_script_or_is_listed() -> None:
    # The scan follows a load by a module loader only through the host script's name in the loading file.
    trees = _trees()
    scripts = [relative for relative in trees if _host_script(relative)]
    unnamed = {relative for relative, tree in trees.items() if _uses_a_loader(tree) and not _named(tree, scripts)}
    assert unnamed == set(LOADS_NO_HOST_SCRIPT)


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
    builders = switch_builders({"x": tree})["x"]
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
    builders = switch_builders({"x": tree})["x"]
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


def _scan(files: dict[str, str]) -> set[tuple[str, str]]:
    """(file, name) of every finding in sources keyed by their path under the package."""

    trees: dict[str, ast.AST] = {relative: ast.parse(source) for relative, source in files.items()}
    return {(relative, name) for relative, name, _ in python_findings(trees)}


# A host script that switches users itself (run -> evaluate -> config_test), as base/files/stale_exe_restart.py does.
HOST_SWITCH = """
def config_test(unit):
    return subprocess.run(["runuser", "-u", unit.user, "--", unit.exe, "-t"], check=False)

def evaluate(unit, argv=()):
    return config_test(unit)

def run(units):
    return [evaluate(unit) for unit in units]
"""

# A host script whose only function builds a user-switched command.
TOOL = """
def as_user(user, env, argv):
    return ["runuser", "-u", user, "--", "env", *(f"{k}={v}" for k, v in env.items()), *argv]
"""


def test_a_package_leak_is_caught_next_to_host_scripts() -> None:
    files = {
        "helpers/python.py": STUBS,
        "services/app/commands.py": """
def manage(cfg, argv, env):
    return _as_user(cfg.user, cfg.home, env, ["python3", "manage.py", *argv])
""",
        "services/app/deploy.py": """
def migrate(cfg):
    return manage(cfg, ["migrate"], {"HOME": cfg.home, "DJANGO_SECRET_KEY": cfg.key})
""",
        "base/files/restart.py": HOST_SWITCH,
    }
    assert _scan(files) == {("services/app/deploy.py", "DJANGO_SECRET_KEY")}


def test_a_host_script_leak_is_caught_in_its_own_program() -> None:
    files = {
        "helpers/python.py": STUBS,
        "base/files/restart.py": HOST_SWITCH
        + """
def check(unit):
    # check -> evaluate -> config_test: two calls deep.
    unit.env = {"HOME": unit.home, "ADMIN_PASSWORD": unit.password}
    return evaluate(unit, ["env", "API_TOKEN=" + unit.token])
""",
    }
    assert _scan(files) == {("base/files/restart.py", "ADMIN_PASSWORD"), ("base/files/restart.py", "API_TOKEN")}


def test_a_name_two_programs_merely_share_links_nothing() -> None:
    # A former false positive: generic names chained package modules through two
    # unrelated host scripts to a runuser call and flagged an env file's DATABASE_URL.
    files = {
        "base/files/restart.py": HOST_SWITCH,
        # Calls its own injected runner, as the fan controller does.
        "services/fans/files/controller.py": """
class Controller:
    def _call(self, argv):
        return self.run(argv)

    def update(self, reading):
        return self._call(["ipmitool", "sensor", "list"])
""",
        "services/unifi/render.py": """
def role_vars(cfg):
    values = {"HOME": cfg.home}
    values.update(cfg.extra)
    return values
""",
        "services/vault/deploy.py": """
def render_env(cfg):
    return sorted(role_vars(cfg).items())
""",
        "services/site/render.py": """
def render_env(cfg):
    # An env file's content, not a command's environment.
    return {"HOME": cfg.home, "DATABASE_URL": cfg.database_url}
""",
    }
    assert _scan(files) == set()
    # As package modules, the same sources are linked by name, as all files were before.
    flat = {relative.replace("/files/", "/"): source for relative, source in files.items()}
    assert _scan(flat) == {("services/site/render.py", "DATABASE_URL")}


def test_a_package_module_that_loads_a_host_script_reaches_its_user_switch() -> None:
    files = {
        "helpers/python.py": STUBS,
        "services/app/files/tool.py": TOOL
        + """
def push(cfg, helpers):
    # The package hands the script one of its own modules.
    return helpers._as_user(cfg.user, cfg.home, {"PUSH_TOKEN": cfg.token}, ["push"])
""",
        # A module loader with the script named in a path, as thermal_monitoring's fan_control loads its controller.
        "services/app/loader.py": """
SCRIPT = Path(__file__).parent / "files" / "tool.py"

def tool():
    spec = importlib.util.spec_from_file_location("app_tool", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def sync(cfg):
    return tool().as_user(cfg.user, {"HOME": cfg.home, "SYNC_TOKEN": cfg.token}, ["sync"])
""",
        "services/app/checks.py": """
from .files import tool

def check(cfg):
    return tool.as_user(cfg.user, {"CHECKS_JSON": cfg.checks}, ["check"])
""",
        # Gets the loaded module as a value from another package module.
        "services/app/deploy.py": """
def backup(cfg, module):
    return module.as_user(cfg.user, {"BACKUP_PASSWORD": cfg.password}, ["backup"])
""",
    }
    found = {
        ("services/app/loader.py", "SYNC_TOKEN"),
        ("services/app/checks.py", "CHECKS_JSON"),
        ("services/app/deploy.py", "BACKUP_PASSWORD"),
        # Loaded, the script is part of the package and sees its names too.
        ("services/app/files/tool.py", "PUSH_TOKEN"),
    }
    assert _scan(files) == found
    rest = ("helpers/python.py", "services/app/files/tool.py", "services/app/deploy.py")
    # Either load on its own links the script into the package.
    for loading in ("services/app/loader.py", "services/app/checks.py"):
        one = {relative: files[relative] for relative in (*rest, loading)}
        assert _scan(one) == {finding for finding in found if finding[0] in one}
    # Neither imported nor loaded, the script is a program of its own.
    assert _scan({relative: files[relative] for relative in rest}) == set()


@pytest.mark.parametrize(
    "source",
    [
        "importlib.util.spec_from_file_location(name, path)",
        "from importlib import import_module as load",
        "from runpy import run_path",
        "loader = importlib.import_module",
        "exec(code, namespace)",
        "eval(compile(source, path, 'exec'), namespace)",
        "module = __import__(name)",
        "module = pydoc.importfile(path)",
    ],
)
def test_a_module_loader_is_recognised_under_any_name(source: str) -> None:
    assert _uses_a_loader(ast.parse(source))


def test_reading_package_data_is_no_module_loader() -> None:
    assert not _uses_a_loader(ast.parse("from importlib.resources import files\nsource = files(package) / 'x.py'"))


def test_a_loader_imported_under_another_name_links_the_script() -> None:
    files = {
        "services/app/files/tool.py": TOOL,
        "services/app/aliased.py": """
from importlib import import_module as load

def sync(cfg):
    module = load("ops_deploy.services.app.files.tool")
    return module.as_user(cfg.user, {"HOME": cfg.home, "SYNC_TOKEN": cfg.token}, ["sync"])
""",
    }
    assert _scan(files) == {("services/app/aliased.py", "SYNC_TOKEN")}


def test_a_host_script_reaches_the_user_switches_it_imports() -> None:
    files = {
        "helpers/python.py": STUBS,
        "services/app/files/manage.py": """
from ops_deploy.helpers.python import _as_user

def migrate(cfg):
    return _as_user(cfg.user, cfg.home, {"DJANGO_SECRET_KEY": cfg.key}, ["manage.py", "migrate"])
""",
        "services/app/files/tool.py": TOOL,
        # The script's own directory is on sys.path, so it imports the one next to it by its bare name.
        "services/app/files/notify.py": """
import tool

def notify(cfg):
    return tool.as_user(cfg.user, {"SMTP_PASSWORD": cfg.smtp}, ["mail"])
""",
    }
    assert _scan(files) == {
        ("services/app/files/manage.py", "DJANGO_SECRET_KEY"),
        ("services/app/files/notify.py", "SMTP_PASSWORD"),
    }
