#!/usr/bin/env python3
"""Select the test files a working-tree change can affect (``just test-changed``).

The change is ``git diff HEAD`` (staged and unstaged, renames as delete + add)
plus untracked files. Each changed path selects test files by these rules:

- a test file (``tests/**/test_*.py``) selects itself;
- a Python module (under ``src/``, ``tests/`` or ``smoke/``) selects every
  test file whose import closure contains it (static imports, parsed with
  ``ast``; import lines in the source of child programs; dotted module names
  in strings; ``from a import b`` counts ``a.b`` when that is a module, and a
  module imports its parent packages), and the test files that load, by
  path, a helper whose closure contains it (a harness no test imports);
- any file also selects the test files whose closure contains a module that
  *names* it: a module whose text has its basename, one of its path
  suffixes (``files/run.sh``, ``infra/files``, ...; also spelled as path
  segments ``"infra" / "files"``) or its template family prefix
  (``role__``). That covers host scripts, templates and data read by path
  or by ``importlib.resources``;
- a file under ``src/ops_deploy/services/<svc>/`` or ``infra/<x>/`` also
  selects the tests of that package (those importing any module in it);
- :data:`PATH_RULES` add what only a recorded run shows.

The repo-wide sweeps always run (:data:`ALWAYS`), and :data:`SOURCE_SWEEPS`
run for any change under ``src/``. Some changes select the whole suite
(fail open): the core packages (:data:`CORE`), ``conftest.py``, test helpers
imported by many test files (:data:`WIDELY_USED`), the project and lock
files, the justfile, and any path no rule maps to a test.

The rules were checked against a full run recording what each test file
executed (coverage contexts) and opened, ran or imported, also in child
Pythons (docs/development.md). It is a fast inner loop and may still miss
what no rule sees (a path a subprocess builds). ``just test`` or
``just check`` before each commit stays mandatory.

Usage: ``affected_tests.py [--explain] [PATH ...]``. Without paths it reads
the change from git. It prints the selected test files, one per line, or
the single word ``ALL`` for the whole suite (or ``NONE`` for no change).
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import subprocess
import sys
from collections.abc import Iterable
from functools import cache
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
TESTS = ROOT / "tests"
PACKAGE = "ops_deploy"

# Repo-wide sweeps over every source file: run on every change.
ALWAYS = (
    "tests/test_policy.py",
    "tests/test_traefik_hsts.py",
    "tests/test_size_cap.py",
    "tests/test_affected_tests.py",
)
# Sweeps that scan the whole package by globbing it: run on every change under src/.
SOURCE_SWEEPS = (
    "tests/test_become_environment_secrets.py",
    "tests/test_remote_shell_execution.py",
    "tests/test_traefik_edge_headers.py",
)
# A change here selects the whole suite.
CORE = tuple(f"src/{PACKAGE}/{name}/" for name in ("core", "ops", "helpers", "base", "testing"))
FULL_SUITE_FILES = frozenset(
    {
        "pyproject.toml",
        "uv.lock",
        "justfile",
        f"src/{PACKAGE}/__init__.py",
        "tests/__init__.py",
        "scripts/affected_tests.py",
    }
)
# A test helper imported (directly or not) by at least this many test files counts as widely used.
WIDELY_USED = 15
# Changes that select nothing beyond the sweeps when no module names them.
DOCUMENTATION = re.compile(r"^(docs/.*|[^/]+\.md|mkdocs\.yml|LICENSE|\.gitignore|\.github/.*)$")
# Path suffixes too generic to say which file a module means.
GENERIC_NAMES = frozenset({"__init__.py", "README.md", "files", "templates", "tests", "src"})


# -- the module graph ------------------------------------------------------------------------------


def _module_name(path: Path) -> str | None:
    if path.suffix != ".py":
        return None
    for base in (SRC, ROOT):
        try:
            relative = path.relative_to(base)
        except ValueError:
            continue
        if base is ROOT and relative.parts[0] == "smoke" and len(relative.parts) == 2:
            return relative.stem  # smoke/*.py import each other by bare name (smoke/ on sys.path)
        if base is ROOT and relative.parts[0] != "tests":
            return None
        parts = list(relative.with_suffix("").parts)
        if parts[-1] == "__init__":
            parts.pop()
        return ".".join(parts)
    return None


@cache
def modules() -> dict[str, Path]:
    """Every importable module of the package and the tests: dotted name -> file."""

    found: dict[str, Path] = {}
    for base in (SRC / PACKAGE, TESTS, ROOT / "smoke"):
        for path in sorted(base.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            name = _module_name(path)
            if name is not None:
                found[name] = path
    return found


@cache
def texts() -> dict[str, str]:
    return {name: path.read_text(errors="replace") for name, path in modules().items()}


def _resolve(name: str, level: int, current: str, is_package: bool) -> str:
    if not level:
        return name
    base = current.split(".")
    if not is_package:
        base.pop()
    if level > 1:
        base = base[: len(base) - (level - 1)]
    return ".".join([*base, name] if name else base)


def _parents(name: str) -> Iterable[str]:
    parts = name.split(".")
    for end in range(1, len(parts) + 1):
        yield ".".join(parts[:end])


CACHE = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "ops-deploy" / "affected-tests.json"
# Dotted names in strings: importlib.import_module("ops_deploy.x"), monkeypatch targets, f"ops_deploy.services.{name}".
_DOTTED = re.compile(r"""["'](ops_deploy(?:\.\w+)*|tests(?:\.\w+)+)""")
# Import lines anywhere, also inside the source of a child program (python -c, a script written by the test).
_IMPORT_LINE = re.compile(
    r"^[ \t]*(?:from|import)[ \t]+((?:ops_deploy|tests)(?:\.\w+)*)(?:[ \t]+import[ \t]+([\w, \t]+))?", re.M
)
_BODIES = ("body", "orelse", "finalbody", "handlers", "cases")


def _targets(name: str, path: Path, text: str) -> list[str]:
    """What a module imports or names by its dotted name, resolved but not yet checked against the modules."""

    is_package = path.name == "__init__.py"
    found: set[str] = set(_DOTTED.findall(text))
    for base, names in _IMPORT_LINE.findall(text):
        found.add(base)
        found.update(f"{base}.{alias.strip()}" for alias in names.split(",") if alias.strip())
    try:
        stack: list[ast.AST] = list(ast.parse(text, filename=str(path)).body)
    except SyntaxError:
        stack = []
    while stack:  # statements only: imports are statements, at any depth of def/if/try/with/match
        node = stack.pop()
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = _resolve(node.module or "", node.level, name, is_package)
            found.add(base)
            found.update(f"{base}.{alias.name}" for alias in node.names)
        for field in _BODIES:
            stack.extend(getattr(node, field, None) or ())
    return sorted(found)


def _cached_targets() -> dict[str, list[str]]:
    """Module -> its targets; parsed again only for files whose size or mtime changed (cache in ~/.cache)."""

    try:
        old = json.loads(CACHE.read_text())
    except (OSError, ValueError):
        old = {}
    if not isinstance(old, dict) or old.get("version") != 2:
        old = {}
    entries: dict[str, list[object]] = old.get("files", {})
    fresh: dict[str, list[object]] = {}
    result: dict[str, list[str]] = {}
    for name, path in modules().items():
        stat = path.stat()
        key = str(path)
        entry = entries.get(key)
        if entry is None or entry[:3] != [name, stat.st_mtime_ns, stat.st_size]:
            entry = [name, stat.st_mtime_ns, stat.st_size, _targets(name, path, texts()[name])]
        fresh[key] = entry
        result[name] = list(entry[3])  # type: ignore[call-overload]
    if fresh != entries:
        try:
            CACHE.parent.mkdir(parents=True, exist_ok=True)
            scratch = CACHE.with_name(f".{CACHE.name}.{os.getpid()}")
            scratch.write_text(json.dumps({"version": 2, "files": fresh}))
            os.replace(scratch, CACHE)
        except OSError:
            pass
    return result


@cache
def imports() -> dict[str, frozenset[str]]:
    """Module -> the known modules it imports or names (and their parent packages)."""

    known = modules()
    graph: dict[str, frozenset[str]] = {}
    for name, targets in _cached_targets().items():
        found = {parent for target in targets for parent in _parents(target) if parent in known}
        found.update(parent for parent in _parents(name) if parent in known)
        found.discard(name)
        graph[name] = frozenset(found)
    return graph


@cache
def closures() -> dict[str, frozenset[str]]:
    """Test file module -> every module it imports, directly or not (itself included)."""

    graph = imports()
    result: dict[str, frozenset[str]] = {}
    for name in test_modules():
        seen = {name}
        stack = [name]
        while stack:
            for target in graph[stack.pop()]:
                if target not in seen:
                    seen.add(target)
                    stack.append(target)
        result[name] = frozenset(seen)
    return result


def _is_test_file(path: PurePosixPath) -> bool:
    return path.parts[0] == "tests" and path.name.startswith("test_") and path.suffix == ".py"


@cache
def test_modules() -> dict[str, str]:
    """Test file module -> its repo-relative path."""

    return {
        name: path.relative_to(ROOT).as_posix()
        for name, path in modules().items()
        if _is_test_file(PurePosixPath(path.relative_to(ROOT).as_posix()))
    }


@cache
def importers() -> dict[str, frozenset[str]]:
    """Module -> the test files whose closure contains it."""

    found: dict[str, set[str]] = {}
    for test, closure in closures().items():
        for module in closure:
            found.setdefault(module, set()).add(test_modules()[test])
    return {module: frozenset(tests) for module, tests in found.items()}


# -- the rules ---------------------------------------------------------------------------------------


class Full(Exception):
    """The change selects the whole suite."""


def _names(path: PurePosixPath) -> list[str]:
    """The strings that, found in a module, mean it refers to ``path``."""

    parts = path.parts
    # The shallowest directory specific enough to name: a service or infra package, a tests/ subdirectory.
    shallowest = 4 if parts[:2] == ("src", PACKAGE) else 2
    names: set[str] = set()
    # The file and each specific directory above it, spelled with at least two trailing parts:
    # files/run.sh, mastodon/files/run.sh, ...; services/mastodon, mastodon/files, ...
    for end in range(2, len(parts) + 1):
        if end == len(parts) or end >= shallowest:
            names.update("/".join(parts[start:end]) for start in range(end - 1))
    if path.name not in GENERIC_NAMES:
        names.add(path.name)
    stem = path.name.removesuffix(".j2")
    if path.suffix == ".j2" and "." in stem:
        names.add(stem)  # toy.service.j2 renders toy.service
    if "__" in path.name:
        names.add(path.name[: path.name.index("__") + 2])  # role__template.j2 found as f"role__{template}"
    return sorted(names)


@cache
def _spelled() -> dict[str, str]:
    """Module texts with path segments joined: ``"golden" / "nyxmon"`` reads ``golden/nyxmon``."""

    joined = re.compile(r"[\"']\s*/\s*[\"']")
    return {module: joined.sub("/", text) for module, text in texts().items()}


def _naming_modules(path: PurePosixPath) -> set[str]:
    names = _names(path)
    return {module for module, text in _spelled().items() if any(name in text for name in names)}


def _package_of(path: PurePosixPath) -> str | None:
    parts = path.parts
    if len(parts) >= 4 and parts[:2] == ("src", PACKAGE) and parts[2] in ("services", "infra"):
        candidate = f"{PACKAGE}.{parts[2]}.{parts[3]}"
        if candidate in modules():
            return candidate
    # infra/files, infra/templates: shared by infra's modules, which name what they use.
    return None


@cache
def imported_by() -> dict[str, frozenset[str]]:
    """Module -> the modules importing it directly."""

    found: dict[str, set[str]] = {}
    for module, targets in imports().items():
        for target in targets:
            found.setdefault(target, set()).add(module)
    return {module: frozenset(users) for module, users in found.items()}


def _through_path_loaded(module: str) -> tuple[set[str], set[str]]:
    """Test files reaching ``module`` through a helper no test imports, which tests load by path instead.

    ``tests/integration/*/harness.py`` and ``smoke/*.py`` are run or loaded from a path a test names;
    whatever they import is the test's too. Returns (test files, the helpers).
    """

    seen = {module}
    stack = [module]
    while stack:
        for user in imported_by().get(stack.pop(), ()):
            if user not in seen:
                seen.add(user)
                stack.append(user)
    helpers = {
        user
        for user in seen
        if not importers().get(user) and not user.startswith(f"{PACKAGE}.") and user not in test_modules()
    }
    tests: set[str] = set()
    for helper in helpers:
        for name in _naming_modules(PurePosixPath(modules()[helper].relative_to(ROOT).as_posix())):
            tests |= importers().get(name, frozenset())
    return tests, helpers


# Dependencies no static rule sees, found by the validation run (docs/development.md): changed path
# (regular expression) -> test files (globs under the repo).
PATH_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    # The native fixtures run smoke/daybook_<name>_native_fixture.py (path built with an f-string),
    # which import and read the daybook services in a child process.
    (
        rf"src/{PACKAGE}/services/daybook_|smoke/",
        ("tests/test_daybook_*_native_fixture.py", "tests/test_photo_activation_fixtures.py"),
    ),
    # host_module(service) loads files/<service>_host.py of the services it is parametrized with.
    (rf"src/{PACKAGE}/services/[^/]+/files/[^/]+_host\.py$", ("tests/test_mac_apps_artifacts.py",)),
    # Tests that run a smoke/ script by a path built at run time (f"smoke/daybook_{name}_native_fixture.py").
    (r"smoke/", ("tests/test_daybook_root_python.py", "tests/test_daybook_runtime_code_controller.py")),
)


@cache
def _path_rules() -> tuple[tuple[re.Pattern[str], frozenset[str]], ...]:
    return tuple(
        (re.compile(rule), frozenset(str(p.relative_to(ROOT)) for glob in globs for p in ROOT.glob(glob)))
        for rule, globs in PATH_RULES
    )


def _tests_of_package(package: str) -> set[str]:
    found: set[str] = set()
    for module, tests in importers().items():
        if module == package or module.startswith(package + "."):
            found |= tests
    return found


def select_for(relative: str, explain: list[str] | None = None) -> set[str]:
    """The test files one changed path selects; raises :class:`Full` for the whole suite."""

    path = PurePosixPath(relative)

    def note(text: str) -> None:
        if explain is not None:
            explain.append(f"{relative}: {text}")

    if relative in FULL_SUITE_FILES or relative.startswith(CORE) or path.name == "conftest.py":
        note("core, project or conftest file: whole suite")
        raise Full(relative)
    selected: set[str] = set()
    module = _module_name(ROOT / relative)
    known = modules()
    if _is_test_file(path):
        note("test file: itself")
        selected.add(relative)
    if module is not None and module in known:
        tests = importers().get(module, frozenset())
        if module.startswith("tests.") and not _is_test_file(path) and len(tests) >= WIDELY_USED:
            note(f"test helper imported by {len(tests)} test files: whole suite")
            raise Full(relative)
        if tests:
            note(f"imported by {len(tests)} test files")
        selected |= tests
        loaded, helpers = _through_path_loaded(module)
        if loaded:
            note(f"reached through {len(helpers)} helpers loaded by path: {len(loaded)} test files")
        selected |= loaded
    # Modules are also read by path (copied into a fixture, loaded with runpy, listed with their package).
    naming = _naming_modules(path) - ({module} if module else set())
    by_name: set[str] = set()
    for name in naming:
        by_name |= importers().get(name, frozenset())
    if by_name:
        note(f"named by {len(naming)} modules, imported by {len(by_name)} test files")
    selected |= by_name
    package = _package_of(path)
    if package is not None:
        in_package = _tests_of_package(package)
        if in_package:
            note(f"part of {package}: {len(in_package)} test files")
        selected |= in_package
    for rule, ruled in _path_rules():
        if rule.match(relative):
            note(f"path rule {rule.pattern}: {len(ruled)} test files")
            selected |= ruled
    if not selected:
        if DOCUMENTATION.match(relative):
            note("documentation no module names: sweeps only")
        elif module is not None and module in known:
            note("module no test imports: sweeps only")
        else:
            note("no rule maps it: whole suite")
            raise Full(relative)
    return selected


def select(paths: Iterable[str], explain: list[str] | None = None) -> set[str] | None:
    """Selected test files for all changed paths, or None for the whole suite."""

    paths = sorted(set(paths))
    selected: set[str] = set()
    try:
        for relative in paths:
            selected |= select_for(relative, explain)
    except Full:
        return None
    if any(relative.startswith("src/") for relative in paths):
        selected.update(SOURCE_SWEEPS)
    selected.update(ALWAYS)
    return {test for test in selected if (ROOT / test).is_file()}


def changed_paths() -> list[str]:
    def git(*args: str) -> list[str]:
        out = subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True, text=True).stdout
        return [line for line in out.split("\0") if line]

    return sorted(
        set(git("diff", "--name-only", "--no-renames", "-z", "HEAD"))
        | set(git("ls-files", "--others", "--exclude-standard", "-z"))
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("paths", nargs="*", help="repo-relative paths (default: the git change)")
    parser.add_argument("--explain", action="store_true", help="say on stderr why each path selects what")
    args = parser.parse_args(argv)
    paths = args.paths or changed_paths()
    if not paths:
        print("NONE")
        return 0
    explain: list[str] | None = [] if args.explain else None
    selected = select(paths, explain)
    for line in explain or ():
        print(line, file=sys.stderr)
    print("ALL" if selected is None else "\n".join(sorted(selected)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
