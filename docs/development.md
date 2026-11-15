# Development

The project uses [uv](https://docs.astral.sh/uv/) and [just](https://just.systems).

| Recipe | What it runs |
|---|---|
| `just sync` | `uv sync --locked` |
| `just test` | `pytest -n <half the CPUs> --dist worksteal` with bytecode cached in `~/.cache/ops-deploy/pycache` (pass extra args: `just test -k toy`; `PYTEST_JOBS=auto just test` for one worker per CPU; serial, for example with `--pdb`: `just test -n 0`) |
| `just test-changed` | only the test files the working-tree change can affect (`scripts/affected_tests.py`, see below); an inner loop, not a gate |
| `just test-parity` | the same with `OPS_LIBRARY_PATH` (default `../ops-library`, made absolute), in its own `.venv-parity` with `ansible-core==2.21.5`: the parity, drift and role-oracle tests that `just test` skips; prints the ops-library HEAD and whether it is dirty |
| `just typecheck` | `mypy` in strict mode over `src/` and `tests/` |
| `just lint` | `ruff check` and `ruff format --check` |
| `just fmt` | apply ruff fixes and formatting |
| `just docs` | `mkdocs build --strict` |
| `just size-cap` | code-line count of helpers + ops + core against the cap (see below) |
| `just check` | lint, typecheck, test, size-cap and docs, as CI runs them |
| `just smoke` | real deploys to the local lima VM ([smoke target](concepts/smoke.md)); `smoke-up`, `smoke-ssh`, `smoke-down` manage the VM |

CI (`.github/workflows/ci.yml`) runs `just check` steps on Python 3.12 and 3.13.

`just test` runs the suite with [pytest-xdist](https://pytest-xdist.readthedocs.io/).
By default it starts half as many workers as the machine has CPUs (rounded
down, at least one), so several agents or checkouts can run suites on one
machine at the same time; `PYTEST_JOBS` overrides the count (a number, or
`auto` for one per CPU). `--dist worksteal` hands out tests, not files, and
lets an idle worker take tests a busy one has not started yet, so no single
file bounds the wall time (with `--dist loadfile`, `tests/test_drive_fan_control.py`
and its about 190 real subprocesses per calibration test kept one worker busy
for 90 s or more). Tests of one file may therefore run on several workers and
module-scoped fixtures once per worker. Most of the time goes into waiting
on subprocesses, so the speedup is large (on an 18-core M5 Max: about 12
minutes serial, about a minute and a half with the default 9 workers).

Two more things keep the suite fast:

- **Bytecode.** The recipe unsets `PYTHONDONTWRITEBYTECODE` (agent sessions
  set it) and points `PYTHONPYCACHEPREFIX` at `~/.cache/ops-deploy/pycache`
  (or `$XDG_CACHE_HOME/ops-deploy/pycache`, or your own
  `PYTHONPYCACHEPREFIX`), so the tree stays free of `__pycache__` while
  collection and the Python children the tests start (pyinfra runs,
  Home Assistant pipelines) load cached bytecode instead of compiling the
  package each time. Children started with `-I` ignore the prefix and compile
  as before.
- **Stub executables** (`tests/stubs.py`). On macOS the first `exec` of a
  newly written file costs 0.2 to 0.6 s, under load more than a second; a
  second exec of the same inode, or of a hard link to it, a few ms. The cost
  is the same in a plain login shell; new files carry a
  `com.apple.provenance` attribute, and the system's policy check runs once
  per new executable. `stubs.install(path, content)` writes each distinct
  stub once per run into a cache under pytest's base temp directory and
  hard-links it to `path`, so a stub every test writes anew costs that once.
  The test sees a regular file with the same path, content and mode (only
  the link count differs), so use it for stubs the code under test runs, not
  for files it inspects (several host scripts refuse files with other hard
  links), and do not write a stub in place afterwards (install the new
  content instead; the helper fails loudly if a cached copy changed). Keep
  per-test paths out of a stub's text where that is equivalent (derive them
  from `$0` or `sys.argv[0]`): a stub with a test's path in it is new for
  every test. A test with a short timeout around a fresh stub runs it once
  beforehand (`test_backups_mount_snapshot`).

Waits that only stand in for a
production timeout are shortened in the test, not slept out: the
`ssh_guard_tx` revert test runs a copy of the program with `QUIESCE_WAIT`
rewritten to 2 s, and the Traefik proof tests patch `proof.POLL` (the API
poll interval, passed to the proof in its spec) along with `SETTLE` and
`PATIENCE`. Tests running in parallel must not share state:

- use `tmp_path` for files, never a fixed path below `/tmp` on the
  controller (a short `tempfile.mkdtemp(dir="/tmp")` is fine where a Unix
  socket path must stay short);
- bind servers to port `0` and read the port back;
- keep parametrize ids stable across processes (no `time.time()` or other
  run-dependent values in an id; pass `ids=`), or xdist refuses to run
  because the workers collected different tests;
- do not rely on process state left behind by an earlier test, nor on the
  order of tests within a file (with `worksteal` another worker may run the
  next one).
  `tests/conftest.py` puts pyinfra's state, inventory, config and host
  context back after each test (`ContextManager.use()` does not restore it
  when the block raises), and the umask (host programs run in-process set
  `0o077`).

## Only the affected tests: `just test-changed`

`just test-changed` runs the test files that `scripts/affected_tests.py`
selects for the working-tree change against `HEAD` (staged, unstaged and
untracked files). `uv run python scripts/affected_tests.py --explain [PATH ...]`
says why each path selects what. The rules:

- a changed test file selects itself;
- a changed module selects every test file whose import closure contains it
  (static imports read with `ast`, import lines inside the source of child
  programs, and dotted module names in strings such as
  `importlib.import_module("ops_deploy.x")` or monkeypatch targets), and the
  tests that load a helper importing it by path (`tests/integration/*/harness.py`,
  `smoke/*.py`: helpers no test imports, found by the tests naming them);
- any file selects the test files that import a module naming it (its file
  name, a path suffix such as `traefik_routine/run.sh`, also spelled as path
  segments, `"parity" / "ansible"`, or a template family prefix such as
  `ssh_guard_deploy__`), and, under `services/<svc>/` or `infra/<x>/`, the
  tests of that package;
- `PATH_RULES` in the script adds what only a run shows (tests that build a
  path at run time, such as `f"smoke/daybook_{name}_native_fixture.py"`);
- `tests/test_policy.py`, `tests/test_traefik_hsts.py`, `tests/test_size_cap.py`
  and `tests/test_affected_tests.py` always run, and the sweeps over the whole
  package (`tests/test_become_environment_secrets.py`,
  `tests/test_remote_shell_execution.py`) on any change under `src/`;
- the whole suite runs (fail open) for the core packages (`core`, `ops`,
  `helpers`, `base`, `testing`), `conftest.py`, test helpers imported by 15
  or more test files (such as `tests/fakehost.py`), `pyproject.toml`,
  `uv.lock`, the `justfile`, the selector itself, and any path no rule maps
  (documentation no module names runs only the always-run tests).

The script caches what it parses in `~/.cache/ops-deploy/affected-tests.json`
(per file, by size and modification time); a selection takes about a second.
For one changed source file it typically picks a few dozen of the roughly 500
test files.

The rules were checked against a full run that recorded, per test file, the
modules it executed (coverage with `--cov-context=test`) and the repo files it
opened, listed, ran or imported, also inside child Python processes (through
a `sitecustomize` on `PYTHONPATH`; children started with `-I` or a clean
environment are not seen). Every file a test opened, ran, imported or
executed is now selected when it changes; what remains are directory
listings by the import system. It is still an inner loop that a rule can
miss (a path a child process builds, a file only stat-ed): run `just test` or
`just check` before each commit.

## Optional original-role oracle checks

`just test-parity` runs all of these against `../ops-library` (or
`OPS_LIBRARY_PATH`). The drift tests compare against the checkout's working
tree, so run it on a clean `main` checkout before recording digests. The
recipe syncs the locked environment into `.venv-parity` and installs
`ansible-core` there; it stays out of the dev group, because only these oracle
tests import it, and a skip on a missing import would hide an oracle that
silently did not run. Not `uv run --with ansible-core`: its overlay brings a
second `packaging`, and the Home Assistant extras probe (rightly) treats
duplicate distribution metadata as not current.

Setting `OPS_LIBRARY_PATH` enables additional comparisons with the original
Ansible roles. Use an absolute path to the intended owned checkout and record
its Git HEAD. Some tests import Ansible filters in the **pytest interpreter**;
a separate `ansible --version` or `ansible-playbook` on `PATH` does not prove that
those imports work. For these optional checks, install the qualified test tool
into the same owned environment after syncing (no product dependency change):

```bash
uv sync --locked
uv pip install --python .venv/bin/python 'ansible-core==2.21.5'
OPS_LIBRARY_PATH=/absolute/path/to/owned/ops-library uv run --locked python - <<'PYTHON'
import importlib.metadata
import os
from pathlib import Path
import subprocess
import sys

import ansible
import pytest

library = Path(os.environ["OPS_LIBRARY_PATH"])
assert library.is_absolute()
assert importlib.metadata.version("ansible-core") == "2.21.5"
print("pytest Python:", sys.executable, "Ansible:", ansible.__file__)
print("original roles:", library,
      subprocess.check_output(["git", "-C", str(library), "rev-parse", "HEAD"], text=True).strip())
raise SystemExit(pytest.main(["-q", "tests/test_daybook_inbox_declaration.py"]))
PYTHON
```

Select the applicable oracle tests in that final argument. If a broader run
fails solely because this optional import is missing, retain the initial result,
repair that owned environment and rerun the exact failed nodes plus the checks
that did not execute. Report both runs; do not describe them as an uninterrupted
passing suite or replay unrelated native qualification.

## Rules enforced by tests and lint

- Never enable pyinfra privilege arguments or choose another user in `ops_deploy`
  (`tests/test_policy.py`): sudo/doas/dzdo/su uploads otherwise use shared plaintext
  temporary staging. Literal `False` may disable each actual SDK flag. Empty/None
  user clearing requires the corresponding flag disabled in the same call;
  `_su_user` clearing requires all three flags disabled (there is no `_su` flag).
  True, dynamic values, integer zero, user overrides and clearing alone remain
  forbidden. Explicit private connecting-identity handoffs preserve this invariant.
- No secret-looking or payload (`*_JSON`, `*_DATA`, `*_SPEC`) environment
  name in a user-switched command's environment or on a command line, and no
  pyinfra `_env` (`tests/test_become_environment_secrets.py`, see
  [Secrets](concepts/secrets.md#rules)).
- `pyinfra.api.MaskString` is banned (ruff `TID251`); use `HiddenValue`.
- The whole suite must stay fast (target: under 10 s) and must not touch the
  network or the controller's rsync; use the [test harness](concepts/testing.md).
  `tests/smoke/` is the exception and is skipped unless `just smoke` runs it.

## Size cap on the shared layer

The shared layer (`src/ops_deploy/helpers`, `ops` and `core`) must stay at or
below **1,700 code lines**. The cap guards against framework creep: services
should call a small set of plain helpers, not grow an abstraction layer.

The cap was 1,500 until the owner raised it to 1,650 on 2026-10-21, to make
room for `helpers.rust_release`, the Rust release helper shared by all Rust
ports (the shared layer was then at 1,633 code lines).

On 2026-10-27 the approved existing `sync_tree` extension added 45 shared code
lines (1,648 → 1,693): explicit remote rsync selection and a verified preceding
preparation operation for genuinely fresh destinations. The cap is now 1,700.
The native uv branch remains in `base`, and service-specific Darwin operations
remain in their service packages; this change adds no shared Mac framework.

`scripts/size_cap.py` (`just size-cap`) prints line and code-line counts per
layer and exits non-zero above the cap. A code line is a physical line holding
at least one Python token other than a comment, outside a docstring (the first
string statement of a module, class or function). Blank lines, comments and
docstrings are free, since the rendered documentation is built from them. Only
`*.py` files count; Jinja templates do not. Services (`services/`), the
host-level base deploys (`base/`) and the shared host services (`infra/`) are deploys, not part of the shared layer, and do not
count.

CI runs it on every push, and `tests/test_size_cap.py` also fails the suite
above the cap. Record the numbers at each phase gate. Raising the cap is an
owner decision; change `DEFAULT_CAP` only together with that decision.
