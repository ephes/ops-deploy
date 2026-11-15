# Development

The project uses [uv](https://docs.astral.sh/uv/) and [just](https://just.systems).

| Recipe | What it runs |
|---|---|
| `just sync` | `uv sync --locked` |
| `just test` | `pytest -n <half the CPUs> --dist loadfile` (pass extra args: `just test -k toy`; `PYTEST_JOBS=auto just test` for one worker per CPU; serial, for example with `--pdb`: `just test -n 0`) |
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
`auto` for one per CPU). `--dist loadfile` keeps each test file on one worker,
so tests within a file still run in order. Most of the time goes into waiting
on subprocesses, so the speedup is large (on an 18-core M5 Max: about 12
minutes serial, about 2½ minutes with the default 9 workers). The wall time cannot drop below the
slowest file; `tests/test_base_ssh_guard_tx.py` deliberately waits out a
60-second revert timeout. Tests running in parallel must not share state:

- use `tmp_path` for files, never a fixed path below `/tmp` on the
  controller (a short `tempfile.mkdtemp(dir="/tmp")` is fine where a Unix
  socket path must stay short);
- bind servers to port `0` and read the port back;
- keep parametrize ids stable across processes (no `time.time()` or other
  run-dependent values in an id; pass `ids=`), or xdist refuses to run
  because the workers collected different tests;
- do not rely on process state left behind by an earlier test.
  `tests/conftest.py` puts pyinfra's state, inventory, config and host
  context back after each test (`ContextManager.use()` does not restore it
  when the block raises), and the umask (host programs run in-process set
  `0o077`).

## Optional original-role oracle checks

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
