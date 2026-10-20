# Development

The project uses [uv](https://docs.astral.sh/uv/) and [just](https://just.systems).

| Recipe | What it runs |
|---|---|
| `just sync` | `uv sync --locked` |
| `just test` | `pytest` (pass extra args: `just test -k toy`) |
| `just typecheck` | `mypy` in strict mode over `src/` and `tests/` |
| `just lint` | `ruff check` and `ruff format --check` |
| `just fmt` | apply ruff fixes and formatting |
| `just docs` | `mkdocs build --strict` |
| `just size-cap` | code-line count of helpers + ops + core against the cap (see below) |
| `just check` | lint, typecheck, test, size-cap and docs, as CI runs them |
| `just smoke` | real deploys to the local lima VM ([smoke target](concepts/smoke.md)); `smoke-up`, `smoke-ssh`, `smoke-down` manage the VM |

CI (`.github/workflows/ci.yml`) runs `just check` steps on Python 3.12 and 3.13.

## Rules enforced by tests and lint

- No `_sudo`, `_sudo_user`, `_su_user` or `_doas` in `ops_deploy`
  (`tests/test_policy.py`): pyinfra stages `_sudo` uploads as plaintext in `/tmp`.
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
below **1,500 code lines**. The cap guards against framework creep: services
should call a small set of plain helpers, not grow an abstraction layer.

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
