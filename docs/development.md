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
| `just check` | lint, typecheck, test and docs, as CI runs them |

CI (`.github/workflows/ci.yml`) runs `just check` steps on Python 3.12 and 3.13.

## Rules enforced by tests and lint

- No `_sudo`, `_sudo_user`, `_su_user` or `_doas` in `ops_deploy`
  (`tests/test_policy.py`): pyinfra stages `_sudo` uploads as plaintext in `/tmp`.
- `pyinfra.api.MaskString` is banned (ruff `TID251`); use `HiddenValue`.
- The whole suite must stay fast (target: under 10 s) and must not touch the
  network or the controller's rsync; use the [test harness](concepts/testing.md).
