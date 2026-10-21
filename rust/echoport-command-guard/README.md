# echoport-command-guard (Rust port, in progress)

The Rust port of the `echoport_remote_command_guard` forced-command guard.
The plan and contract are in [PLAN.md](PLAN.md), the test map in
[TESTMAP.md](TESTMAP.md). Nothing here is released or deployed yet; the
hosts run the Python guard.

Status: **S1** (crate skeleton, policy, tokeniser). What exists:

- The crate (a member of the `rust/` workspace): the library that decides and
  the binary `echoport-command-guard`.
  - `--version` prints `echoport-command-guard <version> (<commit>)`
    (`build.rs`: `ECHOPORT_COMMAND_GUARD_GIT_COMMIT`, else `git rev-parse
    HEAD`, else `unknown`).
  - `--check-policy <file>` validates a policy file as the Python guard does
    (exit 0, or `echoport-remote-command-guard: invalid policy: <detail>` on
    stderr and exit 1), with the stricter types of PLAN.md 4.2.
  - Any other argv is the Python guard's usage error (exit 2), except
    `<prog> <policy>`: forced-command mode is S4, so until then it refuses
    every command (`echoport-remote-command-guard: command not allowed`,
    exit 1) and never executes anything.
  - `check()` ports the pre-checks, the prefilter (PLAN.md 4.1), the two raw
    shapes (detected only), the tokeniser and the tool dispatcher. Every tool
    branch still refuses; S3a and S3b port them.
- `parity/oracle.py`: the Python guard as the oracle. A module for the
  generator and the tests, and a JSON-lines server (`python3 -I
  parity/oracle.py`) with the ops `ping`, `check`, `split`, `check_policy`
  and `realpath` for the Rust property tests. Stdlib only.
- `parity/gen_fixtures.py`: writes `fixtures/` (below).
- `parity/allowed_differences.json`: per-case exceptions (empty).
- `fixtures/`: the Layer-1 cases, generated and committed.

## Build and test

From `rust/` in a worktree (never in a shared checkout; this writes
`rust/target/`), or with `just rust-check` from the repository root:

```bash
cargo test -p echoport-command-guard --locked
```

The tests:

- `src/**` unit tests: prefilter, tokeniser, `repr`, `normpath`, the policy
  loader, the dispatcher.
- `tests/layer1.rs`, the Layer-1 runner: every decision and policy case of
  `fixtures/` against the Rust guard, with the case's recorded environment as
  a virtual `GuardEnv`. A Rust acceptance must equal Python's decision. A
  refusal by a branch that is not ported yet counts as pending. Any other
  refusal must be Python's, with Python's reason, unless the case has a `p3`
  tag or is listed in `parity/allowed_differences.json`. Policy cases must
  give Python's verdict, normalized policy and error type, and Python's
  message for `Refused` and `KeyError` texts in printable ASCII (PLAN.md 4.3).
- `tests/tokeniser.rs`: the tokeniser against Python's `shlex.split` through
  the oracle server, over every fixture command that passes the prefilter
  and over 2,000 seeded random commands (proptest). `PROPTEST_CASES=100000`
  runs more, `PROPTEST_RNG_SEED=<n>` changes the seed.
- `tests/cli.rs`: the binary's argv grammar, `--version`, `--check-policy`.

The oracle tests run `$ECHOPORT_ORACLE_PYTHON -I parity/oracle.py`
(default `python3`; CI uses Python 3.12, production's, from uv:
`ECHOPORT_ORACLE_PYTHON=$(uv python find --no-project 3.12)`). They fail
rather than skip when it cannot start.

CI (`.github/workflows/rust.yml`) runs these with the workspace and adds the
fixture drift check: `gen_fixtures.py check` under Python 3.12 and 3.13, then
`check --record` in the repo venv (`uv sync --locked`). `rust.yml` runs only
for changes under `rust/`; a change to the Python guard or a runner template
alone is caught by `just test-echoport-remote-command-guard` (part of `just
test`).

## Fixtures

Regenerate after any change to the Python guard or a remote runner template:

```bash
just echoport-command-guard-fixtures
```

It records the inputs in the repo venv (`gen_fixtures.py record`: the test
policies to `fixtures/policies/`, every runner command and every `check()`
and `Policy.from_dict()` call of the guard's unit tests to
`fixtures/corpus/`), generates the cases under Python 3.12 (production's
Python), and requires byte-identical output under 3.13 (staging's) and the
venv. `just test-echoport-remote-command-guard` (part of `just test`) fails
when `fixtures/GUARD_SHA256` does not match the guard or regenerating gives a
different result.

Files (each under the repository's 1000 KB limit; `fixtures/manifest.json`
lists them with their counts):

| File | Cases |
| --- | --- |
| `runner.jsonl` | every command each runner sends for a backup and a restore (all allowed) |
| `journal.jsonl` | the shapes seen in the hosts' journals (PLAN.md 3.4), with synthetic stamps |
| `unit.jsonl` | every `check()` call of the Python unit tests |
| `mutation/*.jsonl` | mutations of every accepted command and per-tool variants (PLAN.md 7.2 item 4) |
| `fs.jsonl` | every lstat and realpath state for each path-taking shape |
| `policy.jsonl` | `--check-policy` documents |

A decision case:

```json
{"id": "fs/lstat-reg-postgres/production/1b11925bc15d", "source": "fs", "policy": "production",
 "command": "scp -f /tmp/echoport_pp_dump_2026-10-15T02-00-00.dump",
 "env": {"euid": 0, "users": {"postgres": 110},
         "lstat": {"/tmp/echoport_pp_dump_2026-10-15T02-00-00.dump": {"kind": "reg", "mode": 384, "uid": 110, "nlink": 1}},
         "realpath": {}},
 "expected": {"verdict": "allowed", "argv": ["scp", "-f", "/tmp/echoport_pp_dump_2026-10-15T02-00-00.dump"],
              "umask": null, "stdin": null, "stdout": null}}
```

- `policy` names `fixtures/policies/<policy>.json`.
- `command`, or `command_hex` for a command that is not valid UTF-8 (the
  bytes of `SSH_ORIGINAL_COMMAND`).
- `env` holds every lookup the Python guard made, with its answer.
  - `lstat`: `{kind, mode, uid, nlink}` with `kind` one of `reg dir lnk fifo
    sock chr blk` and `mode` the permission bits (decimal), or `{"absent":
    true}`, or `{"errno", "strerror"}`.
  - `users`: name to uid, `null` for no such user.
  - Defaults: a path missing from `lstat` is absent, a path missing from
    `realpath` resolves to `os.path.normpath(path)`, and a missing user does
    not exist.
- `expected` is one of:
  - `{"verdict": "allowed", argv, umask, stdin, stdout}`, where a redirect is
    `{directory, name, owners}` and `umask` is `null` or `63` (`0o077`);
  - `{"verdict": "refused", "reason"}`;
  - `{"verdict": "error", "error_type", "message"}`: Python's `check()`
    raised, so the Python guard exits 1 with a traceback and runs nothing.
- `p3` (optional) lists the PLAN.md 4.1/4.2 classes the case falls into.
  The Rust guard may refuse such a case where Python accepts it, and its
  reason may differ; it must never accept what Python refuses.
  - `prefilter`: outside printable ASCII and tab, or contains `\` or `#`.
  - `invalid-utf8`.
  - `python-error`: the `error` verdict.
  - `policy-type`, `policy-trailing-newline`: policy documents.

A policy case has `policy_text` (or `policy_hex`) and `expected` `{"ok":
true, "normalized": {...}}` or `{"ok": false, "error_type", "message"}`.
