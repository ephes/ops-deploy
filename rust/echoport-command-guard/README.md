# echoport-command-guard (Rust port, in progress)

The Rust port of the `echoport_remote_command_guard` forced-command guard.
The plan and contract are in [PLAN.md](PLAN.md), the test map in
[TESTMAP.md](TESTMAP.md). Nothing here is built, released or deployed yet;
the hosts run the Python guard.

Status: **S0** (contract freeze and fixture generator). There is no crate yet
(S1). What exists:

- `parity/oracle.py`: the Python guard as the oracle. A module for the
  generator and the tests, and a JSON-lines server (`python3 -I
  parity/oracle.py`) with the ops `ping`, `check`, `split`, `check_policy`
  and `realpath` for the Rust property tests. Stdlib only.
- `parity/gen_fixtures.py`: writes `fixtures/` (below).
- `parity/allowed_differences.json`: per-case exceptions (empty).
- `fixtures/`: the Layer-1 cases, generated and committed.

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
