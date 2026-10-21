# echoport-command-guard (Rust port, in progress)

The Rust port of the `echoport_remote_command_guard` forced-command guard.
The plan and contract are in [PLAN.md](PLAN.md), the test map in
[TESTMAP.md](TESTMAP.md). Nothing here is released or deployed yet; the
hosts run the Python guard.

Status: **S1** (crate skeleton, policy, tokeniser), **S2** (the filesystem
layer), **S3a** (the rules without filesystem) and **S4** (runtime and
exec). What exists:

- The crate (a member of the `rust/` workspace): the library that decides and
  the binary `echoport-command-guard`.
  - `--version` prints `echoport-command-guard <version> (<commit>)`
    (`build.rs`: `ECHOPORT_COMMAND_GUARD_GIT_COMMIT`, else `git rev-parse
    HEAD`, else `unknown`).
  - `--check-policy <file>` validates a policy file as the Python guard does
    (exit 0, or `echoport-remote-command-guard: invalid policy: <detail>` on
    stderr and exit 1), with the stricter types of PLAN.md 4.2.
  - `<prog> <policy>` is forced-command mode, the Python guard's flow
    (PLAN.md 3.1; `src/modes.rs`): an unset `SSH_ORIGINAL_COMMAND` is
    refused before the policy is read (`interactive sessions are not
    allowed`), a policy error refuses (`policy error`), then `check()`, the
    umask, the redirects (`src/redirect.rs`: `O_NOFOLLOW` opens relative to
    a checked private directory), the `allowed from` log line, and the exec
    (`src/exec.rs`): `PATH` set to `SAFE_PATH`, CPython's PEP 538 `LC_CTYPE`
    coercion, SIGPIPE and SIGXFSZ ignored, and CPython's `os.execvp` search
    (no `/bin/sh` fallback; `cannot run <tool>: <strerror>`, exit 127).
    Every refusal is exit 1 with `command not allowed`; a panic refuses and
    never execs. Log lines go to syslog as the Python guard's
    (`openlog("echoport-remote-command-guard", LOG_PID, LOG_AUTH)`, Python's
    `repr` of the command, cut at 1000 characters; `src/syslog.rs`).
  - `--decide <policy>` prints the decision for `SSH_ORIGINAL_COMMAND` as
    one JSON line on stdout and exits 0 when it is allowed, else 1. The
    verdicts are `allowed` (with `argv`, `umask`, `stdin`, `stdout`, the
    fixtures' form), `refused` (`reason`), `interactive`, `policy-error`
    (`error_type`, `message`) and `panic` (`reason`). It never opens a
    redirect, logs or executes anything.
  - `--shadow <policy> </abs/python> -I </abs/guard> <policy>` logs the same
    JSON record under the identifier `echoport-remote-command-guard-shadow`
    (priority info; `check()` only, so a redirect that later fails to open
    is still `allowed` there), then always `execv`s `<python> -I <guard>
    <policy>` with the environment unchanged; the PID stays, so the two
    log lines pair up by `_PID`. Any other tail (not absolute, not `-I`,
    another policy path, extra arguments) is exit 2 and executes nothing.
  - Any other argv is the Python guard's usage error (exit 2).
  - The binary's `GuardEnv` is `env::RealEnv` (S2, below): the real euid,
    NSS user lookups, `lstat` and `realpath`.
  - `check()` ports the pre-checks, the prefilter (PLAN.md 4.1), the two raw
    shapes (detected only), the tokeniser and the tool dispatcher (S1), and
    the branches that need no filesystem (S3a, `src/rules/`): `sudo -u
    postgres` and `runuser -u postgres --` with every PostgreSQL branch
    (including the `pg_restore … < file` redirect), `runuser -u <user> --
    sqlite3` (`.backup`, `.timeout`, the integrity check), `systemctl`,
    `curl`, `rm -f` of temp dumps, `rm -rf --` of temp dirs, `mktemp`, `du`
    and the `sh -c` probe. The branches that look at the filesystem (the raw
    `tar` and `cat >` shapes, `scp`, `rsync`, `rm -f` of `-wal`/`-shm`
    files, `cat`, `sha256sum`, `readlink`, `test`, `mv`, `mkdir`, `chmod`,
    `chown`) still refuse; S3b ports them.
  - The filesystem layer (S2): `env::RealEnv`, the real `GuardEnv`
    (`geteuid`, `getpwnam_r` through NSS, `lstat` with glibc's `strerror`
    texts, `realpath`); `pyrealpath`, a port of CPython's non-strict
    `os.path.realpath` over `lstat`/`readlink` that refuses loops, more than
    40 links, `lstat` errors other than `ENOENT`/`ENOTDIR`, `readlink`
    errors and non-UTF-8 link targets (PLAN.md 4.2); and `rules::paths`, the
    helpers of `check()` (`_root_for`, `_require_in_roots`,
    `_lstat_or_none`, `_require_plain_file_or_absent`,
    `_require_private_dir`, `_user_uids`) with Python's refusal reasons.
    The `soft-canonicalize` crate was evaluated and rejected (PLAN.md 5.2).
- `parity/oracle.py`: the Python guard as the oracle. A module for the
  generator and the tests, and a JSON-lines server (`python3 -I
  parity/oracle.py`) with the ops `ping`, `check`, `split`, `check_policy`,
  `realpath` (over a virtual tree) and `os_realpath` (real filesystem) for
  the Rust property tests. Stdlib only.
- `parity/gen_fixtures.py`: writes `fixtures/` (below).
- `parity/allowed_differences.json`: per-case exceptions (empty).
- `fixtures/`: the Layer-1 cases, generated and committed.
- `parity/e2e/`: the Layer-2 containers (Ubuntu 24.04 with Python 3.12,
  Debian 13 with Python 3.13) and, so far, the filesystem comparison
  `layer2_realpath.py` with the probe `examples/env-probe.rs` (below).

## Build and test

From `rust/` in a worktree (never in a shared checkout; this writes
`rust/target/`), or with `just rust-check` from the repository root:

```bash
cargo test -p echoport-command-guard --locked
```

The tests:

- `src/**` unit tests: prefilter, tokeniser, `repr`, `normpath`, the policy
  loader and its helpers (scratch databases, `mktemp` results), the
  dispatcher and the S3a rules (`rules::{postgres,sqlite,files}`; their
  expected reasons are the Python guard's), `pyrealpath`, and the
  `rules::paths` helpers with Python's refusal reasons.
- `tests/layer1.rs`, the Layer-1 runner: every decision and policy case of
  `fixtures/` against the Rust guard, with the case's recorded environment as
  a virtual `GuardEnv`. A Rust acceptance must equal Python's decision. A
  refusal by a branch that is not ported yet counts as pending, and only a
  command that reaches an S3b branch may be pending. Any other refusal must
  be Python's, with Python's reason, unless the case is listed in
  `parity/allowed_differences.json`, or has a `p3` tag and is refused by the
  prefilter or is a `python-error` case. Policy cases must
  give Python's verdict, normalized policy and error type, and Python's
  message for `Refused` and `KeyError` texts in printable ASCII (PLAN.md 4.3).
- `tests/tokeniser.rs`: the tokeniser against Python's `shlex.split` through
  the oracle server, over every fixture command that passes the prefilter
  and over 2,000 seeded random commands (proptest). `PROPTEST_CASES=100000`
  runs more, `PROPTEST_RNG_SEED=<n>` changes the seed.
- `tests/realpath.rs`: `pyrealpath` against `os.path.realpath` through the
  oracle server, over 2,000 random virtual trees (the oracle's `realpath`)
  and 500 random real trees in a temp directory with the real `GuardEnv`
  (`os_realpath`), plus fixed cases, the 40-link limit and `RealEnv`'s
  `lstat`, `euid` and user lookups on a real directory. Rust must resolve to
  Python's string or refuse as PLAN.md 4.2 allows; a loop refusal must be
  confirmed by a resolver without Python's `seen` map.
- `src/redirect.rs` tests (`GuardRedirects`): on real temporary
  directories; the exact `OSError` texts are checked on Linux.
- `tests/cli.rs`: the binary's argv grammar, `--version`, `--check-policy`,
  forced-command refusals (interactive, refused commands, broken policies),
  `--decide` with the real `check()`, and `--shadow`'s argv rule and its
  exec of a stand-in Python guard with the same PID. On Linux these runs write a few
  refusal lines to the system log of the machine that runs them.
- `tests/flow.rs` (own `main`, no libtest): the forced-command flow,
  `--decide` and `--shadow` in a real child process with a stub `check()`
  that returns the decision a test asks for, a test search path instead of
  `SAFE_PATH` and a log file instead of syslog. The exec target is a probe
  script that records what it inherited: argv, environment (`PATH`,
  `LC_CTYPE` compared with what the CPython of `$ECHOPORT_ORACLE_PYTHON`
  exports for the same environment), umask, ignored signals, open fds,
  stdin, stdout. Also the exec search (`ENOEXEC`, `EACCES`, `ENOENT`, a
  later valid candidate, no shell), the redirect failures, panics and the
  log texts. The probes read `/proc`: on Linux they run (CI), elsewhere the
  test prints a skip line. On macOS run them in a container, for example
  from the repository root:

  ```bash
  docker run --rm -v "$PWD":/work:ro -v ep-guard-target:/target \
    -e CARGO_TARGET_DIR=/target -w /work/rust rust:1.99.1-bookworm \
    cargo test -p echoport-command-guard --locked --test flow
  ```

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

## Layer 2: the filesystem layer on real trees

```bash
just echoport-command-guard-layer2   # or rust/echoport-command-guard/parity/e2e/run-layer2.sh [ubuntu2404] [debian13]
```

Needs Docker; changes nothing outside the containers. It builds
`examples/env-probe.rs` (the real `GuardEnv` as JSON lines) with the pinned
toolchain on Debian 12, runs `parity/e2e/layer2_realpath.py` as root in an
Ubuntu 24.04 (Python 3.12.3) and a Debian 13 (Python 3.13.5) container with
the policies' users, and fails on any difference PLAN.md 4.2 does not allow.
The script builds real trees under the policies' path roots: links in and
out of a root, dangling links, `..` in targets, loops, a replaced
directory, files below which nothing exists (`ENOTDIR`), hard links, a fifo,
foreign owners, a 40- and a 41-link chain, an `ENAMETOOLONG` component, a
non-UTF-8 link target, an `EACCES` case run as `nobody`, and 300 seeded
random trees (`ECHOPORT_L2_ARGS="--random 3000 --seed 7"` for more). It
compares `realpath`, `lstat` (kind, mode, uid, link count, or errno and
`strerror`), user lookups and the euid. `ECHOPORT_E2E_SUFFIX` is appended to
the image and container names.

S2 results (2026-10-21, arm64 Docker host): 1,531 `realpath` and 1,640
`lstat` comparisons per distribution (15,031 and 15,140 with 3,000 random
trees), no difference; the refusals were the expected ones (`ELOOP` for the
loops and the 41-link chain, `ENAMETOOLONG`, `EILSEQ`, `EACCES`). Run with
`--probe <bin> --realpath-only` the same script evaluates another resolver;
that is how `soft-canonicalize` 0.5.6 was measured (PLAN.md 5.2: 265 of
1,531 differ).

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
