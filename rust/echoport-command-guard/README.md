# echoport-command-guard (Rust port, in progress)

The Rust port of the `echoport_remote_command_guard` forced-command guard.
The plan and contract are in [PLAN.md](PLAN.md), the test map in
[TESTMAP.md](TESTMAP.md). Version 0.1.0 is released (S7, see "Release"
below) but installed nowhere; the hosts run the Python guard. 0.1.0 keeps a
race of the Python guard (the root-run `chmod`, `chown`, `mv` and `rm -f`
of `-wal`/`-shm`, PLAN.md 4.5 and R12) and must never be installed: the
first release a host gets is the one of the hardening slice H1 (work item
`echoport-guard-toctou-hardening`).

Status: **S1** (crate skeleton, policy, tokeniser), **S2** (the filesystem
layer), **S3a** (the rules without filesystem), **S3b** (the rules with
filesystem), **S4** (runtime and exec), **S5** (the parity gate: decision
property tests, Layer 2 and Layer 3 against the Python guard on both host
distributions, fuzzing; see "Parity gate" below) and **S6** (the role switch:
`roles/echoport_remote_command_guard` installs this binary through
`rust_release_binary` and selects it with `echoport_remote_command_guard_impl`,
default `python`; see its README) and **S7** (release 0.1.0: the lean
measurements, the security review of the whole crate, the tag; see "Lean
measurements", "Security review (S7)" and "Release" below). Every branch of
the Python guard's `check()` is ported. What exists:

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
  - `check()` ports the pre-checks, the prefilter (PLAN.md 4.1), the
    tokeniser and the tool dispatcher (S1); the branches that need no
    filesystem (S3a, `src/rules/`): `sudo -u postgres` and `runuser -u
    postgres --` with every PostgreSQL branch (including the `pg_restore … <
    file` redirect), `runuser -u <user> -- sqlite3` (`.backup`, `.timeout`,
    the integrity check), `systemctl`, `curl`, `rm -f` of temp dumps, `rm
    -rf --` of temp dirs, `mktemp`, `du` and the `sh -c` probe; and the
    branches that look at the filesystem through the `GuardEnv` (S3b): the
    raw `umask 077 && tar …` shape (umask `077`) and `umask 077 && cat > …`
    (a created stdout redirect), `scp -f/-t` and the three rsync server
    forms (`src/rules/transfer.rs`; uploads and receivers run as `runuser -u
    <owner> --`), `rm -f` of `-wal`/`-shm` files, the snapshot `cat` (a
    stdin redirect owned by the service user), `sha256sum`, `readlink`,
    `test`, `mv`, `mkdir -p` (as the root's owner), `chmod` and `chown`. An
    unbalanced quote inside the `tar` shape, where the Python guard crashes,
    is refused as `unparsable command: No closing quotation` (PLAN.md 4.2).
  - The filesystem layer (S2): `env::RealEnv`, the real `GuardEnv`
    (`geteuid`, `getpwnam_r` through NSS, `lstat` with glibc's `strerror`
    texts, `realpath`); `pyrealpath`, a port of CPython's non-strict
    `os.path.realpath` over `lstat`/`readlink` that refuses loops, more than
    40 symlink traversals (counted as the kernel counts them), `lstat` errors other than `ENOENT`/`ENOTDIR`, `readlink`
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
- `parity/e2e/`: the Layer-2 and Layer-3 containers (Ubuntu 24.04 with
  Python 3.12 and OpenSSH 9.6, Debian 13 with Python 3.13 and OpenSSH 10.0):
  the filesystem comparison `layer2_realpath.py` with the probe
  `examples/env-probe.rs`, the decision comparison `layer2_decide.py`, and
  the sshd end-to-end comparison `layer3_sshd.py` with its stub tools
  `stub-tool.sh` (below); `build-local-archive.sh <dest.tar.gz>` builds the
  guard in the same Debian 12 container (target `local-archive`) into a
  release-layout archive for the role's molecule scenarios.
- `fuzz/`: the cargo-fuzz targets and their committed corpus (below).

## Lean measurements (S7)

```bash
just echoport-command-guard-lean   # or rust/echoport-command-guard/parity/e2e/run-lean.sh [ubuntu2404] [debian13]
```

Needs Docker; changes nothing outside the containers. `parity/e2e/lean.py`
runs as root in each Layer-3 container (PLAN.md 8.3) and starts the Python
and the Rust guard the way sshd starts the forced command, 20 times per case
after one warm-up run: `--check-policy` on the production fixture policy, a
refusal (`id`) and an allowed command (`test -d`, so the figure includes the
exec'd tool). It reports the median (and min-max) wall time from spawn to
exit and the peak RSS as GNU `time -f %M` prints it, plus the size of the
stripped Rust binary, and exits 1 when the Rust guard exceeds a budget
(binary 2 MiB, peak RSS 4 MiB for `--check-policy` and the refusal, wall
time 5 ms) or a run has an unexpected exit status or stderr. The recorded
numbers come from the x86_64 runner of the `rust` workflow started by hand
(`gh workflow run rust.yml --ref <ref>`, job "echoport-command-guard lean
measurements"; the report is the job summary).

S7 results (2026-10-21), median of 20 runs:

| Where | Guard | `--check-policy` | Refusal | Allowed (with `test -d`) | Stripped binary |
|---|---|---|---|---|---|
| x86_64 CI runner, Ubuntu 24.04 | Python 3.12.3 | 42.32 ms, 14.25 MiB | 42.76 ms, 14.38 MiB | 39.41 ms, 14.38 MiB | |
| x86_64 CI runner, Ubuntu 24.04 | Rust | 0.96 ms, 2.38 MiB | 1.06 ms, 2.38 MiB | 1.70 ms, 2.50 MiB | 668,576 bytes |
| x86_64 CI runner, Debian 13 | Python 3.13.5 | 40.45 ms, 14.25 MiB | 40.20 ms, 14.25 MiB | 38.17 ms, 14.38 MiB | |
| x86_64 CI runner, Debian 13 | Rust | 0.99 ms, 2.25 MiB | 1.08 ms, 2.25 MiB | 1.70 ms, 2.50 MiB | 668,576 bytes |
| arm64 Docker host, Ubuntu 24.04 | Python 3.12.3 | 19.96 ms, 13.25 MiB | 22.12 ms, 13.38 MiB | 17.75 ms, 13.38 MiB | |
| arm64 Docker host, Ubuntu 24.04 | Rust | 0.27 ms, 2.00 MiB | 0.30 ms, 2.12 MiB | 0.44 ms, 2.12 MiB | 661,272 bytes |
| arm64 Docker host, Debian 13 | Python 3.13.5 | 20.73 ms, 13.36 MiB | 20.66 ms, 13.48 MiB | 18.24 ms, 13.62 MiB | |
| arm64 Docker host, Debian 13 | Rust | 0.32 ms, 1.88 MiB | 0.34 ms, 2.00 MiB | 0.49 ms, 2.12 MiB | 661,272 bytes |

The x86_64 rows are the recorded ones (`rust` workflow run 39637463506,
4 CPUs, on the S7 branch at `3b8feeb9`, whose crate sources are the
release's); the arm64 rows are a local run for comparison. Memory at rest is zero for both guards (no
resident process). S9 measures `--check-policy` again on both hosts.

## Release

The binary is released by the tag `echoport-command-guard-v<version>`
through `.github/workflows/rust-release.yml` (`rust/README.md` "Releases",
PLAN-foundation.md section 4). The crate has no `release.json`: one archive
`echoport-command-guard-<version>-x86_64-unknown-linux-gnu.tar.gz` with
`echoport-command-guard` and `LICENSE`, built on `ubuntu-22.04` (glibc floor
2.35), plus its `.sha256`, attached to
`https://github.com/ephes/ops-library/releases/tag/echoport-command-guard-v<version>`.
The role pins a version and that sha256
(`echoport_remote_command_guard_rust_version`,
`echoport_remote_command_guard_rust_sha256`); no release installs itself.

| Version | Tag (commit) | Archive sha256 | Stripped binary |
|---|---|---|---|
| 0.1.0 (S7, parity port; **never install**, PLAN.md R12) | `echoport-command-guard-v0.1.0` (`5b734af5`) | `300c849c7883275b600054e4e41d457f49d90ec61d116cb2d63dbeea2f4953c9` | 668,632 bytes (0.64 MiB), highest `GLIBC_2.34` |

## Security review (S7)

PLAN.md R2 asks for a dedicated security review of the whole crate before
the first release: `gpt-6.1-sol` at high reasoning over every production
source (`src/`, `build.rs`, `Cargo.toml`, `examples/`), focused on
acceptance drift against the Python guard, path handling (realpath, root
containment, the redirect opens) and fd/exec hygiene. It found no acceptance
drift and one Critical finding, which the Python guard has as well: the
root-run `chmod 0600|0700`, `chown [-R]`, `mv` and `rm -f` of `-wal`/`-shm`
are checked on the resolved path and then executed as root on the original
pathname, so the root's service user can swap in a symlink in between and
redirect them outside the root (the reviewer reproduced it with `chmod`
through the forced command). The owner accepted it for 0.1.0 only, as a
parity port (2026-10-21; PLAN.md 4.5, R12, the role README "Files the guard
opens itself"). The hardening slice H1 fixes it in both guards before any
install (S9 depends on it).

## Build and test

From `rust/` in a worktree (never in a shared checkout; this writes
`rust/target/`), or with `just rust-check` from the repository root:

```bash
cargo test -p echoport-command-guard --locked
```

The tests:

- `src/**` unit tests: prefilter, tokeniser, `repr`, `normpath`, the policy
  loader and its helpers (scratch databases, `mktemp` results), the
  dispatcher and the rules (`rules::{postgres,sqlite,files,transfer}`,
  with virtual filesystems for the S3b branches; their expected reasons are
  the Python guard's), `pyrealpath`, and the `rules::paths` helpers with
  Python's refusal reasons.
- `tests/layer1.rs`, the Layer-1 runner: every decision and policy case of
  `fixtures/` against the Rust guard, with the case's recorded environment as
  a virtual `GuardEnv`. A Rust acceptance must equal Python's decision, and
  every case Python allows must be allowed (no branch is pending since
  S3b). A refusal must be Python's, with Python's reason, unless the case
  is listed in `parity/allowed_differences.json`, or has a `p3` tag and is
  refused by the prefilter. Where Python's `check()` crashes (the
  `python-error` cases), Rust's reason must be `unparsable command:
  <Python's error text>`. Policy cases must give Python's verdict, normalized policy
  and error type, and Python's message for `Refused` and `KeyError` texts in
  printable ASCII (PLAN.md 4.3).
- `tests/tokeniser.rs`: the tokeniser against Python's `shlex.split` through
  the oracle server, over every fixture command that passes the prefilter
  and over 2,000 seeded random commands (proptest). `PROPTEST_CASES=100000`
  runs more, `PROPTEST_RNG_SEED=<n>` changes the seed.
- `tests/decisions.rs` (S5, PLAN.md 7.3): random commands against both
  guards through the oracle server, each in a random virtual host. The
  commands are an accepted command of the curated fixture sources (with its
  recorded host) or a tool followed by words of the policies' vocabulary,
  then up to four mutations (drop, duplicate, swap, replace or insert a
  word, metacharacter tails, requoting, whitespace, path forms, control,
  non-ASCII and invalid UTF-8 characters, backslash escapes, lengths around
  4096); the host gives each path the command names a random `lstat` answer
  (the seven file types with modes, owners and link counts, absent, `lstat`
  errors) and `realpath` (itself, another of the paths, a root, outside),
  runs as root or not, and sometimes lacks a user. A Rust acceptance must
  equal Python's decision and keep the invariants of
  `tests/common/invariants.rs` (the executed tool is a guard tool, `sudo`
  is `sudo -n -u postgres --`, uploads and `mkdir` run as `runuser -u
  <user>` with a user other than root, every path in the decision is a
  safe path); a Rust refusal must be Python's, except for the PLAN.md 4.4
  classes (a command outside the prefilter's alphabet, which the prefilter
  refuses, and a `check()` crash of Python). 2,000 seeded cases in CI;
  `PROPTEST_CASES=100000` runs more, `PROPTEST_RNG_SEED=<n>` changes the
  seed.
  Raw `umask 077 && ...` shapes keep their operators unquoted, and the test
  requires acceptances of both of them. S5 ran 100,000 cases with the oracle
  under Python 3.12 and 3.13: 12,284 equal acceptances (411 `tar`, 399 `cat
  >`), 67,597 equal refusals, 20,119 prefilter refusals (1,011 of them
  commands Python allows, all through backslash escapes), no difference.
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

## Layer 2: real trees in the host distributions

```bash
just echoport-command-guard-layer2   # or rust/echoport-command-guard/parity/e2e/run-layer2.sh [ubuntu2404] [debian13]
```

Needs Docker; changes nothing outside the containers. It builds the guard
and `examples/env-probe.rs` (the real `GuardEnv` as JSON lines) with the
pinned toolchain on Debian 12, then runs two scripts as root in an Ubuntu
24.04 (Python 3.12.3) and a Debian 13 (Python 3.13.5) container with the
policies' users. The Python guard is mounted read-only (it lies outside the
`rust/` build context).

**The filesystem layer** (S2): `parity/e2e/layer2_realpath.py` runs as root in an
Ubuntu 24.04 (Python 3.12.3) and a Debian 13 (Python 3.13.5) container with
the policies' users, and fails on any difference PLAN.md 4.2 does not allow.
A loop refusal must be confirmed by a resolver without Python's `seen` map.
The script builds real trees under the policies' path roots: links in and
out of a root, dangling links, `..` in targets, loops, a replaced
directory, files below which nothing exists (`ENOTDIR`), hard links, a fifo,
foreign owners, 40- and 41-link chains (one of them through a single cached
link), an `ENAMETOOLONG` component, a
non-UTF-8 link target, an `EACCES` case run as `nobody`, and 300 seeded
random trees (`ECHOPORT_L2_ARGS="--random 3000 --seed 7"` for more). It
compares `realpath`, `lstat` (kind, mode, uid, link count, or errno and
`strerror`), user lookups and the euid. `ECHOPORT_E2E_SUFFIX` is appended to
the image and container names.

S2 results (2026-10-21, arm64 Docker host): 1,533 `realpath` and 1,727
`lstat` comparisons per distribution (also clean with 3,000 random trees,
seed 7), no difference; the refusals were the expected ones (`ELOOP` for the
loops and the 41-traversal chains, `ENAMETOOLONG`, `EILSEQ`, `EACCES`). Run with
`--probe <bin> --realpath-only` the same script evaluates another resolver;
that is how `soft-canonicalize` 0.5.6 was measured (PLAN.md 5.2: 265 of
1,531 differ, on the corpus before the cached-link chain was added).

**The decisions** (S5): `parity/e2e/layer2_decide.py` runs the Python
guard's `check()` with the real `os.path.realpath`, `os.lstat`, `pwd` and
euid and the Rust binary's `--decide` on the same real trees and compares
the decisions. For every path-taking shape (`scp -f/-t` of dumps, the
private media archive, read files and root files; the three rsync forms;
`rm` of `-wal`/`-shm`; the `tar` and `cat >` shapes; the snapshot `cat`
and `chown`; `chown -R`, `readlink`, `test`, both `mv` forms, `mkdir`,
`chmod`, `sha256sum`, the `pg_restore < file` redirect), under both fixture
policies and each root, it materialises every state of the paths the
command names: the target file (absent, regular and owned by root, postgres,
the root's owner or nobody, a hard link, a link inside or outside the root,
dangling, a loop, a fifo, a socket, a device, a directory), a directory the
guard requires private (`0700`, `0750`, `0777`, someone else's, a link to a
private directory, absent, a file) and a parent component (a directory, a
link inside the root, outside it, to `../..`, to the root by its absolute
path, with `..` in its target, a loop, dangling, a file). It also runs
`GuardRefusals.test_scp_against_a_real_tree` on a real tree with its own
policy, seven shapes as `nobody` (real `EACCES`, euid checks) and 200
seeded random trees under the roots with random commands into them
(`ECHOPORT_L2_DECIDE_ARGS="--random 1000 --seed 7"` for more). When Rust
allows, Python must allow with the same decision; when Rust refuses, Python
must refuse with the same reason, except for the PLAN.md 4.2 realpath
refusals (a loop, `EACCES`, `ENAMETOOLONG`, a non-UTF-8 link target), each
confirmed by an independent component-by-component resolution of the path
as the same user (without Python's `seen` map for loops), and Python's
`check()` crashes.

S5 results (2026-10-21, arm64 Docker host), the same on both distributions:
1,359 equal acceptances and 492 equal refusals over 28 shapes and 200
random trees, 128 realpath refusals Python resolves past (124 loops, 4
`EACCES` as `nobody`), no difference. With 1,000 random trees (seed 7):
4,546 equal acceptances, 1,134 equal refusals, 299 realpath refusals (295
loops, 4 `EACCES`), no difference.

## Layer 3: end to end through sshd

```bash
just echoport-command-guard-layer3   # or rust/echoport-command-guard/parity/e2e/run-layer3.sh [ubuntu2404] [debian13]
```

Needs Docker; changes nothing outside the containers. The Layer-2 images
plus `openssh-server`, `openssh-client` and `rsync`
(`parity/e2e/Dockerfile`, target `layer3`); `parity/e2e/layer3_sshd.py`
runs as root inside. It binds a syslog receiver to `/dev/log`, starts sshd
on 127.0.0.1 (the hosts' `SyslogFacility AUTH`, `AcceptEnv LANG LC_*`; no
PAM in a container) and gives root one `authorized_keys` line per
implementation and fixture policy, with `restrict` and the forced command of
PLAN.md 6.2: `python` (`/usr/bin/python3 -I
/usr/local/sbin/echoport-remote-command-guard <policy>`), `rust` (`<bin>
<policy>`) and `shadow` (`<bin> --shadow <policy> /usr/bin/python3 -I
<pyguard> <policy>`), the binary at
`/usr/local/lib/echoport-command-guard/<version>/echoport-command-guard`.
Each scenario runs once per implementation from the same fresh state:

- every command the runners send (`fixtures/corpus/runner.jsonl`, 130
  commands) with `ssh`, in a state where the Python guard allows it (the
  harness fails otherwise). `systemctl`, `sudo`, `pg_dump`, `pg_restore`,
  `psql`, `createdb`, `dropdb`, `sqlite3` and `curl` are stubs
  (`parity/e2e/stub-tool.sh`, in `/usr/local/bin`, which `runuser` keeps on
  its search path) that record argv, environment, the targets of fds 0-2,
  the open fds, the signal mask and ignored signals, the umask and the uid,
  and act just enough like the tool; `runuser`, `scp`, `rsync`, `tar`,
  `cat`, `mv`, `chown`, `mkdir` and the rest are real;
- real `scp -O` downloads (a dump, the read file, the private media
  archive) and uploads (into a root as its owner, a restore dump as
  postgres, through a symlink), the three rsync forms with the real client
  (and `-L`, refused), `cat >` with 15 kB of data and onto an existing file,
  the snapshot `cat` (and of a symlink), the `pg_restore < file` redirect,
  `tar` with the umask, `mkdir -p` as the owner, refused commands, the
  PLAN.md 4.1 prefilter (a backslash escape Python allows, `#`, non-ASCII),
  an interactive session, SFTP, the environment without a client `LANG`,
  with `LANG=C.UTF-8` and with `LANG=C`, and a missing tool (exit 127).

Compared between `python` and `rust`: exit code, stdout, stderr, the files
on both sides afterwards (kind, content, owner, group, mode, link count),
the stub records and the syslog lines (identifier, facility and priority,
message without the PID). `shadow` must give exactly what `python` gives,
plus one record under `echoport-remote-command-guard-shadow` with Python's
verdict and reason (a redirect that fails to open is `allowed` there). For
the prefilter scenarios Rust must refuse (`command not allowed`, the
prefilter's reason, nothing run).

Two things the harness normalises, because neither comes from the guard:
sshd runs the forced command through root's shell (`bash -c`), which sets
`_` to the program it starts (the guard's own path); and the random names
`mktemp -d` returns. The stub reads its signal mask before it starts any
child, because the shell blocks signals while it waits for one.

S5 results (2026-10-21, arm64 Docker host): 161 scenarios on each
distribution (148 allowed by Python, 12 refused, 1 interactive), Ubuntu
24.04 (Python 3.12.3, OpenSSH 9.6p1) and Debian 13 (Python 3.13.5, OpenSSH
10.0p2): no difference between `python`, `rust` and `shadow`.

## Fuzzing

```bash
just echoport-command-guard-fuzz       # or rust/echoport-command-guard/fuzz/run-fuzz.sh [seconds] [target...]
rust/echoport-command-guard/fuzz/run-fuzz.sh cmin   # minimise the corpus before committing it
```

`fuzz/` is a cargo-fuzz project outside the workspace (it needs nightly and
libFuzzer; CI uses the pinned stable toolchain, so fuzzing is not a CI gate).
`run-fuzz.sh` builds an image with a pinned nightly (`nightly-2026-10-01`)
and cargo-fuzz 0.13.2 (`fuzz/Dockerfile`), builds the targets with debug
assertions and runs each for an hour by default, all four at once, one
container each, on the committed corpus in `fuzz/corpus/<target>/` (found
crashes land in `fuzz/artifacts/`, the logs in `fuzz/run-<target>.log`). The
targets (PLAN.md 7.4):

- `prefilter_tokens`: arbitrary bytes through the pre-checks, the prefilter,
  the two raw shapes and the tokeniser: no panic, and whatever passes the
  prefilter is printable ASCII and tab without `\` and `#`, and splits or
  fails only with `No closing quotation`;
- `check`: an arbitrary command against either policy, as root or not, in a
  host the input chooses (every path the command could name gets an
  `lstat` answer of any kind, mode, owner and link count, or an error, and
  a `realpath` answer, including errors): no panic, and every acceptance
  keeps the invariants of `tests/common/invariants.rs`;
- `policy`: arbitrary bytes as a policy file: no panic, an accepted policy
  satisfies the validation of PLAN.md 3.2, and decisions under it keep the
  invariants;
- `py_repr`: arbitrary bytes through Python's `repr`: no panic, one quoted
  string of printable ASCII, the same as for the decoded text.

The corpus was seeded from the Layer-1 fixtures (`fuzz/seed_corpus.py`) and
minimised with `cargo fuzz cmin` after the run. S5 results (2026-10-21,
arm64 Docker host, `nightly-2026-10-01`, 3,701 seconds per target, all four
at once): `prefilter_tokens` 207.6 million runs, `check` 11.2 million,
`policy` 85.2 million, `py_repr` 214.6 million; no crash, no broken
assertion, so no new Layer-1 fixture. The committed corpus after `cmin`:
290, 1,328, 2,024 and 228 files (1.7 MB in all).

## Parity gate (S5): the PLAN.md 4.4 review

Every allowed difference is a stricter refusal (PLAN.md 4). S5 reviewed each
class the generator tags with `p3` and the per-case list:

- `prefilter` (2,902 Layer-1 cases) and `invalid-utf8` (32): the Rust guard
  refuses all of them in the prefilter; Python refuses all of them too, with
  other reasons. Python allows a command outside the prefilter's alphabet
  only through a backslash escape (`systemctl start marina\.service`), which
  no runner sends (S0's corpus check); the decision property tests generate
  such escapes and Layer 3 sends one through sshd: Rust refuses, as decided
  (PLAN.md 4.1, Q2).
- `python-error` (5): Python's `check()` crashes on an unbalanced quote in
  the `tar` shape and runs nothing; Rust refuses with `unparsable command:
  No closing quotation`.
- `policy-type` (33, of which Python accepts 21) and
  `policy-trailing-newline` (12, Python accepts 10): policy documents the
  role never writes (strings for lists, numbers, `false`, pairs, duplicate
  keys, non-standard JSON, values ending in `\n`); Rust refuses them
  (PLAN.md 4.2). S9 runs the Rust `--check-policy` on both live policies
  before anything switches.
- The realpath refusals of PLAN.md 4.2 do not occur in Layer 1 (it injects
  `realpath`); Layer 2 meets them on real trees (loops confirmed by the
  resolver without `seen`, `EACCES`) and finds no other difference.
- `parity/allowed_differences.json` stays empty: no case needs an exception
  beyond these classes, for the Python 3.12 and 3.13 decisions alike.

Layer 1 (13,149 decision and 244 policy cases): 3,505 equal acceptances,
6,710 equal refusals (the 5 `python-error` cases included), 2,934 prefilter
refusals; 207 equal policy verdicts and 37 `p3` refusals.

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
