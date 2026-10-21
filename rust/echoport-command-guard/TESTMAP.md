# Python test → Rust test map (echoport-command-guard)

Every Python test that pins guard behaviour gets a Rust counterpart: a Rust
unit or process test, a Layer-1 fixture case, or a Layer-2/3 container case
(PLAN.md 7). Each slice fills in the rows it covers; S5 requires every row
filled. Status: `pending (Sn)`, `done (Sn)`, or `n/a` with the reason.

Baseline: `tests/test_echoport_remote_command_guard.py` at ops-library
`19f3ba86` (33 test methods in 6 classes), guard sha256 `ca74405e…`
(`fixtures/GUARD_SHA256`).

Kinds:

- **fixture**: a Layer-1 case in `fixtures/`, generated from the Python guard
  by `parity/gen_fixtures.py` (S0). Source `unit` replays every `check()` and
  `Policy.from_dict()` call the Python unit tests make, with the lstat,
  realpath and user lookups recorded (a command two tests share is listed
  once, under the first test by name); source `runner` every command the
  runners send; `journal`, `mutation`, `fs` and `policy` are generated
  (PLAN.md 7.2). The Rust Layer-1 runner (S1) reads them; since S3b every
  branch is ported and every case is decided.
- **unit** / **process**: Rust tests (`src/**` unit tests, `tests/cli.rs`).
- **Layer 2** / **Layer 3**: container differential and sshd end-to-end tests
  (`parity/e2e/`, PLAN.md 7.5, 7.6).

## Guard rules (`GuardAllowsRunnerShapes`, 7 tests)

| Python test | Fixture (S0) | Rust counterpart | Status |
| --- | --- | --- | --- |
| `test_postgres_dump_and_restore` | `unit.jsonl` | Layer-1 runner; `rules::postgres` unit tests | done (S0, S3a) |
| `test_tar_runs_with_umask` | `unit.jsonl` (allowed; foreign, open and symlinked dir; symlinked archive) | Layer-1 runner; `rules::files::tests::tar_runs_with_umask` | done (S0, S3b) |
| `test_uploads_run_as_the_target_owner` | `unit.jsonl` | Layer-1 runner; `rules::transfer::tests::scp_uploads_run_as_the_target_owner`, `exact_rsync_commands`; `rules::files::tests::mkdir_runs_as_the_roots_owner` | done (S0, S3b) |
| `test_exact_rsync_commands` | `unit.jsonl` | Layer-1 runner; `rules::transfer::tests::exact_rsync_commands` | done (S0, S3b) |
| `test_django_chat_shapes` | `unit.jsonl` | Layer-1 runner; `rules::postgres` unit tests (scratch restore, runner queries) | fixture done (S0); PostgreSQL, `mktemp`, `rm -rf` done (S3a); `cat >`, `sha256sum` done (S3b) |
| `test_gotosocial_shapes` | `unit.jsonl` (`.timeout` included) | Layer-1 runner; `rules::sqlite` unit tests | fixture done (S0); `sqlite3`, `systemctl`, `mktemp`, `rm -rf`, `curl` done (S3a); `chown`, snapshot `cat`, `rm` wal/shm done (S3b) |
| `test_policy_rejects_unsafe_entries` | `policy.jsonl` (source `unit`) | `tests/layer1.rs` `policy_fixtures` over `policy.jsonl`; `policy::tests` | done (S1) |

## Refusals (`GuardRefusals`, 9 tests)

| Python test | Fixture (S0) | Rust counterpart | Status |
| --- | --- | --- | --- |
| `test_arbitrary_commands` | `unit.jsonl` (both policies) | Layer-1 runner; `rules::tests` | unknown tools, prefilter and tokeniser stages done (S1); S3a tool branches done (S3a); S3b tool branches done (S3b) |
| `test_host_specific_rules` | `unit.jsonl` | Layer-1 runner | fixture done (S0); S3a branches done (S3a); S3b branches done (S3b) |
| `test_symlink_escape_is_refused` | `unit.jsonl` (realpath recorded) | Layer-1 runner; `rules::paths::tests::roots_as_python`; `rules::files::tests::rm_of_sqlite_side_files_inside_a_root`, `rules::transfer::tests::scp_download_checks_the_resolved_path` | helper done (S2); rules done (S3b) |
| `test_rsync_options_must_match_exactly` | `unit.jsonl`; `mutation/tools.jsonl` (`rsync-*`) | Layer-1 runner; `rules::transfer::tests::exact_rsync_commands` | done (S0, S3b) |
| `test_scp_refuses_targets_that_are_not_plain_files` | `unit.jsonl` (lstat recorded); `fs.jsonl` | Layer-1 runner; `rules::paths::tests::plain_file_reasons_as_python`; `rules::transfer::tests` | helper done (S2); rule done (S3b) |
| `test_scp_against_a_real_tree` | — (real filesystem) | Layer 2 | filesystem part done (S2: `parity/e2e/layer2_realpath.py`, the real `GuardEnv` against Python 3.12 and 3.13); the `scp` decision pending (S5) |
| `test_mv_only_onto_new_names_within_one_root` | `unit.jsonl`; `fs.jsonl` | Layer-1 runner; `rules::files::tests::mv_only_onto_new_names_within_one_root` | done (S0, S3b) |
| `test_django_chat_refusals` | `unit.jsonl` | Layer-1 runner; `rules::postgres` unit tests; `rules::files::tests` (`cat >`, `sha256sum`) | fixture done (S0); S3a branches done (S3a); S3b branches done (S3b) |
| `test_gotosocial_refusals` | `unit.jsonl` | Layer-1 runner; `rules::sqlite` unit tests; `rules::files::tests` (`chown`, snapshot `cat`) | fixture done (S0); S3a branches done (S3a); S3b branches done (S3b) |

## Redirects (`GuardRedirects`, 5 tests)

`redirect::tests` on real temporary directories (macOS and Linux; the exact
`OSError` texts are checked on Linux), with a virtual `GuardEnv` for the
euid and owner lookups, as the Python test patches `os.geteuid`. The full
flow with redirects onto fds 0 and 1 is `tests/flow.rs`.

| Python test | Rust counterpart | Status |
| --- | --- | --- |
| `test_create_is_exclusive_and_private` | `redirect::tests::create_is_exclusive_and_private`; `tests/flow.rs` `create_redirect_with_umask` | done (S4) |
| `test_read_plain_file` | `redirect::tests::read_plain_file` (blocking again, close-on-exec); `tests/flow.rs` `read_redirect` | done (S4) |
| `test_refuses_links_and_special_files` | `redirect::tests::refuses_links_and_special_files` (also a directory opened for create, a missing file) | done (S4) |
| `test_refuses_a_shared_or_foreign_directory` | `redirect::tests::refuses_a_shared_or_foreign_directory` (also an owner from the decision, and one that does not exist) | done (S4) |
| `test_refuses_a_symlinked_directory` | `redirect::tests::refuses_a_symlinked_directory` | done (S4) |

## Forced-command flow (`GuardMain`, 5 tests)

Process tests: the binary itself (`tests/cli.rs`, real `check()` and
syslog) for everything that refuses, and `tests/flow.rs` for the whole flow
up to the exec, with a stub `check()`, a probe as the exec target on a test
search path, and a log file (Linux; PLAN.md 7.1). The real `SAFE_PATH`
with stub tools is Layer 3 (S5).

| Python test | Rust counterpart | Status |
| --- | --- | --- |
| `test_interactive_session_is_refused` | `tests/cli.rs` `forced_command_mode_refuses`; `tests/flow.rs` `interactive_session_is_refused` (log line, before the policy) | done (S4) |
| `test_refused_command_is_not_executed` | `tests/cli.rs` `forced_command_mode_refuses`; `tests/flow.rs` `refused_command_is_not_executed`, `real_check_refusals_and_log_text` | done (S4) |
| `test_allowed_command_is_executed_without_shell` | `tests/flow.rs` `allowed_command_runs_with_the_python_guards_inheritance` (argv, `PATH`, environment, fds, signals, umask, stdin/stdout untouched), `exec_search_is_cpythons` | done (S4) |
| `test_broken_policy_refuses_everything` | `tests/cli.rs` `broken_policy_refuses_everything`; `tests/flow.rs` `broken_policy_refuses_everything` (`policy error (<ExcType>)` lines); the documents are in `policy.jsonl` (source `unit`, label `GuardMain`) | done (S0, S4) |
| `test_check_policy_mode` | `tests/cli.rs` `check_policy_*`, `broken_policy_refuses_everything` (`<prog> --check-policy` is forced-command mode); `policy.jsonl` | done (S1, S4) |

## Runners (`RunnerCommandsAreAllowlisted`, 6 tests; `RunnersUseClassicScp`, 1 test)

The recorded commands are `fixtures/corpus/runner.jsonl`; their decisions are
`runner.jsonl` (all allowed).

| Python test | Fixture (S0) | Rust counterpart | Status |
| --- | --- | --- | --- |
| `test_production_db_runners` | `runner.jsonl` | Layer-1 runner | done (S0, S3a, S3b) |
| `test_staging_db_runners` | `runner.jsonl` | Layer-1 runner | done (S0, S3a, S3b) |
| `test_marina_runner` | `runner.jsonl` | Layer-1 runner | done (S0, S3b) |
| `test_villakunterbunt_runner` | `runner.jsonl` | Layer-1 runner | done (S0, S3b) |
| `test_django_chat_runner` | `runner.jsonl` | Layer-1 runner | done (S0, S3a, S3b) |
| `test_gotosocial_runner` | `runner.jsonl` | Layer-1 runner | done (S0, S3a, S3b) |
| `RunnersUseClassicScp.test_scp_helpers_pass_dash_O` | — | n/a: tests the runner templates, not the guard; stays Python | n/a |

## Other suites

| Python test | Rust counterpart | Status |
| --- | --- | --- |
| `tests/test_sqlite_backup_runners.py` (`.timeout`) | `mutation/tools.jsonl` (`sqlite-timeout`: 1, 30000, 999999 accepted; 0, 1000000, `01`, `-1`, extra space, missing `.backup`, order refused) and `sqlite-backup`; `rules::sqlite` unit tests | done (S0, S3a) |
| ops-control `test_echoport_remote_command_guard_policy.py` | `policy.jsonl` (`tests/layer1.rs`) plus the S8 Rust `--check-policy` test | Rust done (S1); ops-control pending (S8) |
| role molecule verify | scenarios `default` (impl python), `shadow` and `rust` on Ubuntu 24.04 and Debian 13 run the same `molecule/shared/verify.yml`; the shadow run pairs every guard journal line with one shadow line by `_PID`. | done (S6) |
| — (new in S6) role switch, pin and prune | molecule scenario `pins` (stub releases, impl shadow, real sshd); `tests/test_echoport_remote_command_guard_role.py` (the live-state filter, the forced command per impl, `confirm_live.yml` on localhost) | done (S6) |

## New in S0 (Python, `tests/test_echoport_command_guard_fixtures.py`)

| Test | What it pins | Rust counterpart | Status |
| --- | --- | --- | --- |
| `FixturesMatchTheGuard.test_guard_sha256` | `fixtures/GUARD_SHA256` is the guard's sha256 | the drift step in `rust.yml`; the oracle tests compare the oracle's guard with it | done (S0, S1) |
| `FixturesMatchTheGuard.test_regenerating_gives_the_committed_fixtures` | `gen_fixtures.py check --record` (runners re-recorded) | the drift step in `rust.yml` (3.12, 3.13, repo venv with `--record`) | done (S0, S1) |
| `FixturesMatchTheGuard.test_every_case_replays_from_its_env` | each case's env with its defaults reproduces the decision | the Layer-1 runner's virtual `GuardEnv` (`env::VirtualEnv`) | done (S0, S1) |
| `FixturesMatchTheGuard.test_case_ids_are_unique_and_allowed_differences_name_real_cases` | ids, `parity/allowed_differences.json` | — | done (S0) |
| `FixturesMatchTheGuard.test_manifest_lists_every_fixture_file` | `fixtures/manifest.json` | the Layer-1 runner reads its file list and checks the case count | done (S0, S1) |
| `PrefilterContract.test_runners_and_journal_send_no_backslash_hash_or_odd_character` | no runner or live command has `\`, `#` or a character outside printable ASCII and tab | — | done (S0) |
| `PrefilterContract.test_p3_tags_follow_the_prefilter_rule` | the `p3` tags of PLAN.md 4.1/4.2 | the Layer-1 runner's tag handling | done (S0, S1) |
| `PrefilterContract.test_accepted_fixture_commands_are_printable_ascii` | every accepted fixture command is printable ASCII and tab | — | done (S0) |
| `PrefilterContract.test_python_accepts_only_printable_ascii_and_tab` | seeded random edits: whatever Python accepts is printable ASCII and tab | `prefilter::tests`; the Layer-1 `prefilter` cases | done (S0, S1) |
| `OracleServer.test_round_trip` | `parity/oracle.py` JSON lines: `ping`, `check`, `split`, `check_policy`, `realpath`, `os_realpath` (S2) | `tests/tokeniser.rs` (`ping`, `split`, S1); `tests/realpath.rs` (`realpath`, `os_realpath`, S2); S5 proptests | done (S0, S2); `split` used (S1); `realpath`, `os_realpath` used (S2) |

## New in S1 (Rust)

| Test | What it pins | Status |
| --- | --- | --- |
| `tests/layer1.rs` `decision_fixtures` | every decision case: a Rust acceptance equals Python's decision; a refusal is Python's, with Python's reason (except listed cases, and `p3` cases refused by the prefilter); until S3b, commands that reached an unported branch were pending | done (S1, S3a); every case decided (S3b) |
| `tests/layer1.rs` `policy_fixtures` | every `--check-policy` document: Python's verdict, normalized policy and error type (message for printable `Refused`/`KeyError`); `p3` documents may only be refused more | done (S1) |
| `tests/tokeniser.rs` `fixture_commands_split_like_python` | every distinct fixture command past the prefilter splits as `shlex.split` | done (S1) |
| `tests/tokeniser.rs` `random_commands_split_like_python` | 2,000 seeded random commands (quotes, whitespace, metacharacters, `\`, `#`, control and non-ASCII): past the prefilter, the tokens or the error equal Python's | done (S1) |
| `tests/cli.rs` | argv grammar (usage exit 2), `--version`, `--check-policy` (forced-command mode refusing until S4; replaced by the S4 tests) | done (S1) |
| `prefilter::tests`, `tokens::tests`, `repr::tests`, `env::tests`, `policy::tests`, `rules::tests` | the pre-checks and prefilter (4.1), the raw shapes, Python `repr` (4.3), `normpath`, the strict policy types (4.2), the dispatcher | done (S1) |

## New in S3a (Rust)

| Test | What it pins | Status |
| --- | --- | --- |
| `rules::postgres::tests` | every `_check_postgres` branch (`pg_dump` both forms, `dropdb`, `createdb` both forms, `pg_restore` from a temp dump and the scratch restore with its `< file` redirect, `psql` `SELECT 1` and the three runner queries), with Python's reasons | done (S3a) |
| `rules::sqlite::tests` | `.backup`, `.timeout` 1/30000/999999 and its refused variants, the integrity check, the per-user snapshot match | done (S3a) |
| `rules::files::tests` | `rm -f` of temp dumps, `rm -rf --` of temp dirs, `mktemp`, `du`, the `sh -c` probe (and that a path `shlex.quote` would change allows no script) | done (S3a) |
| `rules::tests` | `sudo`, `runuser`, `systemctl`, `curl`, `_is_temp_dump`, `_split_in_dir`; the S3b branches were stubs until S3b | done (S3a) |
| `policy::tests` `scratch_databases`, `mktemp_results` | `Policy.scratch_database`, `_temp_dir_re`, `private_temp_dir`, `snapshot_for_temp_dir` (first match wins) | done (S3a) |

## New in S3b (Rust)

| Test | What it pins | Status |
| --- | --- | --- |
| `tests/layer1.rs` `decision_fixtures` | no pending branch: every case Python allows (3,505) is allowed with an identical decision; a `python-error` case (Python's `check()` crashes on an unbalanced quote in the `tar` shape) is refused as `unparsable command: <Python's error>` | done (S3b) |
| `rules::transfer::tests` | `_check_scp`: downloads as root (temp dumps owned by postgres, the private media archive in root's private dir, read files and roots, the resolved path checked as a plain file), uploads as `runuser -u <owner>` (restore dumps as postgres, `.tmp`/`.restore-tmp` in a root, never through a link); `_check_rsync`: the three exact server forms, the trailing `/`, sender as root, receivers as the root's owner | done (S3b) |
| `rules::files::tests` (S3b part) | the raw `tar` shape (umask, argv from the split group, private dir and archive checks, the crash case) and `cat >` (stdout redirect); `rm -f` of `-wal`/`-shm` (each path resolved); the snapshot `cat` (stdin redirect with the service user as owner); `sha256sum`; `readlink`, `test`, `chmod`; `mv` (in-place upload, new names within one root, `mv target exists`/`not checkable`); `mkdir -p` as the root's owner; `chown` (snapshot dir, root owner, `-R`) | done (S3b) |
| `rules::tests::every_tool_has_a_branch` | every tool of `guard.py` has its branch; the raw shapes come before the tokeniser | done (S3b) |
| `tests/cli.rs` `decide_prints_the_decision_only` | the binary's `--decide` prints an S3b redirect decision (`cat >`) and an S3b refusal resolved by the real `GuardEnv` | done (S3b) |

## New in S4 (Rust)

| Test | What it pins | Status |
| --- | --- | --- |
| `tests/flow.rs` `allowed_command_runs_with_the_python_guards_inheritance` | an allowed command: `allowed from` line, `PATH = SAFE_PATH` (the test's search path), other variables unchanged, only fds 0-2 and those the guard inherited (a CI runner passes some down), SIGPIPE and SIGXFSZ added to the inherited ignored set, umask inherited, the guard reads no stdin and writes no stdout (PLAN.md 3.1, 3.5) | done (S4) |
| `tests/flow.rs` `create_redirect_with_umask`, `read_redirect`, `redirect_failure_refuses` | `umask 077` before the create, the file on fd 1 or 0 and mode `0600`, Python's `[Errno 17] File exists: 'db.dump'` reason, nothing run | done (S4) |
| `tests/flow.rs` `exec_search_is_cpythons` | CPython's `os.execvp`: a shebang-less only candidate is `Exec format error` (127) and never run by a shell; the search goes on after `ENOEXEC`/`EACCES`; the first such error is reported; a directory is `Permission denied`; missing is `No such file or directory`; an argv[0] with `/` is executed as is | done (S4) |
| `tests/flow.rs` `locale_coercion_matches_cpython` | PEP 538: the exported `LC_CTYPE` equals what `python3 -I` exports, for nine environments (none, `LANG=C.UTF-8`/`C`, `LC_ALL=C`/empty, `LC_CTYPE=POSIX`, `LC_CTYPE=C` with `LANG`, an unknown locale, `LC_CTYPE=C.UTF-8`); run against CPython 3.12.3 (Ubuntu 24.04) and 3.13.5 (Debian 13) | done (S4) |
| `tests/flow.rs` `panic_never_execs`, `real_check_refusals_and_log_text` | a panic refuses (`internal error: ...`) with nothing on stderr but `command not allowed`; invalid UTF-8 is logged as `\udcNN`; lines are cut at 1000 characters; `-` without `SSH_CLIENT` | done (S4) |
| `tests/flow.rs` `decide_prints_the_decision`, `shadow_logs_then_execs_python` | `--decide` JSON and exit codes, no redirect, log or exec; `--shadow` logs the record under its own identifier and execs the Python guard with the same PID, the environment and umask unchanged, also after a panic | done (S4) |
| `tests/cli.rs` `decide_prints_the_decision_only`, `shadow_requires_the_python_guards_forced_command`, `shadow_execs_the_python_guard_with_the_same_pid` | the binary's `--decide` with the real `check()`; the `--shadow` argv rule (exit 2); its exec (same PID, environment unchanged) and exec failure (127) | done (S4) |
| `redirect::tests::os_error_text_is_pythons`, `exec::tests`, `syslog::tests`, `repr::tests::undecodable_bytes_as_surrogate_escapes` | `str(OSError)`, glibc `strerror` texts, `os.path.join`, failing searches, `message[:1000]`, `repr` of `surrogateescape` text | done (S4) |

## New in S2 (Rust, filesystem layer)

| Test | What it pins | Status |
| --- | --- | --- |
| `tests/realpath.rs` `virtual_trees_resolve_like_python` | 2,000 seeded random virtual trees (dirs, files, links with random targets, `lstat` errors) and safe-path probes: `pyrealpath` resolves to Python's `os.path.realpath` (the oracle's `realpath`), or refuses as PLAN.md 4.2 allows; a loop refusal is confirmed by a resolver without `seen` | done (S2) |
| `tests/realpath.rs` `real_trees_resolve_like_python` | 500 random real trees in a temp directory: `RealEnv::realpath` against the real `os.path.realpath` (`os_realpath`) | done (S2) |
| `tests/realpath.rs` `virtual_cases`, `link_limit` | `..` in targets, dangling links, missing components, `ENOTDIR`, cached links, `//`, absolute targets, loops, `EACCES`; 40 links resolve, 41 refuse | done (S2) |
| `tests/realpath.rs` `real_env_lookups`, `non_utf8_link_target_refuses` | `RealEnv`: kinds, modes, uid and link count from `lstat`, `ENOENT` as absent, `ENOTDIR`/`ENAMETOOLONG` with glibc's texts, `EINVAL` for a NUL byte, euid against `id -u`, `getpwnam_r` for `root` and missing users; a non-UTF-8 link target refuses (Linux) | done (S2) |
| `pyrealpath::tests`, `rules::paths::tests` | the port without the oracle (cached links count their traversals again towards the limit of 40); the helpers' refusal reasons (`_lstat_or_none`, `_require_plain_file_or_absent`, `_require_private_dir`, `_root_for`, `_require_in_roots`, `_user_uids`) and the `path not checkable` refusal | done (S2) |
| Layer 2 `parity/e2e/layer2_realpath.py` | as root in Ubuntu 24.04 (Python 3.12.3) and Debian 13 (Python 3.13.5): `realpath`, `lstat`, `getpwnam` and euid of the real `GuardEnv` (`examples/env-probe.rs`) against CPython on the PLAN.md 7.5 scenarios and 300 random trees | done (S2), local (`just echoport-command-guard-layer2`) |
