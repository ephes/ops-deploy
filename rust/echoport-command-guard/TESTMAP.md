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
  (PLAN.md 7.2). The Rust Layer-1 runner (S1) reads them; until a branch is
  ported its cases are expected to be refused (counted as pending).
- **unit** / **process**: Rust tests (`src/**` unit tests, `tests/cli.rs`).
- **Layer 2** / **Layer 3**: container differential and sshd end-to-end tests
  (`parity/e2e/`, PLAN.md 7.5, 7.6).

## Guard rules (`GuardAllowsRunnerShapes`, 7 tests)

| Python test | Fixture (S0) | Rust counterpart | Status |
| --- | --- | --- | --- |
| `test_postgres_dump_and_restore` | `unit.jsonl` | Layer-1 runner; `rules::postgres` unit tests | done (S0, S3a) |
| `test_tar_runs_with_umask` | `unit.jsonl` (allowed; foreign, open and symlinked dir; symlinked archive) | Layer-1 runner; `rules::files` unit tests | fixture done (S0); Rust pending (S3b) |
| `test_uploads_run_as_the_target_owner` | `unit.jsonl` | Layer-1 runner; `rules::transfer` unit tests | fixture done (S0); Rust pending (S3b) |
| `test_exact_rsync_commands` | `unit.jsonl` | Layer-1 runner | fixture done (S0); Rust pending (S3b) |
| `test_django_chat_shapes` | `unit.jsonl` | Layer-1 runner; `rules::postgres` unit tests (scratch restore, runner queries) | fixture done (S0); PostgreSQL, `mktemp`, `rm -rf` done (S3a); `cat >`, `sha256sum` pending (S3b) |
| `test_gotosocial_shapes` | `unit.jsonl` (`.timeout` included) | Layer-1 runner; `rules::sqlite` unit tests | fixture done (S0); `sqlite3`, `systemctl`, `mktemp`, `rm -rf`, `curl` done (S3a); `chown`, snapshot `cat`, `rm` wal/shm pending (S3b) |
| `test_policy_rejects_unsafe_entries` | `policy.jsonl` (source `unit`) | `tests/layer1.rs` `policy_fixtures` over `policy.jsonl`; `policy::tests` | done (S1) |

## Refusals (`GuardRefusals`, 9 tests)

| Python test | Fixture (S0) | Rust counterpart | Status |
| --- | --- | --- | --- |
| `test_arbitrary_commands` | `unit.jsonl` (both policies) | Layer-1 runner; `rules::tests` | unknown tools, prefilter and tokeniser stages done (S1); S3a tool branches done (S3a); S3b tool branches pending (S3b) |
| `test_host_specific_rules` | `unit.jsonl` | Layer-1 runner | fixture done (S0); S3a branches done (S3a); S3b branches pending (S3b) |
| `test_symlink_escape_is_refused` | `unit.jsonl` (realpath recorded) | Layer-1 runner | fixture done (S0); Rust pending (S3b) |
| `test_rsync_options_must_match_exactly` | `unit.jsonl`; `mutation/tools.jsonl` (`rsync-*`) | Layer-1 runner | fixture done (S0); Rust pending (S3b) |
| `test_scp_refuses_targets_that_are_not_plain_files` | `unit.jsonl` (lstat recorded); `fs.jsonl` | Layer-1 runner | fixture done (S0); Rust pending (S3b) |
| `test_scp_against_a_real_tree` | — (real filesystem) | Layer 2 | pending (S2, S5) |
| `test_mv_only_onto_new_names_within_one_root` | `unit.jsonl`; `fs.jsonl` | Layer-1 runner | fixture done (S0); Rust pending (S3b) |
| `test_django_chat_refusals` | `unit.jsonl` | Layer-1 runner; `rules::postgres` unit tests | fixture done (S0); S3a branches done (S3a); S3b branches pending (S3b) |
| `test_gotosocial_refusals` | `unit.jsonl` | Layer-1 runner; `rules::sqlite` unit tests | fixture done (S0); S3a branches done (S3a); S3b branches pending (S3b) |

## Redirects (`GuardRedirects`, 5 tests)

Real temp directories (Linux CI; macOS development skips with a reason).

| Python test | Rust counterpart | Status |
| --- | --- | --- |
| `test_create_is_exclusive_and_private` | `redirect.rs` tests | pending (S4) |
| `test_read_plain_file` | `redirect.rs` tests | pending (S4) |
| `test_refuses_links_and_special_files` | `redirect.rs` tests | pending (S4) |
| `test_refuses_a_shared_or_foreign_directory` | `redirect.rs` tests | pending (S4) |
| `test_refuses_a_symlinked_directory` | `redirect.rs` tests | pending (S4) |

## Forced-command flow (`GuardMain`, 5 tests)

Process tests of the binary (`tests/cli.rs`) with a fake exec target in
`SAFE_PATH`, run in a container.

| Python test | Rust counterpart | Status |
| --- | --- | --- |
| `test_interactive_session_is_refused` | process test | pending (S4) |
| `test_refused_command_is_not_executed` | process test | pending (S4) |
| `test_allowed_command_is_executed_without_shell` | process test | pending (S4) |
| `test_broken_policy_refuses_everything` | process test; the documents are in `policy.jsonl` (source `unit`, label `GuardMain`) | fixture done (S0); Rust pending (S4) |
| `test_check_policy_mode` | process test (`tests/cli.rs`); `policy.jsonl` | `--check-policy` done (S1); forced-command part pending (S4) |

## Runners (`RunnerCommandsAreAllowlisted`, 6 tests; `RunnersUseClassicScp`, 1 test)

The recorded commands are `fixtures/corpus/runner.jsonl`; their decisions are
`runner.jsonl` (all allowed).

| Python test | Fixture (S0) | Rust counterpart | Status |
| --- | --- | --- | --- |
| `test_production_db_runners` | `runner.jsonl` | Layer-1 runner | fixture done (S0); S3a shapes done (S3a); `scp` and the other S3b shapes pending (S3b) |
| `test_staging_db_runners` | `runner.jsonl` | Layer-1 runner | fixture done (S0); S3a shapes done (S3a); `scp` and the other S3b shapes pending (S3b) |
| `test_marina_runner` | `runner.jsonl` | Layer-1 runner | fixture done (S0); Rust pending (S3b) |
| `test_villakunterbunt_runner` | `runner.jsonl` | Layer-1 runner | fixture done (S0); Rust pending (S3b) |
| `test_django_chat_runner` | `runner.jsonl` | Layer-1 runner | fixture done (S0); S3a shapes done (S3a); `cat >`, `sha256sum` pending (S3b) |
| `test_gotosocial_runner` | `runner.jsonl` | Layer-1 runner | fixture done (S0); S3a shapes done (S3a); S3b shapes pending (S3b) |
| `RunnersUseClassicScp.test_scp_helpers_pass_dash_O` | — | n/a: tests the runner templates, not the guard; stays Python | n/a |

## Other suites

| Python test | Rust counterpart | Status |
| --- | --- | --- |
| `tests/test_sqlite_backup_runners.py` (`.timeout`) | `mutation/tools.jsonl` (`sqlite-timeout`: 1, 30000, 999999 accepted; 0, 1000000, `01`, `-1`, extra space, missing `.backup`, order refused) and `sqlite-backup`; `rules::sqlite` unit tests | done (S0, S3a) |
| ops-control `test_echoport_remote_command_guard_policy.py` | `policy.jsonl` (`tests/layer1.rs`) plus the S8 Rust `--check-policy` test | Rust done (S1); ops-control pending (S8) |
| role molecule verify | runs unchanged for impl `rust` and `shadow` (PLAN.md 6.2) | pending (S6) |

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
| `OracleServer.test_round_trip` | `parity/oracle.py` JSON lines: `ping`, `check`, `split`, `check_policy`, `realpath` | `tests/tokeniser.rs` (`ping`, `split`, S1); S2/S5 proptests | done (S0); `split` used (S1) |

## New in S1 (Rust)

| Test | What it pins | Status |
| --- | --- | --- |
| `tests/layer1.rs` `decision_fixtures` | every decision case: a Rust acceptance equals Python's decision; a refusal outside an unported branch is Python's, with Python's reason (except listed cases, and `p3` cases refused by the prefilter or tagged `python-error`); only commands that reach an S3b branch may be pending | done (S1, S3a); S3b branches pending (S3b) |
| `tests/layer1.rs` `policy_fixtures` | every `--check-policy` document: Python's verdict, normalized policy and error type (message for printable `Refused`/`KeyError`); `p3` documents may only be refused more | done (S1) |
| `tests/tokeniser.rs` `fixture_commands_split_like_python` | every distinct fixture command past the prefilter splits as `shlex.split` | done (S1) |
| `tests/tokeniser.rs` `random_commands_split_like_python` | 2,000 seeded random commands (quotes, whitespace, metacharacters, `\`, `#`, control and non-ASCII): past the prefilter, the tokens or the error equal Python's | done (S1) |
| `tests/cli.rs` | argv grammar (usage exit 2), `--version`, `--check-policy`, forced-command mode refusing until S4 | done (S1) |
| `prefilter::tests`, `tokens::tests`, `repr::tests`, `env::tests`, `policy::tests`, `rules::tests` | the pre-checks and prefilter (4.1), the raw shapes, Python `repr` (4.3), `normpath`, the strict policy types (4.2), the dispatcher | done (S1) |

## New in S3a (Rust)

| Test | What it pins | Status |
| --- | --- | --- |
| `rules::postgres::tests` | every `_check_postgres` branch (`pg_dump` both forms, `dropdb`, `createdb` both forms, `pg_restore` from a temp dump and the scratch restore with its `< file` redirect, `psql` `SELECT 1` and the three runner queries), with Python's reasons | done (S3a) |
| `rules::sqlite::tests` | `.backup`, `.timeout` 1/30000/999999 and its refused variants, the integrity check, the per-user snapshot match | done (S3a) |
| `rules::files::tests` | `rm -f` of temp dumps, `rm -rf --` of temp dirs, `mktemp`, `du`, the `sh -c` probe (and that a path `shlex.quote` would change allows no script) | done (S3a) |
| `rules::tests` | `sudo`, `runuser`, `systemctl`, `curl`, `_is_temp_dump`, `_split_in_dir`; only the S3b branches are stubs | done (S3a) |
| `policy::tests` `scratch_databases`, `mktemp_results` | `Policy.scratch_database`, `_temp_dir_re`, `private_temp_dir`, `snapshot_for_temp_dir` (first match wins) | done (S3a) |
