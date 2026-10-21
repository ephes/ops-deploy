# Python test → Rust test map (software-live)

Every Python test of `software_live.py` gets a Rust counterpart, a fixture
family or a reason why it has none (PLAN.md 6.1). Each slice updates the rows
it covers, so reviewers see the coverage per slice. Status: `done`
(counterpart exists and passes), `pending S<n>` (planned in that slice),
`n/a` (with the reason).

Fixtures live in `fixtures/` and are written by `fixtures/generate.py` from
the Python program (`just rs-software-live-fixtures`).
`tests/test_software_live_rust_fixtures.py` (`just
test-software-live-rust-fixtures`, part of `just test`) fails when a committed
fixture no longer matches the Python program, and when a Python test below is
missing from this file.

## Python tests (`tests/test_software_live.py`, `tests/test_software_health_bridge.py`)

| Python test | Rust counterpart | Status |
| --- | --- | --- |
| `test_deployed_programs_support_python_311` | n/a: Python only; the Python file stays the oracle | — |
| `test_numeric_release_comparison` | `version::tests::parsing_matches_python`, `::comparisons_match_python` against `fixtures/version.json` (`version()`, `numeric_version()`, unbounded numbers, Python's whitespace) | done (S2) |
| `test_matching_process_and_binary` | `traefik::tests::observation_matches_python` (`fixtures/traefik.json` `matching_process_and_binary`, `usr_bin_policy`, `symlinked_binary_is_resolved`); `tests/traefik_host.rs::matching_process_is_probed_through_its_pinned_descriptor` (Linux, a real process) | done (S3b) |
| `test_replaced_disk_binary_is_not_a_completed_update` | `observation_matches_python` (`replaced_disk_binary_same_path`, `replaced_disk_binary_deleted`, `outdated_and_drift`); `traefik_host.rs::replaced_binary_is_reported_and_the_old_image_is_never_executed` (Linux) | done (S3b) |
| `test_same_version_different_bytes_is_drift` | `observation_matches_python` (`same_version_different_bytes`) | done (S3b) |
| `test_unknown_upstream_never_passes` | `observation_matches_python` (`unknown_upstream`, `upstream_not_applicable`, `upstream_status_missing`, …) | done (S3b) |
| `test_new_upstream_and_unassigned_desired_are_visible` | `observation_matches_python` (`new_upstream_and_unassigned_desired`, `desired_version_absent`, `desired_installed_drift`, `running_newer_than_upstream`) | done (S3b) |
| `test_deleted_and_wrong_paths_are_visible` | `observation_matches_python` (`deleted_and_wrong_path`, `symlinked_binary_running_the_link_path`, `non_ascii_running_path`) | done (S3b) |
| `test_unexpected_process_image_is_never_executed` | `observation_matches_python` (`unexpected_image_*_is_not_executed`, `reexec_after_link_check_is_refused`: the call log shows no execution); `traefik::tests::binary_info_matches_python` (`no_probe_never_executes`, `descriptor_target_*_is_refused`); Linux: `traefik_host.rs::foreign_process_image_is_hashed_but_never_executed`, `::execution_follows_the_descriptor_not_the_path`, `::binary_info_checks_the_descriptor_target_before_executing` | done (S3b) |
| `test_bounded_pid_retry` | `observation_matches_python` (`pid_retry_settles`, `pid_retry_exhausted`, `link_retry_*`, `retry_resets_issues`, `pid_gone_after_probe`) | done (S3b) |
| `test_stopped_service_and_probe_errors_are_unknown` | `observation_matches_python` (`stopped_service`, `systemctl_*`, `pid_invalid_*`, `exe_link_*`, `installed_probe_*`, `running_probe_fails`, …); `traefik_host.rs::stopped_service_is_unknown` (Linux) | done (S3b) |
| `test_expected_absence_and_unexpected_other_path` | `observation_matches_python` (`expected_absence`, `unexpected_process`, `unexpected_other_path`, `unexpected_managed_path`, `not_expected_*`) | done (S3b) |
| `test_binary_identity_and_in_place_change` | `binary_info_matches_python` (`output_*`, `changed_during_probe`, `final_stat_*`, `unparseable_wins_over_change`); `traefik::tests::real_binary_identity_and_in_place_change` (a real self-modifying script); `traefik_host.rs::binary_info_checks_the_descriptor_target_before_executing` (the same through the descriptor, Linux) | done (S3b) |
| `test_upstream_failure_warns_without_claiming_local_collection_failed` | upstream part: every transport failure is an `unknown` answer, never an error (`upstream::tests::lookups_and_caches_match_python`: `release_transport_*`, `release_no_cache_failure`), real failures through a local HTTPS server (`http::tests::*`, `upstream::tests::lookups_over_https_with_a_local_server`); the Traefik observation with an unknown upstream: `traefik::tests::observation_matches_python` (`unknown_upstream`); `collect` with it | done (S3a, S3b) / pending S3f |
| `test_failed_upstream_refresh_retains_old_timestamp_only_as_evidence` | `upstream::tests::lookups_and_caches_match_python` (`release_failed_refresh_keeps_evidence`: the Python test's world), `::rust_reads_what_it_wrote` | done (S3a) |
| `test_upstream_daily_cache_and_unparseable_release` | `upstream::tests::lookups_and_caches_match_python` (`release_fetch_then_cached_then_garbage`: fetch, cached hit without a request, unparseable tag) | done (S3a) |
| `test_lifecycle_daily_cache_and_failed_refresh_preserves_evidence` | `upstream::tests::lookups_and_caches_match_python` (`lifecycle_fetch_then_cached_then_failed_refresh`) | done (S3a) |
| `test_lifecycle_refresh_skips_malformed_irrelevant_cycles` | `upstream::tests::lookups_and_caches_match_python` (`lifecycle_skips_malformed_irrelevant_cycles` and the `lifecycle_eol_*`/`lifecycle_support_*` cases) | done (S3a) |
| `test_cached_timestamp_is_used_not_file_touch` | `report::tests::freshness_matches_python` (`with_freshness` uses `generated_at_epoch`: stale, future, string, NaN, missing summary); the caches' `checked_at_epoch`, never the file time, in `upstream::tests::lookups_and_caches_match_python` (`release_cache_from_the_future`, `release_python_written_cache_*`) | done (S2, S3a) |
| `test_os_lifecycle_reports_desired_drift_and_lts_phase` | `os::tests::observe_os_matches_python`, case `desired_drift_and_lts_phase` of `fixtures/os.json` | done (S3c) |
| `test_os_boolean_support_state_is_applied_at_observation_boundary` | `os::tests::observe_os_matches_python`, cases `boolean_support_false_warns`, `boolean_support_true_is_ok` | done (S3c) |
| `test_boolean_lifecycle_fields_preserve_known_support_state` | `lifecycle::tests::ended_matches_python` (`fixtures/lifecycle.json`, both flags for every kind of value) and `postgresql::tests::observe_postgresql_matches_python`, case `boolean_eol_true` | done (S3c) |
| `test_postgresql_minor_and_extra_clusters_are_visible` | `postgresql::tests::observe_postgresql_matches_python`, case `minor_and_extra_clusters` of `fixtures/postgresql.json` | done (S3c) |
| `test_expected_postgresql_absence_is_healthy` | `postgresql::tests::observe_postgresql_matches_python`, case `expected_absence_is_healthy` | done (S3c) |
| `test_postgresql_cluster_parser_omits_data_paths` | `postgresql::tests::clusters_match_python`, case `omits_data_paths` | done (S3c) |
| `test_postgresql_cluster_parser_rejects_unsafe_identity` | `postgresql::tests::clusters_match_python`, case `rejects_unsafe_identity` | done (S3c) |
| `test_security_packages_include_held_and_pinned_versions` | `software-live-apt`: `observe::tests::security_packages_include_held_and_pinned_versions` (the same package, compare function and hold), `::newest_security_version_wins_and_order_is_by_package`, `::a_tie_keeps_the_first_newest_version`, `::security_origins_follow_python`; in the variant containers (CI job `software-live-apt`, `just rs-software-live-apt`) `container/compare.py` runs the helper and `observe_apt` with python-apt on the fake APT world of `container/setup-world.sh` (held native and foreign packages, pinned candidate, every `security_origin` branch) and requires identical JSON | done (S3d) |
| `test_atomic_state_permissions_and_failure_preserves_previous` | `atomic::tests::*` (mode 0640, group through the descriptor, a failed write keeps the old file and leaves no temporary file); the state write of `collect` | done (S3a) / pending S3f |
| `test_invalid_policy_and_public_bind_fail` | policy part: `policy::tests::validation_and_hash_match_python` against `fixtures/policy.json` (incl. `/bin/sh` and `/tmp/proxy` as `binary_path`) and `tests/cli.rs` (`validate` exit codes); bind part: `serve` bind tests | done (S2) / pending S4 |
| `test_http_auth_freshness_and_malformed_state` (`EndpointTests`) | freshness part: `report::tests::freshness_matches_python` against `fixtures/report.json` (stale, `"yes"` in the summary, missing and malformed fields); HTTP part: `serve` integration tests plus endpoint parity | done (S2) / pending S4, S5 |
| `test_idempotent_targeted_upsert_and_reenable` (`NyxmonTests`) | n/a: `nyxmon_checks.py` stays Python (PLAN.md 4.1) | — |
| `test_allowlisted_projection_roundtrip_preserves_time_and_unknowns` | `export::tests::projection_matches_python` against `fixtures/export.json` (`base` with private fields, `apt_unknown_and_postgresql_not_expected`, the time kept as read, …); `::projection_keeps_numbers_as_read_and_copies_nothing_else`; the round trip through the reader: `PythonReaderAcceptsRustExport` (below) | done (S3e) |
| `test_projection_rejects_invalid_source_not_manufacture_success` | `projection_matches_python` (every rejection in Python's order: `schema_*`, `host_*`, `time_*` incl. `OverflowError` of a huge integer, `check_*`, `issues_*`, `apt_*`, a non-object source) | done (S3e) |
| `test_export_atomic_permissions_and_failure_preserves_prior_file` | `export::tests::export_files_match_python` (`fixtures/export.json` `files`: the real `export_inventory` on disk with root ownership emulated as in the Python test; mode 0640, group, new inode, the prior file kept and no temporary file left on every failure: unsafe modes and owners, symlink, hard link, FIFO, directory, size bound, missing group); `::a_failed_write_keeps_the_previous_projection` (`fchown` and rename failures) | done (S3e) |
| `test_export_mode_never_collects_or_connects` | `main::export_inventory` takes no `System` (it cannot collect or connect) and reads only `--config`; `tests/cli.rs::exit_codes_match_python` (`export_ignores_config_json`, `export_missing_*`, `export_source_directory`, with Python's stderr line) | done (S3e) |
| `test_reader_rejects_stale_future_cross_host_and_extra_fields` | n/a: reader side (software_estate). The reader runs on Rust output: `tests/test_software_live_rust_fixtures.py` (`PythonReaderAcceptsRustExport`) reads every projection in `fixtures/rust-export.json` (written by `export::tests::rust_written_exports_are_committed`) and requires the value Python's own projection of the same source gives | done (S3e) |
| `test_reader_refuses_nonroot_writable_or_linked_paths` | n/a: reader side (software_estate) | — |
| `test_unavailable_health_is_explicit_partial_failure_and_opt_in` | n/a: reader side (software_estate) | — |

## S2 — contract parts without a Python test of their own

All fixtures are generated from the Python program; every Rust test named
here passes.

| Python behaviour | Rust counterpart | Status |
| --- | --- | --- |
| `main()` argument handling (`:884-931`): modes, options with every mode, any order, `--opt=value`, unique prefixes, ambiguous prefixes, last occurrence wins, which words can be an option's value (negative numbers, words with a space, `-` vs `-x`, `--`, `-h…`), `--config-json` before `--config` (an empty one falls back), usage errors exit 2, failures exit 1, the `export-inventory` argument check and its stderr line | `tests/cli.rs::exit_codes_match_python` against `fixtures/cli.json` (the Python program run as a subprocess); `main::tests` | done |
| `validate_policy` (`:607-641`): every rule, the order of the checks, the exception class per wrong type (`KeyError`, `TypeError`, `AttributeError`, unhashable values), `str()` of numbers in the cycle and major patterns | `policy::tests::validation_and_hash_match_python` (`fixtures/policy.json`, about 160 cases) | done |
| `policy_sha256` (`:666-668`): `json.dumps(policy, sort_keys=True)` with non-ASCII and control characters, big and negative-zero integers, floats (`1E2`, `1e16`, `1e-05`, `1e400`, ties), key order, duplicate keys, nesting | `policy::tests::validation_and_hash_match_python` (hash taken from `collect()` with patched observations); `pyjson::tests::dumps_matches_python`, `::float_repr_matches_python` (about 2200 doubles incl. 200 exact ties) | done |
| `json.loads` limits: more than 4300 digits (also in a replaced duplicate), BOM, trailing data; serde_json's internal number token as an ordinary key | `pyjson::tests::loads_accepts_and_rejects_like_python` | done |
| `collect()` summary (`:673-683`) and the top-level key set | `report::tests::summary_and_report_shape_match_python` (`fixtures/report.json`, observations patched into `collect()`) | done |
| `with_freshness` (`:687-710`) | `report::tests::freshness_matches_python` | done |
| `f"{Class}: {exc}"[:240]` at an observation boundary | `report::tests::error_texts_are_cut_like_python` (taken from `observe_os`) | done |
| `os.path.realpath` (not strict) | `probe::tests::realpath_matches_python_on_a_real_tree` (`fixtures/realpath.json`) | done |
| `command()` (`:68-77`): `text=True` decoding of both streams before the exit check, universal newlines, `strip()`, `CalledProcessError` (exit code or signal), `TimeoutExpired` with kill, `FileNotFoundError` | `probe::tests::command_*`, `::a_grandchild_holding_the_pipe_times_out`, `::large_output_on_both_pipes_does_not_block` | done |
| `Path.exists()` (Python 3.12 ignored errnos) | `probe::tests::exists_ignores_only_pathlibs_errnos` | done |

## S3b — Traefik contract parts

`fixtures/traefik.json` runs the real `binary_info` and `observe_traefik`
against a fake host (`FakeHost` in `fixtures/generate.py`, the Python side of
`probe::fake::FakeSystem`): the same world, the same answers, and a log of
every call in the same format. The Rust tests replay each world and require
the same result and **the same call log** (opens, descriptor and `/proc`
link reads, `realpath`, `fstat`, hashes, `stat`, and every command with the
descriptors it inherits), so the order of the checks and what is executed
match Python step by step.

| Python behaviour | Rust counterpart | Status |
| --- | --- | --- |
| `main_pid` (`:128-129`): `int()` of `systemctl show … --value` (padding, `+`, `_`, leading zeros, `-0`, negative and huge numbers, non-numbers, more than 4300 digits) | `observation_matches_python` (`pid_*`); `traefik::tests::pid_parsing_follows_int` | done |
| `binary_info` (`:90-125`): the version line `(?m)^Version:\s*(v?\d+\.\d+\.\d+)\s*$` (prefix `v`, Python's whitespace incl. U+001C..U+001F and line breaks, first matching line, universal newlines), the descriptor target check before anything else, the identity `(st_dev, st_ino, st_mtime_ns, st_ctime_ns, st_size)` before the hash, after the probe and of the final `stat` (and not uid, mode or link count), "unparseable" before "changed", errors of open, `fstat`, readlink and the probe | `binary_info_matches_python` (about 50 cases) | done |
| `pass_fds=(fd,)` without `unsafe`: only the probe inherits the descriptor, close-on-exec is set again after the spawn (also after a failed start or a timeout) | `probe::tests::only_run_inheriting_passes_the_descriptor`, `::open_file_is_hashed_and_stated_through_its_descriptor` | done |
| `observe_traefik` (`:242-319`): order of the issues, what the error keeps (issues of the failed attempt, fields set before the failure), `KeyError`/`TypeError` of a malformed upstream answer, `desired_version` absent vs `null`, a version over Python's int limit | `observation_matches_python` (about 75 cases) | done |

## S3a — upstream lookups and caches without a Python test of their own

| Python behaviour | Rust counterpart | Status |
| --- | --- | --- |
| `upstream` (`:149-188`): cache read and validation (version, `checked_at_epoch` int/float/bool, any other content invalid), TTL bounds, extra cache keys, the request (URL, headers, timeout), `read(1024 * 1024)` cutting a long body, `json.loads` of bytes (BOM, not UTF-8, trailing data, 4300 digits), `tag_name` checks, draft/prerelease truthiness, the cache write and its failure, `last_success` | `upstream::tests::lookups_and_caches_match_python` (`fixtures/upstream.json`, about 190 cases; the Python run records every request and every `atomic_json` call) | done |
| `lifecycle_upstream` (`:191-239`): cache validation (product, `cycles` a list, items unchecked), cycle filter (`cycle` a string, `eol`/`support` bool, null, missing or an ISO date, every invalid date form), whole cycles kept, empty and invalid responses, one cache per product | same test | done |
| `cache_variant` (`:62-65`) and `pathlib`'s stem and suffix | `upstream::tests::cache_variant_matches_python`, `::cache_variant_follows_python_3_12_and_3_13` | done |
| Caches Python wrote (`atomic_json` output) are read by Rust | `release_python_written_cache_*`, `lifecycle_python_written_cache_*` | done |
| Caches Rust wrote are read by Python | `upstream::tests::rust_written_caches_are_committed` keeps `fixtures/rust-caches.json` current; `tests/test_software_live_rust_fixtures.py` (`PythonReadsRustWrittenCaches`) runs the Python program on it | done |
| `urlopen` over HTTPS with the system store | `http::tests::*` against a local HTTPS server: headers, status errors, redirects, the 1 MiB cut, a body shorter than its `Content-Length` (kept, as `http.client`'s bounded read), a chunked body that ends early (error), the body's single time budget (PLAN.md 4.2 item 13), an untrusted certificate, the system store refusing a self-signed server, a refused connection, a timeout, no proxy | done |
| `atomic_json` (`:132-146`) | `atomic::tests::*` | done |

## S3c — OS and PostgreSQL observations

The cases run the real Python functions on `TextHost` in
`fixtures/generate.py`: S3b's `FakeHost` (`open`, `fstat`, `readlink`,
`realpath`, `stat` and the child processes) plus the text files (the
os-release candidates and the PID file, read with Python's real text-mode
decoding). The Rust tests replay the same world through
`probe::fake::FakeSystem` and compare the result, the error class (and the
message where it is the Python code's own or a `KeyError`) and the call log.

| Python behaviour | Rust counterpart | Status |
| --- | --- | --- |
| `platform.freedesktop_os_release()`: fallback to `/usr/lib/os-release` on any `OSError` (missing, `EACCES`, `EISDIR`, `EIO`), the errno class when neither can be read, no fallback after a `UnicodeDecodeError`, `_parse_os_release` (quotes, unmatched quotes, the five escapes, names, spacing, comments, CR/CRLF, BOM, duplicates, defaults, non-ASCII and control characters) | `os::tests::os_release_matches_python` (`fixtures/os.json` `release`, 31 cases) | done |
| `observe_os` (`:346-390`): ID and cycle checks, `KeyError` for a missing `VERSION_ID`, desired-cycle drift (also a number in the policy), upstream unknown with and without stale evidence, a missing cycle, `cycle_eol` before `standard_support_ended`, boolean and date states, invalid dates, `newest_cycle`, the UTC date of `now` at midnight | `os::tests::observe_os_matches_python` (`fixtures/os.json` `observe`, 44 cases) | done |
| `lifecycle_date` (S3a's `upstream::lifecycle_date`) as `lifecycle_ended` uses it, `lifecycle_ended`, `lifecycle_cycle`, `lifecycle_evidence`, `datetime.fromtimestamp(now, UTC).date()` (half-even microsecond rounding, negative times, years 1 and 9999) | `lifecycle::tests::*` (`fixtures/lifecycle.json`) | done |
| `postgres_clusters` (`:393-417`): `splitlines` and `split` on Python's line breaks and whitespace, field counts, identities, `int()` of the port (sign, `_`, leading zeros, 4300 digits), range, command failures | `postgresql::tests::clusters_match_python` (`fixtures/postgresql.json` `clusters`, 45 cases) | done |
| `postgresql_server_version` (`:420-449`): PID file `readline(32)` (text decoding of the first chunk, universal newlines, `strip()`), the PID pattern, the pinned image (symlinked install, deleted or other image refused before any execution), `pass_fds`, the identity checks before, after and at the path, a changed or vanished PID file, the version pattern | `postgresql::tests::server_version_matches_python` (`fixtures/postgresql.json` `server_version`, 55 cases) | done |
| `observe_postgresql` (`:452-527`): not expected (missing `pg_lsclusters`, unexpected clusters, failures), cluster selection (name, port, `online…` status, first match, `KeyError` order), drift, extra clusters, upstream states, missing cycle and minor, `cycle_eol`, `outdated_minor` (numeric, longer tuples), partial results kept on failure | `postgresql::tests::observe_postgresql_matches_python` (`fixtures/postgresql.json` `observe`, 53 cases) | done |
| `subprocess`'s `close_fds=True` with `pass_fds=(fd,)` on the host: a child inherits the passed descriptor and no other one, also not one that lost its close-on-exec flag; a plain child inherits neither | `probe::tests::children_inherit_only_the_passed_descriptor` (Linux only; CI) | done |
| `Path.open()` reads one chunk: the host reads at most the first 8192 bytes of the PID file | `probe::tests::read_head_reads_at_most_the_limit` | done |

## S3d — the APT helper and its invocation

| Python behaviour | Rust counterpart | Status |
| --- | --- | --- |
| `observe_apt` (`:574-603`): index ages from `*InRelease` names with `security`, freshness, oldest age, the `ok` and `unknown` objects | `software-live-apt`: `observe::tests::index_ages_follow_pathlib_glob_and_stat`, `::ok_result_has_python_fields`, `::unknown_result_has_python_fields`; container comparison for fresh, stale and future ages and a broken index | done |
| `apt.Cache(memonly=True)` without writes under `/var/cache/apt`, holds from `apt-mark showhold` | container comparison: no file written as root without caches, an unprivileged run reads the warm `srcpkgcache.bin` and writes nothing; holds of a native and a foreign-architecture package | done |
| `apt_pkg.version_compare` | `software-live-apt`: `cache::tests::compare_never_reads_past_the_slice`, `::compare_matches_python_apt_on_the_cache` (20 000 pairs of the image's versions against python-apt) | done |
| the helper's command line (PLAN.md 5.2) | `software-live-apt`: `tests::observe_takes_both_options_in_either_order`, `::usage_errors`, `::version_line_names_the_binary` | done |
| the main binary's side of the helper contract (PLAN.md 5.2, 4.2 item 8): location next to `/proc/self/exe`, ownership and mode check, argv, timeout, exit, output limit, strict result shape | `apt::tests` (fake `System` world and a real script as the helper) | done |

## S3e — inventory export contract parts

| Python behaviour | Rust counterpart | Status |
| --- | --- | --- |
| `inventory_projection` (`:764-863`): key sets, `text()` (non-empty strings only, cut to 160 code points), the issue bound (20, `issues_truncated`), `os.expected` always true, the version fields per check (`cycle`; `server_version`; `installed`/`running`/`upstream.version` only from objects), the security count (`-0`, big integers, `bool`), `observed_at_epoch` as read | `export::tests::projection_matches_python` (about 100 cases) | done |
| `json.loads(raw)` of the source bytes (S3a's reader, `pyjson::loads_bytes`): UTF-8 with or without a byte order mark, invalid UTF-8, empty and trailing data | `export::tests::source_bytes_are_read_like_python` | done |
| `export_inventory` (`:866-881`): the order directory → open → `fdopen` (`IsADirectoryError` for a directory) → file checks → size → JSON → projection → group → write; `pathlib` spelling of both paths (trailing slash, `.` and double slashes) | `export_files_match_python`; `::python_paths_are_normalised_like_pathlib`; `::ownership_and_modes_are_checked_like_python` | done |
| `main()` export branch (`:895-902`): the argument check and the one stderr line | `tests/cli.rs::exit_codes_match_python` | done |

## P3 cases in the fixtures (PLAN.md 4.2)

Fixture cases tagged `p3` are inputs Python accepts and the Rust code
refuses: `non-standard-json` (`NaN`, `Infinity`, lone surrogates; item 4),
`nesting` (deeper than 128 levels; item 4), `encoding` (an export source
in UTF-16 or UTF-32, or with UTF-8-encoded surrogates; item 4),
`unicode-digits` (non-ASCII
digits; item 11; in `traefik.json` a `MainPID` and a version line, in
`postgresql.json` `pg_lsclusters` output, the postmaster PID and its version
line) and `iso-date` (`YYYYMMDD` and ISO week dates; item 6). The Rust tests
assert the refusal.
In `fixtures/export.json`, `time_nan` and `time_infinity` are refused by
both (Python with `ValueError: invalid source time`, Rust while reading the
JSON).

In `fixtures/upstream.json` a P3 call records both the Python answer and,
under `p3`, the answer the Rust code must give: what the Python program
answers for the input the Rust code effectively sees (the cache replaced by
an unusable one, the response replaced by an error of the Rust class, or a
cycle's date replaced by an invalid one). Tags: `non-standard-json` and
`utf16-body` (item 4), `unicode-digits` (item 11), `iso-date` (item 6) and
`cache-crash` (item 12: a lifecycle cache that is not an object, a
`checked_at_epoch` beyond the float range).
