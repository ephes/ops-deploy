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
| `test_upstream_failure_warns_without_claiming_local_collection_failed` | upstream part: every transport failure is an `unknown` answer, never an error (`upstream::tests::lookups_and_caches_match_python`: `release_transport_*`, `release_no_cache_failure`), real failures through a local HTTPS server (`http::tests::*`, `upstream::tests::lookups_over_https_with_a_local_server`); the Traefik observation with an unknown upstream: `traefik::tests::observation_matches_python` (`unknown_upstream`); `collect` with it: `collect::tests::collect_matches_python_end_to_end` (`upstream_unavailable`: every lookup fails, `observation_ok` stays true, `traefik_ok` false) | done (S3a, S3b, S3f) |
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
| `test_atomic_state_permissions_and_failure_preserves_previous` | `atomic::tests::*` (mode 0640, group through the descriptor, a failed write keeps the old file and leaves no temporary file); the state write of `collect`: `collect::tests::the_state_file_on_disk_keeps_its_previous_content_on_failure` (mode, group, the rendered report; an unknown group and a failed rename keep the previous state and leave no temporary file), `::an_unknown_group_is_a_key_error_and_nothing_is_written`, `::a_failed_write_is_the_os_error` | done (S3a, S3f) |
| `test_invalid_policy_and_public_bind_fail` | policy part: `policy::tests::validation_and_hash_match_python` against `fixtures/policy.json` (incl. `/bin/sh` and `/tmp/proxy` as `binary_path`) and `tests/cli.rs` (`validate` exit codes); bind part: `serve::tests::configuration_matches_python` (`fixtures/serve.json` `config`: the real `main()` with `serve --config-json` and a fake `HTTPServer`, including `{"bind": "0.0.0.0"}` of this test) and `tests/cli.rs` (`serve_public_bind` and the other `serve_*` exit codes in `fixtures/cli.json`) | done (S2, S4) |
| `test_http_auth_freshness_and_malformed_state` (`EndpointTests`) | freshness part: `report::tests::freshness_matches_python` against `fixtures/report.json` (stale, `"yes"` in the summary, missing and malformed fields); HTTP part: `serve::tests::requests_match_python` (`fixtures/serve.json` `requests`: raw requests through the real `Handler.handle_one_request` with a password table in place of `htpasswd`, replayed over TCP against the Rust server: 401 without credentials, stale 200 with `fresh: false`, 503 for `"yes"` in the summary and a broken file, 401 when `htpasswd` fails), `::the_role_written_htpasswd_file_is_verified_with_bcrypt` (the Python test's state with a real bcrypt file), `tests/cli.rs::serve_answers_on_its_bind_address_and_logs_nothing`; endpoint parity of both programs: `parity/run_parity.py` sections `endpoint` and `config` (both live servers, the real `htpasswd -vi` on the Python side; see "S5" below) | done (S2, S4, S5) |
| `test_idempotent_targeted_upsert_and_reenable` (`NyxmonTests`) | n/a: `nyxmon_checks.py` stays Python (PLAN.md 4.1) | — |
| `test_allowlisted_projection_roundtrip_preserves_time_and_unknowns` | `export::tests::projection_matches_python` against `fixtures/export.json` (`base` with private fields, `apt_unknown_and_postgresql_not_expected`, the time as Python parses it, …); `::projection_keeps_numbers_as_read_and_copies_nothing_else`; the round trip through the reader: `PythonReaderAcceptsRustExport` (below) | done (S3e) |
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
| `inventory_projection` (`:764-863`): key sets, `text()` (non-empty strings only, cut to 160 code points), the issue bound (20, `issues_truncated`), `os.expected` always true, the version fields per check (`cycle`; `server_version`; `installed`/`running`/`upstream.version` only from objects), the security count (`-0`, big integers, `bool`), `observed_at_epoch` as the parsed number (an integer exactly, a float in its shortest form, also for a 66 000-digit spelling) | `export::tests::projection_matches_python` (about 100 cases) | done |
| `json.loads(raw)` of the source bytes (S3a's reader, `pyjson::loads_bytes`): UTF-8 with or without a byte order mark, invalid UTF-8, empty and trailing data | `export::tests::source_bytes_are_read_like_python` | done |
| `export_inventory` (`:866-881`): the order directory → open → `fdopen` (`IsADirectoryError` for a directory) → file checks → size → JSON → projection → group → write; `pathlib` spelling of both paths (trailing slash, `.` and double slashes) | `export_files_match_python`; `::python_paths_are_normalised_like_pathlib`; `::ownership_and_modes_are_checked_like_python` | done |
| `main()` export branch (`:895-902`): the argument check and the one stderr line | `tests/cli.rs::exit_codes_match_python` | done |

## S3f — `collect` contract parts

| Python behaviour | Rust counterpart | Status |
| --- | --- | --- |
| `collect` (`:644-684`): the order of the steps, their arguments (the sub-policies, the lookup results handed to the observations, the cache path, `now`, the APT age budget), `not_applicable` lookups when Traefik or PostgreSQL is not expected, `generated_at_epoch` read after APT | `collect::tests::steps_run_in_pythons_order_with_pythons_arguments` (`fixtures/report.json`: Python's `collect` with every step patched, each call logged with its arguments) | done |
| `collect` end to end: the Traefik, OS and PostgreSQL observations, the upstream requests and the APT helper in one run, the order of every host access, partial failures kept in the report; a cache path without a name stops `collect` (`cache_variant`'s `ValueError`) | `collect::tests::collect_matches_python_end_to_end` (`fixtures/collect.json`, call logs compared); `::a_lookup_error_outside_the_boundary_stops_collect` | done |
| `main()` collect branch (`:922-931`): the group looked up after the collection (`KeyError`, nothing written), no group for an absent or empty `--group`, `atomic_json` of the report; without `--output` `with_freshness` at a third clock read on stdout | `collect::tests::the_state_is_written_with_the_group_after_the_collection`, `::no_group_or_an_empty_group_writes_without_one`, `::an_unknown_group_is_a_key_error_and_nothing_is_written`, `::the_manual_mode_prints_the_report_with_its_freshness`; exit codes of the policy errors in `tests/cli.rs::exit_codes_match_python` | done |
| `collect --report-usage` (new, PLAN.md 3.1) | `usage::tests::*`, `tests/cli.rs::report_usage_adds_one_line_to_collect` | done |

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

## S4 — the endpoint

`fixtures/serve.json` runs the real Python code: `config` the start of
`main()` for `serve` (with a fake `HTTPServer` that refuses what
`socket.bind` refuses), `requests` raw request bytes through
`Handler.handle_one_request` with the clock fixed and `htpasswd` replaced by
a password table that records each call. The Rust tests replay every request
over TCP against the real hyper server with the same table and clock and
compare the status, the JSON body, the challenge and the `htpasswd` call.
`fixtures/htpasswd.json` (`fixtures/htpasswd.py`) holds the real
`htpasswd -vi` verdicts of Debian 13 and Ubuntu 24.04.

| Python behaviour | Rust counterpart | Status |
| --- | --- | --- |
| `serve` startup (`:909-916`): `ip_address(config["bind"])` (dotted quads only, leading zeros, spaces, IPv6, scoped, integers, other types), loopback or `100.64.0.0/10`, `int(config["port"])` (strings with sign, `_`, spaces and leading zeros, floats truncated, bools, 4300 digits), `bind()`'s host type and port range, the order of these errors, a configuration that is not an object | `serve::tests::configuration_matches_python` (`fixtures/serve.json` `config`, 79 cases); `endpoint::tests::bind_follows_python` | done |
| `HTTPServer` binding a taken address | `tests/cli.rs::serve_exits_1_when_the_port_is_taken`, `serve::tests::run_reports_a_bind_failure` | done |
| `Handler`: method dispatch (501 for every other method), the exact path with the `//` collapse of `parse_request`, 404 before authentication, absolute form, `*`, query strings, fragments (read from the request line, hyper's `Uri` drops them) | `serve::tests::requests_match_python` (`fixtures/serve.json` `requests`) | done |
| Authentication (`:724-739`): the first `Authorization` header, `startswith("Basic ")`, the 4096-byte limit, strict base64 (padding, alphabet, trailing bits), UTF-8, the first `:`, the configured user, `\n` refused before `htpasswd`, what `htpasswd` gets on stdin | same test; `endpoint::tests::basic_auth_follows_python` | done |
| `htpasswd -vi` (Apache 2.4 `htpasswd.c`, APR-util `apr_password_validate`): password from stdin (255 bytes, `\n`/`\r\n`, NUL), the file in 255-byte pieces, whitespace, comments, lines without `:`, empty hashes, every entry of the user, bcrypt `$2y$`/`$2a$`/`$2b$` with exact string comparison (non-canonical characters, costs, trailing text) | `htpasswd::tests::verification_matches_apache_htpasswd` (`fixtures/htpasswd.json`, 89 cases from both distributions); `::stdin_rules`, `::files_are_read_in_pieces_of_255_bytes`, `endpoint::tests::htpasswd_file_is_read_on_every_check` | done |
| The state read per request: `read_text` (UTF-8, BOM, CRLF), `json.loads` (duplicates, big integers, trailing data), `with_freshness` (schema, summary, timestamp types, age limit, future), `meta` and `summary.fresh` replaced, extra keys kept | `serve::tests::requests_match_python` | done |
| `reply`: `Content-Type`, `Content-Length`, `Cache-Control: no-store`, `WWW-Authenticate` only on 401, sorted keys, no request logging (`log_message`) | `requests_match_python` (`Answer::assert_contract`), `endpoint::tests::responses_are_json_with_the_contract_headers`, `tests/cli.rs::serve_answers_on_its_bind_address_and_logs_nothing` | done |
| Head limits of `http.client` (at most 99 header lines, a line of at most 64 KiB) | `serve::tests::head_limits_are_deterministic_and_follow_python` (99 lines taken, 100 refused, a head over 64 KiB always 431; PLAN.md 4.2 item 2); parity `endpoint headers_99`, `headers_100`, `header_line_over_64_kib`, `request_line_over_64_kib`, `head_over_64_kib_in_lines` (S5) | done (S5) |
| The 5 s socket timeout (`:714-716`) and `htpasswd`'s `timeout=5` | `serve::tests::a_partial_request_is_closed_after_the_budget`, `::idle_connections_are_closed_after_the_budget_and_never_block_others`, `::a_slow_password_check_never_holds_up_other_connections`, `::the_password_check_gives_up_after_its_budget` (401 after 5 s, as `TimeoutExpired`), `htpasswd::tests::the_deadline_ends_the_check` (PLAN.md 4.2 items 1 and 2: the head within 5 s, 16 connections at a time) | done |

P3 cases in `fixtures/serve.json`: `startup-config` (PLAN.md 4.2 item 14),
`unicode-digits` (item 11, a port of non-ASCII digits), `header-whitespace`
and `framing` (item 2: trailing whitespace of a header value, a control
character, a folded header line), `non-standard-json` (item 4, `NaN` in the
state). In `fixtures/htpasswd.json`: `non-bcrypt` and `2a-non-ascii`
(item 1).

## S5 — the parity harness (PLAN.md 6.2)

`parity/run_parity.py` runs `software_live.py` (the image's `python3` with
python-apt) and the Rust release binaries side by side, as root in the
`ubuntu:24.04` and `debian:13` containers (CI job `software-live-apt`, last
step; `just rs-software-live-parity` in Docker). Every row compares the two
live programs; P3 cases must show exactly the divergence PLAN.md 4.2 lists.

| Behaviour | Parity section and cases | Status |
| --- | --- | --- |
| `validate` exit codes for the whole policy matrix | `validate` (`fixtures/policy.json`, 161 policies; 7 P3) | done |
| `serve` start-up (bind, port, configuration types) | `config` (`fixtures/serve.json` `config`, 78 configurations: both serve or both exit 1; 9 P3) | done |
| The endpoint: status, JSON body, `Content-Type`, `Cache-Control`, the challenge; no `Server` header and `Connection: close` from Rust; nothing logged | `endpoint` (the 97 raw requests of `fixtures/serve.json` with the states shifted to the real clock, plus the head limits; 6 P3) | done |
| `export-inventory`: exit codes, failure classes and stderr lines, projections, mode 0640 and group, the prior file kept, real root ownership | `export` (`fixtures/export.json`: 32 file cases, 96 projection sources, 12 byte sources) | done |
| `collect` end to end on a real host: Traefik process and binaries, OS release, PostgreSQL processes and `pg_lsclusters`, upstream HTTPS through the system trust store, APT on real lists and the fake repositories; state file mode, owner and group; the manual stdout mode | `collect` (18 scenarios, and the 48 valid policies of `fixtures/policy.json` with their `policy_sha256`; the Python report is also checked against what the world must produce) | done |
| Caches across implementations: fresh (no request), stale with the upstream down (`last_success`), invalid (refetched and rewritten alike) | `collect` "fresh/stale/invalid caches written by python/rust" | done |
| State across implementations: each `serve` on the other's state file; each `export-inventory` on both states; the software_estate reader on the Rust projections | `collect` "cross-read serve", "export of the … state, read by software_estate" | done |
| The comparison rules (P1 types and keys, P2 time fields, error texts) | `parity/test_compare.py` (CI workspace job) | done |

## Role switch (S6, PLAN.md 7.3 and 8.1)

The role side has no Python test to map; its tests are in
`tests/test_software_live_impl.py` (`just test-software-live-impl`, part of
`just test`):

| PLAN.md 7.3 requirement | Test | Status |
| --- | --- | --- |
| drop-ins and shadow units for both impls and both variants; base units keep Python | `TemplateTests` | done (S6) |
| variable validation; variant from `/etc/os-release` | `VariantTests`, `SwitchPlaybookTests.test_variable_validation`, `test_rust_refusals_change_nothing` | done (S6) |
| `nyxmon_checks.py` installed in every mode | `RoleStaticTests.test_nyxmon_checks_installed_in_every_mode` | done (S6) |
| rollback first: impl python with the shadow off and on, a missing archive or a refused candidate, converges to Python | `test_python_rollback_with_*` (five cases) | done (S6) |
| v1 → v2 → v1 → v3 with `keep_versions: 2` keeps v1 (previous) next to v3 and v2; v4 keeps v3 and prunes v1 and v2 | `test_rollback_pin_sequence_with_keep_versions_2` | done (S6) |
| a drop-in left by a failed play protects its version; a failed verification moves no pin and prunes nothing | `test_dropin_of_a_failed_play_protects_its_release` | done (S6) |
| an unreadable or unparseable drop-in or shadow unit skips the prune | `test_unreadable_or_unparseable_dropin_skips_the_prune`, `LiveStateTests` | done (S6) |
| **mandatory**: a collector run (and its `software-live-apt` child) still executing v1 after the unit, the endpoint and both pins moved on keeps v1; an unresolvable running collector skips the prune | `test_running_collector_keeps_its_release`, `test_running_shadow_collector_keeps_its_release`, `test_unresolvable_running_collector_skips_the_prune`, `test_running_unit_without_listable_cgroup_skips_the_prune`, `LiveStateTests.test_running_collector_and_its_apt_child_are_protected` | done (S6) |
| rust → python removes the production pin, sets `previous` to the last Rust version and keeps it installed; a re-run moves nothing and reports no change | `test_switch_to_rust_and_back_to_python`, `test_python_first_deploy_and_rerun` | done (S6) |
| shadow units on and off, shadow pin without a rollback pin | `test_shadow_on_and_off`, `test_rust_with_shadow_pins_both` | done (S6) |
| verification of the running implementation | `VerifyTests`, `test_dropin_of_a_failed_play_protects_its_release` | done (S6) |
