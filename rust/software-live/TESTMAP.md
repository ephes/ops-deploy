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
| `test_matching_process_and_binary` | `traefik` fixtures | pending S3b |
| `test_replaced_disk_binary_is_not_a_completed_update` | `traefik` fixtures | pending S3b |
| `test_same_version_different_bytes_is_drift` | `traefik` fixtures | pending S3b |
| `test_unknown_upstream_never_passes` | `traefik` fixtures | pending S3b |
| `test_new_upstream_and_unassigned_desired_are_visible` | `traefik` fixtures | pending S3b |
| `test_deleted_and_wrong_paths_are_visible` | `traefik` fixtures | pending S3b |
| `test_unexpected_process_image_is_never_executed` | `traefik` fixtures plus a Linux-only test that executes a real fake binary through a pinned descriptor | pending S3b |
| `test_bounded_pid_retry` | `traefik` fixtures | pending S3b |
| `test_stopped_service_and_probe_errors_are_unknown` | `traefik` fixtures | pending S3b |
| `test_expected_absence_and_unexpected_other_path` | `traefik` fixtures | pending S3b |
| `test_binary_identity_and_in_place_change` | `traefik` fixtures | pending S3b |
| `test_upstream_failure_warns_without_claiming_local_collection_failed` | `upstream` fixtures plus a local HTTPS fake server | pending S3a |
| `test_failed_upstream_refresh_retains_old_timestamp_only_as_evidence` | `upstream` fixtures | pending S3a |
| `test_upstream_daily_cache_and_unparseable_release` | `upstream` fixtures | pending S3a |
| `test_lifecycle_daily_cache_and_failed_refresh_preserves_evidence` | `upstream` fixtures | pending S3a |
| `test_lifecycle_refresh_skips_malformed_irrelevant_cycles` | `upstream` fixtures | pending S3a |
| `test_cached_timestamp_is_used_not_file_touch` | `upstream` fixtures; cross-implementation cache tests | pending S3a |
| `test_os_lifecycle_reports_desired_drift_and_lts_phase` | `os` fixtures | pending S3c |
| `test_os_boolean_support_state_is_applied_at_observation_boundary` | `os` fixtures | pending S3c |
| `test_boolean_lifecycle_fields_preserve_known_support_state` | `os` fixtures | pending S3c |
| `test_postgresql_minor_and_extra_clusters_are_visible` | `postgresql` fixtures | pending S3c |
| `test_expected_postgresql_absence_is_healthy` | `postgresql` fixtures | pending S3c |
| `test_postgresql_cluster_parser_omits_data_paths` | `postgresql` fixtures | pending S3c |
| `test_postgresql_cluster_parser_rejects_unsafe_identity` | `postgresql` fixtures | pending S3c |
| `test_security_packages_include_held_and_pinned_versions` | helper tests on a fake APT root in the variant containers; python-apt vs helper comparison | pending S3d |
| `test_atomic_state_permissions_and_failure_preserves_previous` | `atomic` tests (mode, group, failure keeps the old file) | pending S3f |
| `test_invalid_policy_and_public_bind_fail` | policy part: `policy::tests::validation_and_hash_match_python` against `fixtures/policy.json` (incl. `/bin/sh` and `/tmp/proxy` as `binary_path`) and `tests/cli.rs` (`validate` exit codes); bind part: `serve` bind tests | done (S2) / pending S4 |
| `test_http_auth_freshness_and_malformed_state` (`EndpointTests`) | freshness part: `report::tests::freshness_matches_python` against `fixtures/report.json` (stale, `"yes"` in the summary, missing and malformed fields); HTTP part: `serve` integration tests plus endpoint parity | done (S2) / pending S4, S5 |
| `test_idempotent_targeted_upsert_and_reenable` (`NyxmonTests`) | n/a: `nyxmon_checks.py` stays Python (PLAN.md 4.1) | — |
| `test_allowlisted_projection_roundtrip_preserves_time_and_unknowns` | `export` fixtures and tests | pending S3e |
| `test_projection_rejects_invalid_source_not_manufacture_success` | `export` fixtures and tests | pending S3e |
| `test_export_atomic_permissions_and_failure_preserves_prior_file` | `export` tests | pending S3e |
| `test_export_mode_never_collects_or_connects` | `export` tests | pending S3e |
| `test_reader_rejects_stale_future_cross_host_and_extra_fields` | n/a: reader side (software_estate); S3e runs this reader on Rust output | pending S3e |
| `test_reader_refuses_nonroot_writable_or_linked_paths` | n/a: reader side (software_estate) | — |
| `test_unavailable_health_is_explicit_partial_failure_and_opt_in` | n/a: reader side (software_estate) | — |

## S2 — contract parts without a Python test of their own

All fixtures are generated from the Python program; every Rust test named
here passes.

| Python behaviour | Rust counterpart | Status |
| --- | --- | --- |
| `main()` argument handling (`:884-931`): modes, options with every mode, any order, `--opt=value`, unique prefixes, ambiguous prefixes, last occurrence wins, `--config-json` before `--config` (an empty one falls back), usage errors exit 2, failures exit 1, the `export-inventory` argument check and its stderr line | `tests/cli.rs::exit_codes_match_python` against `fixtures/cli.json` (the Python program run as a subprocess); `main::tests` | done |
| `validate_policy` (`:607-641`): every rule, the order of the checks, the exception class per wrong type (`KeyError`, `TypeError`, `AttributeError`, unhashable values), `str()` of numbers in the cycle and major patterns | `policy::tests::validation_and_hash_match_python` (`fixtures/policy.json`, about 160 cases) | done |
| `policy_sha256` (`:666-668`): `json.dumps(policy, sort_keys=True)` with non-ASCII and control characters, big and negative-zero integers, floats (`1E2`, `1e16`, `1e-05`, `1e400`, ties), key order, duplicate keys, nesting | `policy::tests::validation_and_hash_match_python` (hash taken from `collect()` with patched observations); `pyjson::tests::dumps_matches_python`, `::float_repr_matches_python` (about 2200 doubles incl. 200 exact ties) | done |
| `json.loads` limits: more than 4300 digits, BOM, trailing data | `pyjson::tests::loads_accepts_and_rejects_like_python` | done |
| `collect()` summary (`:673-683`) and the top-level key set | `report::tests::summary_and_report_shape_match_python` (`fixtures/report.json`, observations patched into `collect()`) | done |
| `with_freshness` (`:687-710`) | `report::tests::freshness_matches_python` | done |
| `f"{Class}: {exc}"[:240]` at an observation boundary | `report::tests::error_texts_are_cut_like_python` (taken from `observe_os`) | done |
| `os.path.realpath` (not strict) | `probe::tests::realpath_matches_python_on_a_real_tree` (`fixtures/realpath.json`) | done |
| `command()` (`:68-77`): `text=True` decoding, universal newlines, `strip()`, `CalledProcessError`, `TimeoutExpired` with kill, `FileNotFoundError` | `probe::tests::command_*`, `::a_grandchild_holding_the_pipe_times_out`, `::large_output_on_both_pipes_does_not_block` | done |
| `Path.exists()` (Python 3.12 ignored errnos) | `probe::tests::exists_ignores_only_pathlibs_errnos` | done |

## P3 cases in the fixtures (PLAN.md 4.2)

Fixture cases tagged `p3` are inputs Python accepts and the Rust code
refuses: `non-standard-json` (`NaN`, `Infinity`, lone surrogates; item 4),
`nesting` (deeper than 128 levels; item 4) and `unicode-digits` (non-ASCII
digits; item 11). The Rust tests assert the refusal.
