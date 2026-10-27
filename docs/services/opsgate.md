# Native OpsGate

`OpsGateConfig` / `deploy_opsgate` ports the authoritative ops-library role at `56495f75` (2.75.1). It supports the existing Darwin/launchd contract. The owned ARM fixture passed on `cd4ee3e7920232aabcf142971bec96e044611f55`; inventory rollout is separate.

The original two-account contract is preserved: the API runs as `control_service_user`, and the runner as `ops`. Account groups, reciprocal group membership, private homes, credentials, tmux settings, application copies, Python rollback plists and pinned Rust releases remain independently managed. The role defaults render units without managing or starting them; select the existing manage/start inputs to run them.

Each Rust unit selects its versioned binary. Candidate archive/check-config/read-only database validation precedes active plist replacement. A rejected candidate stops a Rust selection and preserves existing releases and active plists; with both units on Python it warns and retains Python. Retention keeps the selected, running and previous rollback versions in addition to the configured newest releases.

Managed infrastructure workspaces retain branch tracking or an explicit Git ref. A current head is compared with the read-only remote ref and status without an index refresh: no fetch, checkout or Git-metadata update occurs on the repeat. These workspace changes do not restart unchanged Rust services. Source/runtime changes restart Python units; environment or selected plist changes retain the role's per-unit restart semantics. Deliberately changing the controller source resumes the normal rsync/runtime update path.

Homebrew and its selected owner remain prerequisites. Missing declared formulae are installed; normal deployment does not upgrade existing formulae. The native uv base API is a separate composition step where the playbook included it. Source sync uses the existing `sync_tree` checksum dry-run, explicit already-installed modern `remote_rsync_path` (default `/opt/homebrew/bin/rsync`) and a real preceding preparation operation for a fresh destination. Existing excluded data, virtualenvs and Git metadata are preserved. The editable rollback install's in-tree build metadata (`*.egg-info`) is also excluded, so an unchanged repeat neither deletes it nor re-runs the environment sync.

```python
from ops_deploy.services.opsgate import OpsGateConfig, deploy_opsgate

cfg = OpsGateConfig(opsgate_source_path="/workspaces/opsgate")
deploy_opsgate(cfg, prepared_secret_values)
```

Secrets are a separate mapping, never config/argv/host data. The mapping uses these original role variable names:

- `opsgate_ops_github_deploy_keys`
- `opsgate_session_secret`
- `opsgate_ui_password_bcrypt`
- `opsgate_submit_token_openclaw`
- `opsgate_submit_token_nyxmon`
- `opsgate_submit_token_operator`
- `opsgate_runner_token`
- `opsgate_ops_ssh_private_key`
- `opsgate_ops_ssh_public_key`
- `opsgate_ops_github_ssh_private_key`
- `opsgate_ops_github_ssh_public_key`
- `opsgate_ops_age_private_key`
- `opsgate_ops_github_token`

Configuration retains the original public variable names. Computed defaults below resolve from other configured inputs before connection.

| Input | Default |
| --- | --- |
| `remote_rsync_path` | `"/opt/homebrew/bin/rsync"` |
| `inventory_hostname` | `"runner"` |
| `opsgate_service_name` | `"opsgate"` |
| `ops_user` | `"ops"` |
| `ops_group` | `"{{ ops_user }}"` |
| `ops_home_dir` | `"/Users/{{ ops_user }}"` |
| `ops_shell` | `"/bin/zsh"` |
| `control_service_user` | `"control_service_user"` |
| `control_service_group` | `"{{ control_service_user }}"` |
| `control_service_home_dir` | `"/Users/{{ control_service_user }}"` |
| `control_service_shell` | `"/usr/bin/false"` |
| `opsgate_manage_users` | `true` |
| `execution_data_dir` | `"{{ ops_home_dir }}/remediation"` |
| `tickets_dir` | `"{{ execution_data_dir }}/jobs"` |
| `session_artifacts_dir` | `"{{ execution_data_dir }}/sessions"` |
| `opsgate_runner_tmp_dir` | `"{{ execution_data_dir }}/tmp"` |
| `opsgate_tmux_tmpdir` | `"{{ execution_data_dir }}/tmux"` |
| `opsgate_ops_workspace_dir` | `"{{ ops_home_dir }}/workspaces"` |
| `opsgate_ops_manage_workspace_repos` | `false` |
| `opsgate_ops_workspace_repositories` | `[{"name": "ops-control", "repo": "git@github.com:ephes/ops-control.git", "version": "main"}, {"name": "ops-library", "repo": "git@github.com:ephes/ops-library.git", "version": "main"}]` |
| `opsgate_ops_ssh_known_hosts_path` | `"{{ ops_home_dir }}/.ssh/known_hosts"` |
| `opsgate_ops_ssh_config_path` | `"{{ ops_home_dir }}/.ssh/config"` |
| `opsgate_ops_github_ssh_private_key_path` | `"{{ ops_home_dir }}/.ssh/id_github_ed25519"` |
| `opsgate_ops_github_ssh_public_key_path` | `"{{ ops_home_dir }}/.ssh/id_github_ed25519.pub"` |
| `opsgate_ops_github_host_key` | `"github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"` |
| `opsgate_ops_github_deploy_key_path_prefix` | `"{{ ops_home_dir }}/.ssh/id_github_deploy_"` |
| `opsgate_app_dir` | `"{{ control_service_home_dir }}/opsgate"` |
| `opsgate_runner_app_dir` | `"{{ ops_home_dir }}/opsgate"` |
| `opsgate_config_dir` | `"/etc/opsgate"` |
| `opsgate_log_dir` | `"/var/log/opsgate"` |
| `opsgate_runtime_dir` | `"/usr/local/var/opsgate/run"` |
| `opsgate_state_dir` | `"{{ opsgate_runtime_dir }}/control"` |
| `opsgate_db_path` | `"{{ opsgate_state_dir }}/opsgate.sqlite3"` |
| `opsgate_source_path` | `""` |
| `opsgate_uv_bin` | `"uv"` |
| `opsgate_rsync_excludes` | `[".vault_password", ".git", ".venv", ".pytest_cache", ".mypy_cache", ".ruff_cache", "__pycache__", "/rust/"]` |
| `opsgate_api_impl` | `"python"` |
| `opsgate_runner_impl` | `"python"` |
| `opsgate_rust_version` | `""` |
| `opsgate_rust_sha256` | `""` |
| `opsgate_rust_release_url` | `"https://github.com/ephes/opsgate/releases/download/rs-v{{ opsgate_rust_version }}/opsgate-{{ opsgate_rust_version }}-aarch64-apple-darwin.tar.gz"` |
| `opsgate_rust_local_archive` | `""` |
| `opsgate_rust_install_root` | `"/usr/local/libexec/opsgate-rs"` |
| `opsgate_rust_keep_versions` | `3` |
| `opsgate_launchd_python_plist_dir` | `"{{ opsgate_config_dir }}/launchd-python"` |
| `opsgate_launchd_verify_retries` | `10` |
| `opsgate_launchd_verify_delay` | `3` |
| `opsgate_api_bind_host` | `"0.0.0.0"` |
| `opsgate_api_bind_port` | `8711` |
| `opsgate_trust_proxy_headers` | `false` |
| `opsgate_session_cookie_secure` | `false` |
| `opsgate_ui_session_timeout_seconds` | `28800` |
| `opsgate_require_tailscale_context` | `true` |
| `opsgate_allowed_cidrs` | `["127.0.0.1/32", "::1/128", "100.64.0.0/10", "fd7a:115c:a1e0::/48"]` |
| `opsgate_disable_file_path` | `"{{ execution_data_dir }}/.disabled"` |
| `opsgate_runner_poll_interval_seconds` | `5` |
| `opsgate_runner_heartbeat_interval_seconds` | `30` |
| `opsgate_runner_stale_after_seconds` | `120` |
| `opsgate_max_parallel_jobs` | `3` |
| `opsgate_max_duration_seconds_default` | `3600` |
| `opsgate_runner_api_base_url` | `"http://127.0.0.1:{{ opsgate_api_bind_port }}"` |
| `opsgate_runner_host` | `"{{ inventory_hostname \| default('runner') }}"` |
| `opsgate_policy_floor_require_reviewer_step` | `false` |
| `opsgate_submit_policy_openclaw_require_reviewer_step` | `false` |
| `opsgate_submit_policy_nyxmon_require_reviewer_step` | `false` |
| `opsgate_submit_policy_operator_require_reviewer_step` | `true` |
| `opsgate_ui_username` | `"opsgate-admin"` |
| `opsgate_ops_git_user_name` | `"OpsGate Runner"` |
| `opsgate_ops_git_user_email` | `"opsgate@localhost"` |
| `opsgate_ops_github_username` | `""` |
| `opsgate_tmux_socket_label` | `"remediation"` |
| `opsgate_tmux_conf_path` | `"{{ ops_home_dir }}/.tmux.conf"` |
| `opsgate_tmux_history_limit` | `200000` |
| `opsgate_tmux_base_index` | `1` |
| `opsgate_launchd_manage_state` | `false` |
| `opsgate_launchd_start_services` | `false` |
| `opsgate_launchd_keepalive` | `true` |
| `opsgate_launchd_path` | `"/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"` |
| `opsgate_api_launchd_label` | `"de.wersdoerfer.opsgate.api"` |
| `opsgate_api_launchd_plist_path` | `"/Library/LaunchDaemons/{{ opsgate_api_launchd_label }}.plist"` |
| `opsgate_api_launchd_manage_state` | `"{{ opsgate_launchd_manage_state }}"` |
| `opsgate_api_launchd_start_service` | `"{{ opsgate_launchd_start_services }}"` |
| `opsgate_api_program` | `"/usr/bin/env"` |
| `opsgate_api_program_arguments` | `["bash", "-lc", "cd {{ opsgate_app_dir }} && .venv/bin/python -m opsgate serve"]` |
| `opsgate_api_working_directory` | `"{{ opsgate_app_dir }}"` |
| `opsgate_api_stdout_log` | `"{{ opsgate_log_dir }}/opsgate-api.log"` |
| `opsgate_api_stderr_log` | `"{{ opsgate_log_dir }}/opsgate-api.err.log"` |
| `opsgate_api_environment` | `{"HOME": "{{ control_service_home_dir }}", "PATH": "{{ opsgate_launchd_path }}", "OPSGATE_ENV_FILE": "{{ opsgate_config_dir }}/opsgate-api.env"}` |
| `opsgate_runner_launchd_label` | `"de.wersdoerfer.opsgate.runner"` |
| `opsgate_runner_launchd_plist_path` | `"/Library/LaunchDaemons/{{ opsgate_runner_launchd_label }}.plist"` |
| `opsgate_runner_launchd_manage_state` | `"{{ opsgate_launchd_manage_state }}"` |
| `opsgate_runner_launchd_start_service` | `"{{ opsgate_launchd_start_services }}"` |
| `opsgate_runner_program` | `"/usr/bin/env"` |
| `opsgate_runner_program_arguments` | `["bash", "-lc", "cd {{ opsgate_runner_app_dir }} && .venv/bin/python -m opsgate runner"]` |
| `opsgate_runner_working_directory` | `"{{ execution_data_dir }}"` |
| `opsgate_runner_stdout_log` | `"{{ opsgate_log_dir }}/opsgate-runner.log"` |
| `opsgate_runner_stderr_log` | `"{{ opsgate_log_dir }}/opsgate-runner.err.log"` |
| `opsgate_runner_environment` | `{"HOME": "{{ ops_home_dir }}", "PATH": "{{ opsgate_launchd_path }}", "TMUX_TMPDIR": "{{ opsgate_tmux_tmpdir }}", "OPSGATE_TMUX_SOCKET_LABEL": "{{ opsgate_tmux_socket_label }}", "OPSGATE_ENV_FILE": "{{ opsgate_config_dir }}/opsgate-runner.env"}` |

## Private HTTPS ingress

`OpsGateIngressConfig` and `deploy_opsgate_ingress` preserve the original
`opsgate_ingress_deploy` role's template, internal source ranges, TLS and
header policy. They run on the existing Linux Traefik host as a separate stage
after the Mac daemon. Configuration uses the original names without the
`opsgate_ingress_` prefix: `backend_url`, `traefik_host`, `traefik_enabled`,
`traefik_entrypoints`, `traefik_cert_resolver`, `traefik_config_path` and
`allowed_ip_ranges`. The defaults and rendered bytes match the role.

Route publication uses `services._traefik_routes.route_put`, including its
existing transaction-lock guard and no-write convergence. Only an actual route
change invokes the original service handler: reload Traefik, and restart if
reload fails. Disabling ingress skips it and retains its existing route.

Focused role parity is exercised against the current absolute library checkout.
The owned Linux workflow tests real Traefik routing, conditional reload/restart,
transaction-lock failure preservation and zero-change repeats; qualification of
this additive ingress path is pending its recorded workflow result.
