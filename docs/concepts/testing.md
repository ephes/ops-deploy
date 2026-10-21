# Testing deploys

`ops_deploy.testing` runs a whole deploy in-process against pyinfra's `@fake`
connector. A scenario takes milliseconds and does no network or controller I/O.

```python
from ops_deploy.services.toy import ToyConfig, deploy_toy
from ops_deploy.testing import RecordingRsyncRunner, run_deploy_fake

rsync = RecordingRsyncRunner(responses={"--dry-run": [">f.st...... app.py"]})
run = run_deploy_fake(
    deploy_toy,
    ToyConfig(source_path=src),
    rsync=rsync,
    responses={"--property SubState toy.service": ["Id=toy.service", "SubState=running"]},
    host_data={"ssh_hostname": "toy.example.invalid"},
)

assert run.succeeded
assert run.executed_commands[-1] == "systemctl restart toy.service"
```

## `run_deploy_fake(deploy_fn, *args, responses=None, host_data=None, **kwargs)`

Plans and executes `deploy_fn(*args, **kwargs)` on one fake host.

- `responses` is pyinfra's `fake_responses` mapping: keys are substrings or
  compiled regexes matched against the masked command, first match wins,
  values are stdout lines or `{"stdout", "stderr", "success"}`. Unmatched
  commands succeed with no output, which most facts read as "absent".
- `host_data` is extra host data (for example `ssh_hostname`).
- A failing operation does not raise: check `run.succeeded` and `run.error`.
  An exception raised while planning (for example a failed rsync dry run)
  propagates.

### Login-shell safety

sshd runs every command through the SSH user's login shell; root's on
macmini and staging is fish. pyinfra sends `sh -c '<command>'`, and inside
single quotes fish (unlike sh and bash) reads `\\` and `\'` as escapes, so
a backslash pair reaches `sh` halved. `run_deploy_fake` therefore builds the
exact line the SSH connector would send for every command (`wire_command`:
`_env`, `_chdir`, the shell wrapper) and raises `AssertionError` if any is
`fish_unsafe`, including the commands of operations an `_if` gate skipped
(they are generated once more with the gate ignored). Ship such payloads as a
file (`files.put`) or on stdin instead.

`tests/test_remote_shell_execution.py` checks `fish_unsafe` against real bash
and fish, and runs generated commands (the weeknotes_home `manage.py` wrapper
with a tricky env file, the `secret_file` installer, the FastDeploy restore's
pgpass line, the probe helpers) through both shells against temporary files.
The fish cases are skipped where fish is not installed.

## What gets recorded

`FakeRun.events` is the ordered list of `RecordedEvent(phase, kind, value)`:

| `kind` | Recorded from | `value` |
|---|---|---|
| `fact` | shell commands run while gathering a fact | masked command |
| `shell` | every other connector shell command | masked command |
| `put` | connector file uploads | remote path (content in `run.uploads`) |
| `function` | `FunctionCommand` callbacks, which `@fake` does not see | callback `__qualname__` |

`phase` is `plan` or `execute`. pyinfra re-reads facts while executing, so
`fact` events appear in both phases.

Helpers: `executed_commands` (non-fact shell commands while executing),
`mutating_changed_ops` (changed ops minus read-only checks such as
`wait_port`/`http_check`; empty on a converged second run),
`fact_commands`, `function_calls`, `uploads` (every `(path, content)` in order,
including repeated uploads to one path), `uploaded_paths`, `upload(path)`, `ops` / `changed_ops` / `op(name)`
(per-operation `changed`, `succeeded` and pyinfra's argument strings `args`),
`stdin` (every `(masked command, stdin text)` pair, as pyinfra sends it), and
`all_text()` for secret-leak assertions. `all_text()` covers events, op names,
op arguments and uploads but not `stdin`, which is where secrets are meant to
travel.

## Real hosts: `run_deploy_ssh`

`run_deploy_ssh(deploy_fn, *args, host_name=..., host_data=..., **kwargs)`
runs the deploy over pyinfra's ssh connector and returns an `SshRun`: the
same `ops`, `error`, `succeeded`, `changed_ops`, `mutating_changed_ops` and
`op()` as `FakeRun` (both are `DeployRun`s), plus `seconds`. `host_data`
holds the ssh connector keys; see [Smoke target](smoke.md).

## Controller-side rsync

`@fake` cannot see commands the controller runs itself. Code that needs rsync
takes an `RsyncRunner` (`ops_deploy.core.rsync`); production passes
`subprocess_rsync_runner`, tests pass `RecordingRsyncRunner`, which records each
argv in `calls` and returns scripted results (`responses` maps a matcher on the
joined argv to itemized lines or an `RsyncResult`). Unmatched calls return no
output, meaning "nothing to transfer".

## Modelling a converged host

A no-op test scripts the facts a fully deployed host would return: `stat`
output for files and directories, `sha1sum` output matching the rendered
content, and `systemctl show` output for the unit. `tests/test_toy.py`
(`converged_host`) is the reference.

## Drift from ops-library

The ports follow ops-library's roles, which keep changing. Parity tests
compare rendered files with the vendored role templates
(`tests/parity/ansible`), but a role can also change what it does (remove a
file, stop restarting Traefik, skip entries on restore) without touching a
template. With `OPS_LIBRARY_PATH` set to a checkout of ops-library's main
branch:

- `test_traefik_parity.py -k vendored` fails when a vendored template differs
  from the role's or is gone;
- `tests/test_ops_library_drift.py` fails when a role file vendored under
  `services/*/files` (`ensure_token_user.py`, `sudoers_blanket_check.py`, the
  delve StoreKit certificates) differs or is gone, and when a role a port
  mirrors changed since it was last checked:
  `tests/parity/ops_library_roles.json` records the ops-library commit and a
  digest of each role's `defaults`, `files`, `handlers`, `tasks`,
  `templates` and `vars`. It covers the `bind_authoritative_deploy`, `fastdeploy_*`, `graphyard_*`,
  `gotosocial_deploy`, `homelab_deploy`/`homelab_shared`, `jellyfin_deploy`/`jellyfin_shared`,
  `journald_config`, `livekit_deploy`,
  `minio_deploy`, `nyxmon_*`, `traefik_deploy`, `uv_install`, `work_app_*`
  and `zellij_ingress_deploy` roles so far. Entries added later than the
  recorded commit name the commit they were checked against in their service
  page (homelab, jellyfin, `uv_install` and gotosocial: `540ede2b`, 2.56.0;
  `bind_authoritative_deploy`: `56564cce`, 2.63.2).

After a role change, port it (or document why not), print the new digests
with `uv run python -m tests.test_ops_library_drift <ops-library>` and update
the manifest and its commit. Without `OPS_LIBRARY_PATH` these tests are
skipped (CI has no ops-library checkout); a stale checkout fails them.

## Notes on pyinfra behaviour

- An operation's body runs at plan time **and** again at execution time.
  `sync_tree` caches its dry run per host and operation so rsync is asked once;
  any other plan-time side effect must be cheap and read-only.
- `_stdin` is written line by line with a newline appended to each line and
  encoded as text, so it is not byte-exact. `secret_file` sends base64.
- Operations called with positional arguments are not typed by pyinfra's
  `PyinfraOperation.__call__`; call custom operations with keywords.
- `files.put` also manages the parent directory, so it emits a directory check
  and `mkdir -p` for the parent.
- The harness patches pyinfra classes for the duration of a run and serialises
  runs with a lock; do not run deploys from several threads in one test.
