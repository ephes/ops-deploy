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

## `run_deploy_fake(deploy_fn, *args, responses=None, host_data=None, pyinfra_config=None, **kwargs)`

Plans and executes `deploy_fn(*args, **kwargs)` on one fake host.

- `responses` is pyinfra's `fake_responses` mapping: keys are substrings or
  compiled regexes matched against the masked command, first match wins,
  values are stdout lines or `{"stdout", "stderr", "success"}`. Unmatched
  commands succeed with no output, which most facts read as "absent".
- `host_data` is extra host data (for example `ssh_hostname`).
- `pyinfra_config` replaces the default `Config()`; `Config(DIFF=True)` with
  pytest's `caplog` shows what `--diff` would log.
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
`planned_changes` / `planned_conditional` (what a `--dry` run lists under
"Change" and "Conditional Change", from each op's `planned` field),
`mutating_changed_ops` (changed ops minus read-only checks such as
`wait_port`/`http_check`; empty on a converged second run),
`fact_commands`, `function_calls`, `uploads` (every `(path, content)` in order,
including repeated uploads to one path), `uploaded_paths`, `upload(path)`, `ops` / `changed_ops` / `op(name)`
(per-operation `changed`, `succeeded` and pyinfra's argument strings `args`),
`stdin` (every `(masked command, stdin text)` pair, as pyinfra sends it),
`secret_files` (every `(path, content)` a `secret_file` install sent, decoded
from its stdin), `written_paths` / `written(path)` (uploads and `secret_file`
installs together, for files such as basic-auth routes that may take either
way), and `all_text()` for secret-leak assertions. `all_text()` covers events, op names,
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

## Golden host files

Files a deploy writes to a host (units, env files, Traefik routes, configs,
root-owned scripts) are pinned by golden tests: a test renders the file from
synthetic inputs and compares it with the copy under `tests/golden/<service>/`
through `tests/goldens.py`'s `assert_golden(path, actual)`. Identical bytes
mean the next deploy rewrites nothing and restarts nothing, so a failing
golden test is a decision rather than a bug. When the change to the host file
is intended, record the new render and review the diff before committing it:

```bash
OPS_DEPLOY_UPDATE_GOLDEN=1 uv run --locked pytest -q tests/test_nyxmon_golden.py
git diff tests/golden
```

Name the golden directory literally in the test module
(`Path(__file__).parent / "golden" / "<service>"`), so that
`just test-changed` maps a changed golden file to its test. Goldens hold only
synthetic values: fixture secrets, `example` hosts and documentation
addresses (`192.0.2.0/24`), never real hostnames, IPs or secrets.

The goldens were first recorded when the Ansible parity and role-oracle tests
were retired (see the changelog): every deploy now runs on pyinfra, and the
recorded bytes are the ones the ops-library roles produced, which hosts
carried at that point. Files vendored from ops-library (`services/*/files`,
`infra/files`, `software_estate_publisher` templates, `*.py.txt` helpers) are
ops-deploy's own now and change like any other source; there is no longer a
comparison with an ops-library checkout. The
[2026-10-30 reconciliation](parity-reconciliation-2026-10-30.md) is kept as a
historical record.

Policy carried over from ops-library is checked without a checkout:
`tests/test_traefik_hsts.py` fails when any template under `src/` sets
`stsPreload` (HSTS preload, removed from the roles in `abae172`), and each
service's tests check its rendered route with `tests/hsts.py`.

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
