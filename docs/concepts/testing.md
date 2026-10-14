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
