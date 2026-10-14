# Smoke target

`just smoke` deploys for real, over SSH, to a local [lima](https://lima-vm.io)
VM running Ubuntu 24.04, the OS of the prod host (macmini). It is the only part
of the test suite that touches a network or a host.

| Recipe | What it does |
|---|---|
| `just smoke-up` | create, start and provision the VM; idempotent, fast when it already runs |
| `just smoke` | `smoke-up`, then `pytest tests/smoke` (extra args are passed on) |
| `just smoke-ssh [cmd]` | root shell on the VM, or run `cmd` there |
| `just smoke-down` | delete the VM and its SSH key |

`smoke/vm.sh` installs lima with Homebrew if `limactl` is missing.

## The VM

- Instance `ops-deploy-smoke` (override with `SMOKE_VM`), lima template
  `ubuntu-24.04`, `vz`, plain mode (no mounts, no port forwards, no
  containerd), 2 CPUs, 2 GiB, 20 GiB disk. It uses the Mac's native
  architecture (arm64 on Apple silicon), while macmini is x86_64.
- Root logs in with a dedicated key in
  `~/.local/state/ops-deploy/smoke/<vm>/` (override with `SMOKE_STATE_DIR`),
  through lima's SSH forward on `127.0.0.1:<port>`. The port can change when
  the VM restarts; `smoke/vm.sh env` prints the current settings:

    ```sh
    smoke/vm.sh env
    # SMOKE_SSH_HOST=127.0.0.1
    # SMOKE_SSH_PORT=...
    # SMOKE_SSH_KEY=~/.local/state/ops-deploy/smoke/ops-deploy-smoke/id_ed25519
    # SMOKE_SSH_KNOWN_HOSTS=~/.local/state/ops-deploy/smoke/ops-deploy-smoke/known_hosts
    ```

    The host key is read through lima's own channel and pinned in that
    `known_hosts`, so every connection uses `StrictHostKeyChecking=yes`.
    `smoke-up` refreshes it.
- `smoke/provision.sh` (run as root on every `smoke-up`) installs what a
  service deploy expects to find, pinned to what macmini runs: rsync and
  python3, uv 0.13.0 in `/usr/local/bin`, and Traefik 3.7.14 as
  `traefik.service` with the file provider on `/etc/traefik/dynamic` and the
  `web-secure` entry point on `:443` (Traefik's default certificate).

The VM is meant to stay up between runs and is shared by later slices; a test
must leave it in a state the next run can deploy over.

## What runs

`tests/smoke/` is skipped unless `SMOKE_SSH_HOST` is set (the recipe sets it).

`test_toyweb_smoke.py` deploys [toyweb](../services/toyweb.md) with
`run_deploy_ssh` (pyinfra's ssh connector), using the Django app in
`smoke/toyweb_app/` and fresh random secrets per session, then deploys again:

- the second run has no mutating changes (`mutating_changed_ops == []`;
  `wait_port`/`http_check` are tagged read-only);
- the unit is active and enabled, the app answers on its port, migrations are
  applied;
- `.env` is `0600 toyweb:toyweb` and no staging directory is left;
- through Traefik, a client outside the internal ranges gets `401`, and `200`
  with the basic-auth password;
- neither secret is in `/tmp`, `/var/tmp`, `/dev/shm`, `/root` or the
  service home (outside `.env`); the route holds only the bcrypt hash.

`test_nyxmon_smoke.py` deploys [nyxmon](../services/nyxmon.md) twice from the
committed `HEAD` of a nyxmon checkout (`NYXMON_SOURCE`, else
`$PROJECTS_ROOT/nyxmon`; skipped without one) and checks convergence, both
units, private database and env files, migrations, the Traefik auth and leaks.

`test_secret_file_smoke.py` exercises `secret_file`'s failure handling on a
real host:

- a stream cut short (at a line boundary) is rejected as an interrupted
  upload; the destination is untouched and no staging directory exists;
- killing the SSH client mid-stream leaves the destination untouched, and the
  secret is nowhere in the temp directories;
- a failing final rename (a non-empty directory at the destination) removes
  the staging directory;
- a deploy over a stale staging directory (what a run killed after staging
  leaves) removes it, installs the file `0600 nobody:nogroup`, and a second
  run changes nothing; the value is not in the temp directories or the
  journal.

The run prints a "smoke timings" section with the wall time of each deploy.

## Timings

Measured on an Apple silicon Mac (2026-10-14):

| Step | Time |
|---|---|
| `smoke-up`, new VM, image not cached | 64 s |
| `smoke-up`, new VM, image cached | 19 s |
| `smoke-up`, VM running | 0.3 s |
| toyweb first run, fresh VM (user, uv sync, migrate, Traefik) | 8.0 s |
| toyweb first run, deployed VM (new secrets) | 3.6-5.6 s |
| toyweb second run (converged) | 0.3-0.4 s |
| nyxmon first run, fresh service (uv downloads Python 3.13) | 11.8 s |
| nyxmon second run (converged) | 0.8 s |
| `just smoke`, VM running | 10-12 s |
