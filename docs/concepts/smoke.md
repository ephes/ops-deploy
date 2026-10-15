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
  python3, `build-essential` (some wheels, such as asyncpg for Python 3.14,
  do not exist for arm64 and are built from source, as macmini can), uv
  0.13.0 in `/usr/local/bin`, Traefik 3.7.14 as `traefik.service` with the
  file provider on `/etc/traefik/dynamic` and the `web-secure` entry point on
  `:443` (Traefik's default certificate), and PostgreSQL 17 from the PGDG
  repository (in the repository file `postgres_install` writes). Root's login
  shell is fish (`/usr/bin/fish`), as on macmini and staging: every deploy
  command passes through it.

The VM is meant to stay up between runs and is shared by later slices; a test
must leave it in a state the next run can deploy over.

## What runs

`tests/smoke/` is skipped unless `SMOKE_SSH_HOST` is set (the recipe sets it).
Checks on the VM go through `SmokeHost.run`, which sends them base64-encoded
for `sh` to evaluate, so they do not depend on root's fish login shell;
`login_shell=True` sends a command as it is, the way pyinfra does.
A smoke session also fails when a strict probe logged a failure ("probe
failed: ..."), even if the step after it and the second probe passed.
Services that share a port (chesslab and marina use 10019, static_site's
smoke site and weeknotes_home 10062) cannot run side by side: stop the other
one's unit before such a smoke when one VM runs them all. With every service
deployed, the 2 GiB VM also runs out of memory (the kernel killed Logyard's
Loki): stop the other services' units before the Logyard smoke.

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
A third run from a fresh export of the same commit (new mtimes) must change
nothing.

`test_fastdeploy_smoke.py` deploys [fastdeploy](../services/fastdeploy.md)
from the committed `HEAD` of a FastDeploy checkout (`FASTDEPLOY_SOURCE`, else
`$PROJECTS_ROOT/fastdeploy`; skipped without one), adds a registered service
and a runner directory, deploys again and once more from a fresh export.
Both reruns may only restart the service. It checks the initial user's login,
the database role's password login, the sudoers rule, the Traefik auth, that
the registered service and runner survive, and leaks (also in
`/var/log/postgresql`). The first run installs Node.js from NodeSource and
builds the frontend.

`test_nyxmon_lifecycle_smoke.py` and `test_fastdeploy_lifecycle_smoke.py`
deploy the service again (the deploy tests' fixtures) and then back it up,
lose and restore data, and remove it twice (the second run without change)
before deploying it once more. The FastDeploy test also checks that a
restore from a broken archive rolls back to its safety backup. A nyxmon
backup creates `/opt/backups` as `0700` (as the role does); the FastDeploy
test sets it to `0755`, as on macmini, because `pg_dump` writes there as
`postgres`.

`test_delve_smoke.py` builds [delve](../services/delve.md) from the Delve
backend source (`DELVE_SOURCE_PATH`, else
`$PROJECTS_ROOT/podcast/apps/delve-backend`; skipped without one; needs Go)
for the VM's architecture and deploys it four times: first, converged, a
second build of the same source (identical bytes, no change) and a changed
binary over the running one (install and restart only). It checks the unit
and the disabled collector timer, owners and modes, `/health` through
Traefik, and leaks.

`test_weeknotes_home_smoke.py` deploys [weeknotes_home](../services/weeknotes_home.md)
from the committed `HEAD` of a daybook checkout (`DAYBOOK_SOURCE`, else
`$PROJECTS_ROOT/daybook`; skipped without one) after resetting its earlier
state on the VM. Its operations wiring runs against small stand-ins for
Echoport, FastDeploy and Nyxmon (`tests/smoke/weeknotes_home_stubs.py`).

`test_work_app_smoke.py` deploys [work_app](../services/work_app.md) from the
committed `HEAD` of a work-ledger checkout (`WORK_LEDGER_SOURCE`, else
`$PROJECTS_ROOT/work-ledger`; skipped without one) twice and once from a fresh
export; the reruns must have no mutating change. It checks the service,
modes and owners, the Traefik route, leaks, and that the port preflight
refuses another listener. It then backs the app up, deletes its data,
restores it, and removes it twice (the second removal changes nothing).

`test_infra_smoke.py` runs [PostgreSQL and Redis](../infra.md) on the VM.
PostgreSQL: twice with a throwaway database, owner and `pg_trgm` (second run
without mutating change; files equal the rendered role output), a table row
written as the owner over TCP survives, and a password change alters only the
role. Redis (installed if missing): password on, twice, unauthenticated
`PING` refused, `redis.conf` `root:redis 0640`; a `redis.conf` touched after
the server started gets a restart and a stored key survives it. Redis is left
without a password.

`test_traefik_smoke.py` runs [Traefik](../traefik.md) on the VM. It saves the
VM's own Traefik first and puts it back afterwards. Install of 3.7.13 over
the VM's 3.7.14, upgrade to 3.7.14 (install, version check, restart), a third
run without change or restart; the running binary, static config and unit
match the rendered role output; HTTP redirects to HTTPS, metrics answer on
the dashboard entrypoint, and a stand-in `lighttpd.service` ends up masked
and stopped. Then a backup with ACME state, a restore over a damaged store,
and a removal that keeps routes and certificates, run twice (the second
without change).

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
| fastdeploy first run, fresh service (Node.js, uv builds asyncpg, npm build) | 53.6 s |
| fastdeploy second run (converged apart from the restart) | 2.2 s |
| delve first run / second run / changed binary (2026-10-15) | 1.5 s / 0.4 s / 1.5 s |
| `just smoke`, VM running | 10-12 s |
