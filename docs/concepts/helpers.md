# Deploy helpers

`ops_deploy.helpers` replaces the shared parts of the Ansible roles. Each
helper is a plain function called inside a `@deploy`. It adds pyinfra
operations and returns their `OperationMeta`, so later steps can be gated on
change. Ansible's `notify`/handlers become explicit arguments such as
`when_changed=[...]` and `restart_when=[...]`.

```python
@deploy("Deploy app")
def deploy_app(cfg: AppConfig, secrets: SecretValues) -> None:
    system_user(cfg.user, home=cfg.home, directories=[cfg.site_path])
    pyproject = files.put(...)
    deps = uv_sync(cfg.site_path, user=cfg.user, home=cfg.home, when_changed=[pyproject])
    django_manage(
        cfg.app_path,
        "migrate",
        "--noinput",
        user=cfg.user,
        home=cfg.home,
        venv=cfg.venv_path,
        env_file=cfg.env_path,
        when_changed=[deps],
    )
    unit = systemd_unit(cfg.service_name, render(...))
    traefik_route(
        TraefikRoute(
            name="app",
            host=cfg.host,
            app_port=cfg.app_port,
            basic_auth=BasicAuth(user="admin", password=SecretStr(secrets["pw"])),
        )
    )
    service_rollout(cfg.service_name, units=[unit], restart_when=[deps])
    wait_port(cfg.app_port)
    http_check(f"http://127.0.0.1:{cfg.app_port}/")
```

`services/toyweb` is a complete example and the deploy-level test bed.

## `system_user(user, *, home, group=None, shell="/bin/bash", directories=(), mode="0755")`

Ensures a system group (default: same name as the user), a system user with
that primary group, `home`, and then `directories` in order. All of them are
owned by `user:group` with `mode`. Replaces `tasks/user.yml`.

- The home directory is created by the directory step, not by `useradd`
  (`-M`), so the same code path covers new and existing users.
- An existing user is not modified, as in the roles: its home, shell and
  primary group stay as they are. The only change is adding it to `group`
  (`usermod -a -G`) if it is in neither its primary nor its supplementary
  groups. Any difference from the wanted home, shell or primary group is
  logged as a pyinfra warning (`existing user app has home '/srv/app',
  wanted '/home/app'; left unchanged`), so drift shows up without being
  "fixed" behind the operator's back.

## `sudoers_file(name, content)`

Installs `/etc/sudoers.d/<name>` as `root:root 0440`, like the roles'
`template` with `validate: visudo -cf %s`. The content is uploaded to
`/etc/sudoers.d/.ops-deploy-<name>` first (sudo skips drop-ins whose name
contains a dot, so the staged copy is never live), checked with `visudo -cqf`
and only then moved over the rule; a rule that does not parse is removed and
the installed one stays. No change when content, owner and mode already match.
`name` may only use letters, digits, `_` and `-`.

## `postgres_database(name, *, owner, password, admin_user="postgres", service="postgresql", port=5432, enabled=True)`

Replaces the database part of `postgres_install` (`postgres_install_users`
and `postgres_install_databases`): `service` running (and enabled unless
`enabled=False`), login role
`owner` with `password` (a `SecretStr`), database `name` owned by it, and its
`public` schema owned by it. Other role attributes are left alone. All SQL runs
as `admin_user` through `runuser ... psql -p <port>` (peer auth; the port
selects the cluster), and the server must be running by the time the
operations run: either already, or set up by
[`deploy_postgres_install`](../infra.md) earlier in the same deploy. While it
is not installed or not running at planning time, the probe reads as empty and
role and database are planned as new; a `CREATE` of something that does exist
then fails instead of changing it.

The password never leaves the controller. PostgreSQL accepts a pre-hashed
SCRAM-SHA-256 verifier, so the helper computes one (random salt, 4096
iterations) and sends `CREATE/ALTER ROLE ... PASSWORD '<verifier>'` on
`psql`'s stdin. To decide whether the role needs it, the probe reports the
stored verifier's iteration count and salt plus a SHA-256 of the whole
verifier (never the verifier itself); the controller recomputes the verifier
with that salt and compares. A role with the right password and `LOGIN`
changes nothing. Passwords must be ASCII (PostgreSQL's SASLprep is the
identity there). Identifiers must be plain lowercase names.

Returns `PostgresDatabase(service, role, database)`.

## `systemd_unit(name, content)`

Writes `<name>.service` (or `name` as is, if it already ends in a unit type
such as `.timer`) as `root:root 0644`. It reports a change only if the content
differs.

## `service_rollout(name, *, units=(), restart_when=(), always_restart=False)`

Returns a `Rollout` with the operation metas:

1. `systemctl daemon-reload` only if one of `units` changed.
2. `systemctl enable` if not enabled.
3. `systemctl start` if not running.
4. `systemctl restart` if one of `units` or `restart_when` changed, or always
   with `always_restart=True` (for fastdeploy, whose restart stays
   unconditional, even right after step 3 started it). Without
   `always_restart`, there is no restart directly after step 3 started the
   service in the same run.

The roles enable, start and then restart via handlers, so a first Ansible run
starts the service and then restarts it. Here it is started once.

## `uv_sync(project_dir, *, user, home, venv=None, python=None, args=..., uv=/usr/local/bin/uv, when_changed=None)`

Runs, as root dropping to the service user:

```
cd <project_dir> && runuser -u <user> -- env HOME=<home> UV_PROJECT_ENVIRONMENT=<venv> <uv> sync <args> [--python X]
```

- `args` defaults to `--frozen --no-dev --no-default-groups` (what the roles
  run against a synced lockfile). Pass `("--no-dev",)` for a rendered
  `pyproject.toml` without a lockfile.
- `venv` defaults to `<project_dir>/.venv`.
- With `when_changed`, the sync only runs if one of those operations changed,
  or if `<venv>/bin/python` is not executable (first deploy, a venv removed by
  hand, or a dangling interpreter symlink). Without `when_changed` it runs every time.
- When it runs, pyinfra reports it as changed. The roles look for
  `Installed`/`Uninstalled`/`Updated` in uv's output instead. Here the
  `when_changed` gate is what keeps a no-op deploy quiet.
- `HOME` is set so that uv's cache belongs to the service user, not root.

Why `runuser` rather than `_sudo_user`: the `_sudo` global arguments are
banned in this package (see `tests/test_policy.py`), because pyinfra stages
`_sudo` uploads as plaintext in `/tmp`.

## certifi/pip security floors: `ops_deploy.helpers.python_security`

After the eMudhra/emSign CA compromise (certifi advisory GHSA-6q48-6c7w-9gw2)
a normal deploy must not bring back certifi below 2026.10.19 or upstream pip
below 26.2.2. Both checks fail closed and never add, upgrade or rewrite
anything:

- `require_lock_floors(project, label, *, root=None)` reads, on the
  controller, every `uv.lock` uv may install for `project`: its own and those
  of its parents up to `root` (the synced tree), because a workspace member is
  installed from its workspace root's lock. It raises `ValueError`, naming the
  lock, when one locks certifi or pip below the floor (packages a lock does not
  contain are ignored). Call it while planning, before any operation, with the
  source the deploy syncs. Without any lock it is left to `uv sync`.
- `verify_trust(python, *, user, home, name)` is a read-only operation (see
  `mark_read_only`) for after the dependency sync: it runs
  `templates/python_security_check.py.txt` as `<python> -I -c <script>` as the
  service user (no secrets in it, so it travels on the command line, not
  stdin). It fails when certifi/pip in the environment are below the floor
  (noting when the floor release's `Requires-Python` excludes the
  environment's Python, so it cannot be updated in place), when they are
  imported from outside the environment unless `dpkg-query` shows
  `python3-certifi`/`python3-pip` using `/etc/ssl/certs/ca-certificates.crt`,
  or when their bundles contain emSign ECC Root CA - G3 or AAA Certificate
  Services (the environment's `ssl`/OpenSSL loads the bundle; each CA
  certificate it holds is matched by SHA-256 of OpenSSL's DER, as
  `openssl x509 -fingerprint` hashes it; a bundle OpenSSL cannot load fails). The
  installed version is read from the one `*.dist-info/METADATA` next to the
  imported package (no `importlib.metadata`, so old Pythons work; zero or
  several fail closed). Explicit trust settings such as
  `SSL_CERT_FILE` are not changed or inspected.

`django_site` uses both. The same floors are enforced by ops-library's
`python_security_floor` role for the Ansible deploys.

## `django_manage(project_dir, *command, user, home, venv, env_file=None, when_changed=None, name=None)`

Runs `./manage.py <command>` in `project_dir` as `user`, with `venv/bin` first
on `PATH` and `VIRTUAL_ENV` set. If given, `env_file` is sourced on the target
with `set -a`, so secret values never appear in the command line. The file
must be shell-sourceable, like the roles' `.env.shell`. `when_changed` gates
the command as in `uv_sync`.

## `traefik_route(route, *, renderer=render_route, restart="traefik")`

Writes `/etc/traefik/dynamic/<route.name>.yml` (`root:root 0644`; through
`secret_file` when it holds a basic-auth hash, see
[below](#no-hash-in-diff-output)) and restarts `traefik.service` when the file
changed and Traefik is running (the roles' `reload traefik` handler). With `restart="none"`, it relies on the file
provider's `watch = true` instead.

`TraefikRoute` covers the roles' dual-router template:

| Field | Default | Notes |
|---|---|---|
| `name` | required | router/middleware/service prefix and file name |
| `host` | required | validated host name |
| `app_port` | required | |
| `app_host` | `127.0.0.1` | |
| `title` | `""` | used only in the header comment |
| `basic_auth` | `None` | `BasicAuth(user, password: SecretStr)`; enables the dual-router pattern |
| `internal_ip_ranges` | RFC1918, Tailscale, ULA | clients that skip auth (priority 120 router) |
| `middlewares` | `()` | extra middlewares appended to every router |
| `cert_resolver` | `""` | empty means `tls: {}` (file-provider certificates) |
| `frame_options` | `DENY` | `customFrameOptionsValue`; fastdeploy uses `SAMEORIGIN` |
| `redirect` | `None` | `RedirectRegex(regex, replacement, permanent=False)` |
| `health_check` | `None` | `HealthCheck(path="/", interval="30s", timeout="3s")` |
| `internal_only` | `False` | one router for `internal_ip_ranges` (`<name>-int`, its `-http` with the same rule) and none for anyone else; excludes `basic_auth` (compose_app's `access: internal`) |

The `<name>-headers` middleware sends HSTS for 180 days
(`stsSeconds: 15552000`) with `includeSubDomains` and `forceSTSHeader`, but
without `preload`, as the roles' templates since ops-library `abae172`: the
owner decided against browser preload registration. No route template in
ops-deploy sets `stsPreload` (`tests/test_traefik_hsts.py`).

### Basic auth hashing

- The bcrypt hash is computed **on the controller** in the format
  `htpasswd -nB` produces (`$2y$`, cost 5). Traefik accepts both. The password
  never reaches the target or a command line. The roles pipe it into
  `htpasswd` on the target.
- The hash already in the deployed file is **reused** if it still verifies
  against the password. bcrypt salts are random, so re-hashing on every run
  (as the roles do) would rewrite the file and restart Traefik on every
  deploy. A rotated password produces a new hash and one restart.
- Hashes from `htpasswd` (the Ansible path) are reused as well. So once the
  comments match, switching a service from Ansible to ops-deploy causes no
  change.

### No hash in `--diff` output

With `--diff` (`just pyinfra-check` in ops-control runs `--dry --diff`),
pyinfra's `files.put` logs the old and new file line by line, so a basic-auth
route would show the deployed and the new bcrypt hash in the controller's
output. pyinfra 3.10 has no per-operation way to turn that off (`DIFF` is one
global config value, shared by all hosts' concurrent runs). So a route file
whose new content **or** deployed content holds an htpasswd hash marker
(`$2`/`$2a`/`$2b`/`$2x`/`$2y`, `$apr1$`, `{SHA}`) is written with
[`secret_file`](operations.md#secret_file) instead: its content travels on
stdin and is never logged. Under `--diff` such a route shows up only as a
changed operation, without a content diff; this also covers removing basic
auth from a route, whose deployed file still holds the old hash. Routes
without a hash are still written with `files.put` and diffed as before.

Bytes, owner and mode (`root:root 0644`) and change detection are the same:
a change of content, owner or mode marks the operation changed (and restarts
Traefik where `restart="traefik"`), and an up-to-date file is a no-op.
Differences that come with `secret_file`: an owner- or mode-only difference
rewrites the whole file (same bytes) instead of running `chown`/`chmod`; a
symlink at the route path is refused instead of replaced; the host needs
`python3`; and every route operation reads the deployed file
(`FileContents`), routes without basic auth included. pyinfra still prints
raw fact output at `-vvv`, which includes the deployed file; keep that
verbosity out of shared logs. `tests/test_traefik_route_diff.py` (and the
jellyfin and homelab `--diff` tests) check that no hash reaches anything
pyinfra logs, in the plan or the execution phase.

### Parity with the Ansible templates

`tests/test_traefik_parity.py` renders the vendored nyxmon and fastdeploy role
templates (`tests/parity/ansible/`) and checks that `render_route` produces the
same YAML, line for line, once comments and blank lines are dropped. The
comments differ: the header says "Managed by ops-deploy", and the role-specific
explanations are gone. So the first ops-deploy run over an Ansible-deployed
route rewrites the file once and restarts Traefik once. A service that needs a
byte-identical file can pass its own `renderer(route, auth_hash) -> str`.

Set `OPS_LIBRARY_PATH` to also check that the vendored copies still match
ops-library.

## Read-only checks: `wait_port` and `http_check`

```python
wait_port(port, *, host="127.0.0.1", retries=30, delay=1)
http_check(url, *, status=200, host_header=None, retries=10, delay=1, timeout=5)
```

Both run a single retry loop on the target: bash `/dev/tcp` for the port, and
`curl` without following redirects for HTTP. `status` may be one code or
several (for example `(200, 302)`). Arguments are validated against shell
metacharacters.

pyinfra reports every shell operation that ran as changed. Both helpers
therefore tag their operation with `mark_read_only`. `is_read_only(state,
op_hash)` lets a runner tell them apart. In tests, `OpResult.read_only` and
`FakeRun.mutating_changed_ops` exclude them, so "the second run changes
nothing" is checked as `run.mutating_changed_ops == []`. Use
`mark_read_only(meta)` for any other custom check that changes nothing.

## Pinned Rust release binaries: `ops_deploy.helpers.rust_release`

The pyinfra side of ops-library's internal role `rust_release_binary`
(ops-library `rust/PLAN-foundation.md` 6.1 and 6.3, slice F4). It installs,
pins and prunes release binaries of the Rust crates in ops-library's `rust/`
(`metrics-httpd`, `echoport-command-guard`, `software-live`). It uses the
same on-host layout and writes the same files with the same bytes as the role,
so Ansible and pyinfra can take turns on a host:

```
<root>/<version>/<name>              root:root 0755, never modified in place
<root>/<version>/LICENSE             root:root 0644 (and any other member)
<root>/<version>/.archive-sha256     root:root 0644, "<archive sha256>\n"
<root>/.pins/<consumer>              root:root 0644, "<version>\n": the version the consumer runs, verified live
<root>/.pins/<consumer>.previous     root:root 0644, "<version>\n": the rollback pin
<root>/.staging-<version>/           transient
```

`<root>` defaults to `/opt/<name>`. The [metrics-httpd
switch](../services/metrics_httpd.md) of `thermal_monitoring`, `logyard` and
`static_site` (slice S5e) is its first user.

```python
installed = install_release(
    "metrics-httpd",
    cfg.httpd_rust_version,
    sha256=cfg.httpd_rust_sha256,
    validate_user="thermal-metrics",
    fail_hard=cfg.httpd_impl == "rust",
)
# ... drop-in, restart, verify that the unit runs installed.binary ...
pin_release("metrics-httpd", "thermal-metrics-endpoint", cfg.httpd_rust_version)  # None: back to Python
prune_releases("metrics-httpd", protect=live_executables, after=[installed])
```

- `install_release(name, version, *, sha256="", install_root="", release_url="",
  local_archive=None, members=(), executables=(), validate_user="nobody",
  fail_hard=True)` returns an `Install` (`op`, `binary`, `validated`). An
  installed version is only validated (`validated` is true), as a read-only
  operation; a different archive for it is
  refused (an installed version is never replaced in place). A new version is
  downloaded from `release_url` (default: the ops-library GitHub release
  `<name>-v<version>`) or uploaded from `local_archive` (checked against
  `sha256` when both are given). The archive's sha256 must match, and it must
  hold exactly `members` (default `[name, "LICENSE"]`) as regular files at
  its root, each once. The members are unpacked with `executables` (default
  `[name]`) 0755 and the rest 0644, `.archive-sha256` is recorded, and the
  version is moved into place. Then `<binary> --version` runs as
  `validate_user` (`runuser`) and must start with `<name> <version> (`. A
  failure removes this run's fresh install and fails the deploy. With
  `fail_hard=False` it warns and the deploy goes on, so a Python rollback is
  never blocked, and `Install.failed()` tells later `_if` callbacks. A
  `local_archive` that cannot be read raises `ValueError` while planning, or
  with `fail_hard=False` is refused the same soft way on the host. A staging
  leftover is removed without following a symlink. It never moves a pin and
  never deletes another version.
- `pin_release(name, consumer, version, *, install_root="", previous="",
  keep_previous=True)` pins `version` for `consumer`, or removes the pin when
  `version` is `None`. Pinning `V` over a current pin `C ≠ V` makes `C` the
  previous pin. Removing the pin keeps its version as the previous pin unless
  `keep_previous` is false. `previous` replaces the automatic choice. The
  previous pin is written first. A pin file that is not a regular file
  holding exactly one version fails the step and changes nothing. Call it
  only after the consumer verified that its unit runs `version`. A later pin
  of the same consumer in one deploy runs whenever an earlier one changed,
  since its planning probe saw the files before that change.
- `prune_releases(name, *, install_root="", keep_versions=3, protect=(),
  live_state_unknown=False, after=())` keeps the `keep_versions` newest
  version directories by mtime, every version a pin of any consumer names
  (`.previous` included), and every `protect` entry. An entry is a version or
  an executable path as `readlink /proc/<pid>/exe` prints it, also with
  ` (deleted)` and below the root's resolved path. Only plain directories
  named like a version are ever removed. Prune deletes nothing and warns when
  `live_state_unknown` is set or a pin, the pin directory or a `protect` entry
  cannot be interpreted. It is skipped when an `Install` in `after` failed in
  this run, and it runs again, even when the planning probe found nothing,
  after an operation in `after` changed (an `Install` that only validated an
  installed version is no change). Unlike the role, nothing remembers a
  failed install by itself (the role's sticky
  `rust_release_binary_failed_names`): pass every `Install` of the crate from
  the same deploy in `after`.

The decisions (pin moves, the prune plan, the version and consumer grammar)
are ops-library's `plugins/filter/rust_release.py`, vendored byte for byte as
`templates/rust_release.py.txt`; `tests/test_ops_library_drift.py` compares
the two, and the drift manifest records the role. The steps run on the host
at execution time, in `templates/rust_release_host.py.txt` (standard library
only). Both texts are sent on stdin to `/usr/bin/python3 -I -` as root, so
target hosts need a system Python 3.9 or later; every Ansible-managed host
has one. While planning, the same script with `--check` (`probe`, read-only)
decides whether a pin or prune step is needed, so a converged run changes
nothing.

`tests/test_rust_release.py` runs the host script locally against temporary
roots with fake release archives. It also checks the planned operations
against the fake connector. With `OPS_LIBRARY_PATH` and `ansible-playbook`
it runs the role on a twin tree with the same steps: installs, the pin moves
v1 → v2 → v1 → v3, a second consumer, a switch to Python, then prunes with
`protect` entries and the fail-closed cases. The trees must stay
byte-identical (contents and modes), and both engines must remove the same
versions. On macOS the role needs Homebrew's `gmv`.

nyxmon's and graphyard's agent installs keep their own code (`.staging`,
`.previous-version`, no `.pins`). Moving them to this helper would change
their on-host layout, so it is not a pure refactor.

## Strict probes: `ops_deploy.helpers.probes`

A deploy decides while planning whether a step is needed by asking the host
(`migrate --check`, a wiring script in check mode, a database query). A probe
written as `... 2>/dev/null || true` turns every failure (a broken venv, a
crashed script, a command the login shell mangled) into an answer such as
"not current". Probes that run application code or tools use these helpers
instead:

```python
check = when_present([venv_python, manage_py, env_file], migrations_state(plan), otherwise="pending")
state = probe(check, name="app migrations")  # "current", "pending" or None
migrate = server.shell(..., _if=lambda: state != "current" or code.did_change())
if state is None:
    verify_probe(check, name="app migrations", expect="current")
```

- `probe(command, *, name, stdin=None)` runs the command in a subshell while
  planning and returns its stdout, or `None` when it exited non-zero (logged
  as a warning). `stdin` is text for the command's standard input: the way a
  check payload reaches a script without a command line or an environment
  variable (both readable by other users while it runs). It is passed as
  `StdinLines`, which prints as `<stdin redacted>`: pyinfra logs a fact's
  arguments, `_stdin` included, in its debug output ("Loaded fact ...").
  `stdin_arguments(text)` gives those global arguments (with `_get_pty=False`)
  for any other fact that needs stdin.
  A failure is not fatal while planning: the step it gates is how a
  half-finished earlier run repairs itself (a sync that died before
  `uv sync`), so the caller runs the step.
- `verify_probe(command, *, name, expect=None, stdin=None)` is a read-only operation
  ("Probe again: <name>") placed after that step: the probe must now succeed
  (and print `expect` last), else the deploy fails with the probe's error
  output. A probe that is broken for its own reasons can no longer pass as a
  change that is needed on every run.
- `when_present(paths, command, *, otherwise)`: states that are normal before a
  first deploy (no venv, no database yet) are answers, not failures.
- `migrations_state(plan)` wraps `manage.py migrate --check --plan`
  (`current`/`pending`; an exit without Django's "Planned operations:" line
  is an error), `uv_sync_state(check)` wraps `uv sync --check` (exit 1 is
  `pending`, anything else non-zero an error), `last_line(command)` prints the
  last stdout line of a check-mode script and fails with it.

Absence probes, whose failure is itself the answer (no file, no container, a
missing binary's version), keep the plain `2>/dev/null || true` form (for
example `ops_deploy.base._common.output`).

## Parity differences from the Ansible roles

Known, intended differences. Everything else is meant to behave like the
roles. The Traefik YAML is checked by `tests/test_traefik_parity.py`.

1. **Traefik file comments.** The generated route matches the nyxmon and
   fastdeploy templates line for line except for comments. The first
   ops-deploy run over an Ansible-deployed route therefore rewrites it once
   and restarts Traefik once. Use `renderer=` for a byte-identical file.
2. **Stable basic-auth hash.** The roles re-hash the password on every run, so
   their route file (and Traefik) changes on every deploy. Here a still-valid
   deployed hash is reused.
3. **uv/Django change reporting.** When `uv_sync` or `django_manage` run,
   pyinfra counts them as changed. The roles parse uv/`manage.py` output
   instead. The `when_changed` gates keep a no-op deploy free of them.
4. **Traefik restart only if running.** The route's restart only restarts a
   running Traefik. The roles' handler would also start a stopped one.
5. **One start on the first deploy.** `service_rollout` starts a new service
   once. The roles start it and then restart it from a handler.
   `always_restart=True` restarts even then.
6. **PostgreSQL install separate.** `postgres_database` manages the role,
   database and schema owner only; the roles also install and configure the
   server through their `postgres_install` dependency, which is
   [`deploy_postgres_install`](../infra.md) here. A changed password is
   set as a SCRAM verifier computed on the controller (the role sends the
   password).
