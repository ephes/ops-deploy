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
- If the user already exists with a different home, pyinfra runs
  `usermod -d` without `-m`, so files are never moved. The Ansible roles
  leave such a user unchanged instead.

## `systemd_unit(name, content, *, unit_dir=/etc/systemd/system)`

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

## `django_manage(project_dir, *command, user, home, venv, env_file=None, when_changed=None, name=None)`

Runs `./manage.py <command>` in `project_dir` as `user`, with `venv/bin` first
on `PATH` and `VIRTUAL_ENV` set. If given, `env_file` is sourced on the target
with `set -a`, so secret values never appear in the command line. The file
must be shell-sourceable, like the roles' `.env.shell`. `when_changed` gates
the command as in `uv_sync`.

## `traefik_route(route, *, renderer=render_route, restart="traefik")`

Writes `/etc/traefik/dynamic/<route.name>.yml` (`root:root 0644`) and restarts
`traefik.service` when the file changed and Traefik is running (the roles'
`reload traefik` handler). With `restart="none"`, it relies on the file
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
