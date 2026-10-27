# open_webui

Port of the `open_webui_venv_deploy` Ansible role: Open WebUI in a
uv-managed virtualenv, run by its own systemd unit, behind Traefik with basic
auth outside the internal networks. Deploy only: removal stays with the
`open_webui_venv_remove` role.

```python
from pydantic import SecretStr
from ops_deploy.helpers import BasicAuth
from ops_deploy.services.open_webui import OpenWebUIConfig, deploy_open_webui

cfg = OpenWebUIConfig(
    version="0.7.2",
    python_version="3.11.14",
    ollama_base_url="http://ollama.example.com:11434",
    traefik_host="chat.example.com",
    data_dir="/srv/data/open-webui/data",
    extra_env={"OFFLINE_MODE": "true", "ENABLE_VERSION_UPDATE_CHECK": "false"},
    mounts_required=("/srv/data",),
)
deploy_open_webui(cfg, BasicAuth(user="admin", password=SecretStr(password)))
```

ops-control registers it with the basic auth secret from its Traefik SOPS
file (see its `docs/PYINFRA.md`).

## Files are the role's

The role's `open-webui.env.j2`, `open-webui.service.j2` and
`open-webui-traefik.yml.j2` are shipped unchanged and rendered the way
Ansible's `template` module renders them (`trim_blocks`), so the environment
file, the unit and the route are byte-identical to the role's
(`tests/test_open_webui_parity.py`). The two tools can take turns on a host
without rewriting them, and the role's `traefik` task file (which
`rotate-traefik-basic-auth.yml` runs) keeps the route as this deploy wrote it.
The bcrypt hash is computed on the controller; the hash already in the
deployed route is kept while it still matches the password.

## Version pins and install constraints

The role installs the latest `open-webui` into the latest Python of a
prefix (`3.11`). Here `version` and `python_version` are exact, and the
deploy probes the host while planning:

- The virtualenv is kept while `<venv>/bin/python -I -B` runs and reports
  exactly `python_version`. Missing, broken (a dangling interpreter link) or
  another Python: `uv python install <python_version>` (a no-op when uv
  already has it), the virtualenv is removed and created again with
  `uv venv --managed-python --python <python_version>`.
- `uv pip install open-webui==<version>` runs after a recreation, or when the
  installed `open-webui` distribution has another version (or none).
- That install takes the certifi/pip floor constraints file and the shipped
  constraints of the version, `files/open-webui-<version>-constraints.txt`:
  the 288 distributions of the environment 0.7.2 was qualified with. A fresh
  install therefore resolves the same dependency versions (torch, the CUDA
  wheels, ...) instead of the latest ones. The constraints reach the host on
  stdin into a temporary file the service user can read, removed after the
  install; they are not kept on the host. A version without shipped
  constraints is refused by the config.

On a converged host none of these runs: no uv command at all, so a repeat
changes nothing.

`.webui_secret_key` in `site_dir` (Open WebUI generates it on its first
start and signs sessions with it while no `WEBUI_SECRET_KEY` is set) and
everything below `data_dir` are never written, also when the virtualenv is
recreated. `extra_env` may not set `WEBUI_SECRET_KEY` (it would replace that
key and sign everyone out) or `OPENAI_API_KEY` (no secret is written into
the environment file).

## Configuration (`OpenWebUIConfig`)

Defaults follow `open_webui_venv_deploy/defaults/main.yml`
(`tests/test_open_webui_parity.py` compares them with the role when
`OPS_LIBRARY_PATH` is set).

| Field | Default | Notes |
|---|---|---|
| `version`, `python_version` | `0.7.2`, `3.11.14` | not in the role (it installs the latest); exact releases |
| `service_name` | `open-webui` | the unit and the port preflight's owner |
| `user`, `group` | `openwebui` | system user, shell `/usr/sbin/nologin` |
| `home` | `None` | `None`: `/home/<user>`; uv keeps the managed Python and its cache there |
| `site_dir`, `data_dir`, `log_dir` | `/opt/open-webui`, `/var/lib/open-webui`, `/var/log/open-webui` | `user:group 0755` |
| `env_path`, `venv_path` | `None` | `None`: `<site_dir>/open-webui.env`, `<site_dir>/.venv` |
| `python_security_floor_enabled` | `true` | the floor constraints file, its use in the install, trust checks before and after |
| `python_security_constraints_path` | `None` | `None`: `<site_dir>/.python-security-constraints.txt` |
| `manage_uv`, `uv_install_dir` | `true`, `/usr/local/bin` | [`uv_install`](../base.md) with ops-deploy's pin; off: uv must already be there |
| `bind_host`, `host_port`, `use_host_flag`, `extra_args` | `127.0.0.1`, `3000`, `true`, none | `open-webui serve --port <port> --host <bind_host>` |
| `systemd_restart`, `systemd_restart_sec`, `systemd_hardening` | `on-failure`, `5`, `false` | |
| `ollama_base_url`, `webui_auth_enabled`, `openai_api_base_url` | the role's | rendered into the environment file (empty values are left out) |
| `extra_env` | `{}` | combined with the role's defaults (a key of the defaults is overridden in place) |
| `traefik_enabled`, `traefik_host` | `true`, required | the route `/etc/traefik/dynamic/open-webui.yml` |
| `traefik_entrypoints`, `traefik_cert_resolver`, `traefik_middlewares` | `web-secure`, `""`, none | plain names |
| `internal_ip_ranges` | the role's five | clients that skip basic auth |
| `basic_auth_enabled`, `basic_auth_remove_header` | `true`, `true` | without basic auth the role's single `open-webui-secure` router |
| `healthcheck_*` | the role's | port wait (`timeout × retries` seconds), then `GET http://<host>:<port><path>` |
| `mounts_required` | `()` | not in the role: mount points checked (read-only) before any change; `data_dir` must be below one |

Path fields must be absolute and in their one spelling (no `//`, `.` or
`..` segment, no trailing slash), so the checks below cannot be bypassed by
an alias. The virtualenv (removed when it is recreated) may not hold or lie
in `home`, `site_dir`, `data_dir`, `log_dir` or the secret key file, and the
two files the deploy writes (`env_path`, `python_security_constraints_path`)
must differ, may not be a managed directory, the secret key file, or lie in
`data_dir` or the virtualenv.

Not ported: `package_spec` (the version pin replaces it), `manage_user`,
`webui_secret_key`, `openai_api_key`, `uv_version`/`uv_update_existing`/
`uv_force_reinstall` (ops-deploy's `UvInstallConfig` pin),
`basic_auth_password_hash`, another `traefik_config_path` and
`systemd_enabled: false`.

## What the deploy does

1. Checks the basic auth rules, Linux with systemd, every `mounts_required`
   mount (`findmnt`) and the playbook's port preflight: a TCP listener on
   `host_port` at a loopback or wildcard address must belong to
   `<service_name>.service` (cgroup), or the deploy stops before any change.
2. With the floor enabled and a virtualenv that is kept, verifies its
   certifi/pip trust before any change (`helpers.python_security`). Unlike
   the role, certifi is not deferred: the role's unconditional install could
   raise it, this deploy installs only on a version change. An environment
   below the floor is refused; removing the virtualenv makes the next deploy
   recreate it with the shipped constraints (certifi 2026.10.19).
3. uv (`manage_uv`); the group and system user. An existing user is only
   added to the group (home, shell and primary group are left as they are,
   with a warning when they differ). The home directory is created
   `user:group 0750` (what `useradd -m` gives on Ubuntu) only while it is
   missing; an existing one is never changed.
4. The site, data and log directories; the environment file
   (`root:root 0600`, written with `secret_file`); the floor constraints file
   (`user:group 0644`).
5. Interpreter, virtualenv and package as above; after an install, a probe
   must find exactly `version`. The trust check runs again afterwards.
6. The unit (`root:root 0644`). `daemon-reload` only when it changed; enable
   and start; restart only when the environment file, the unit, the
   interpreter, the virtualenv or the package changed (and not right after
   this run started it). The role reloads systemd on every run.
7. The route, without restarting Traefik (its file provider watches the
   directory; the role's handler reloads it).
8. Health checks (read-only).

## Tests

`tests/test_open_webui.py` (plans against the fake connector: fresh,
converged, version change, unusable virtualenvs, environment, unit and route
changes, refusals), `tests/test_open_webui_parity.py` and the owned native
fixture [`tests/integration/linux_apps`](https://github.com/ephes/ops-deploy/tree/main/tests/integration/linux_apps)
(a real install of 0.7.2 with the constraints, sessions across restarts and
recreations, faults and zero-write repeats).
