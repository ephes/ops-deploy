# toyweb

A toy uv/Django web service that uses every deploy helper together. It is
shaped like nyxmon in its rendered-`pyproject.toml` mode. It exists to test the
helpers and is not deployed anywhere.

```python
from ops_deploy.services.toyweb import ToywebConfig, deploy_toyweb

cfg = ToywebConfig(secrets=SecretRef("secrets/prod/toyweb.yml"))
deploy_toyweb(cfg, store.load(cfg.secrets))
```

## Configuration (`ToywebConfig`)

| Field | Default | Notes |
|---|---|---|
| `service_name` | `toyweb` | unit, Traefik route name |
| `user` | `toyweb` | home is `/home/<user>` |
| `site_path` | `/home/toyweb/site` | `pyproject.toml`, `.env`, `.venv`, `app/`, `static/` |
| `source_path` | `None` | local directory synced to `<site_path>/app/` with `sync_tree` (`.env` excluded) |
| `persistent_excludes` | `/db.sqlite3`, `/db.sqlite3-*`, `/media/` | host-side state in `app/` that the sync never deletes |
| `app_port` | `10098` | |
| `python_version` | `3.12` | passed to `uv sync --python` |
| `dependencies` | `django>=5.2`, `granian>=2.0` | rendered into `pyproject.toml` |
| `traefik_host` | `toyweb.example.invalid` | |
| `basic_auth_user` | `admin` | |
| `secrets` | required | must provide `basic_auth_password` and `django_secret_key` |

## What the deploy does

1. Checks that the secrets have both keys.
2. `system_user`: group, user, home, `site`, `site/app`, `site/static`.
3. If `source_path` is set: `sync_tree` to `site/app/`.
4. Writes `pyproject.toml` (`0644`), and the `.env` with
   `DJANGO_SECRET_KEY` through `secret_file` (`0600`, over stdin). The key is
   single-quoted so the file works both as systemd `EnvironmentFile` and when
   sourced by `django_manage`. A key with spaces, quotes or backslashes is
   rejected before anything runs.
5. `uv sync --no-dev` if `pyproject.toml` changed or the venv is missing.
6. `migrate` and `collectstatic` if the sync ran or the source changed.
7. Installs the unit, then writes the Traefik route with basic auth, and
   restarts Traefik if the route changed.
8. `service_rollout`: daemon-reload on unit change, enable, start, and restart
   on unit, source, dependency or `.env` change.
9. `wait_port` and `http_check` (200 or 302, with the Traefik host header).
   Both are read-only.

`tests/test_toyweb.py` covers the first run, a converged second run (no
mutating changes), source, dependency, `.env` and unit changes, a missing
venv, a rotated password, and that neither secret appears in commands,
operation names or uploads (the secret key travels only on `secret_file`'s
stdin).
