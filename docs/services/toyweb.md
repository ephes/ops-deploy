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
| `app_port` | `10098` | |
| `python_version` | `3.12` | passed to `uv sync --python` |
| `dependencies` | `django>=5.2`, `granian>=2.0` | rendered into `pyproject.toml` |
| `traefik_host` | `toyweb.example.invalid` | |
| `basic_auth_user` | `admin` | |
| `secrets` | required | must provide `basic_auth_password` |

## What the deploy does

1. Checks that the secrets have `basic_auth_password`.
2. `system_user`: group, user, home, `site`, `site/app`, `site/static`.
3. Writes `pyproject.toml` (`0644`) and `.env` (`0600`, no secrets).
4. `uv sync --no-dev` if `pyproject.toml` changed or the venv is missing.
5. `migrate` and `collectstatic` if the sync ran.
6. Installs the unit, then writes the Traefik route with basic auth, and
   restarts Traefik if the route changed.
7. `service_rollout`: daemon-reload on unit change, enable, start, and restart
   on unit, dependency or `.env` change.
8. `wait_port` and `http_check` (200 or 302, with the Traefik host header).
   Both are read-only.

`tests/test_toyweb.py` covers the first run, a converged second run (no
mutating changes), a dependency change, `.env` and unit drift, a missing venv,
a rotated password, and that the password never appears in commands,
operation names or uploads.
