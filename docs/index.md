# ops-deploy

`ops-deploy` is a Python package (`ops_deploy`) of typed
[pyinfra](https://pyinfra.com) deploys for self-hosted services.

It is the public half of the setup:

| Here (public) | Private repository |
|---|---|
| Service config classes (`BaseServiceConfig` subclasses) | Inventory (hosts, groups, connection data) |
| Deploy functions, templates, custom operations | SOPS-encrypted secret files and their decryption |
| `SecretRef` (a *path* to an encrypted file) | The `SecretStore` that turns a `SecretRef` into values |
| Test harness and tests | Entry points that wire a service to a host |

A deploy is a function `deploy_<service>(cfg, ...)` decorated with pyinfra's
`@deploy`. The private side validates the config, loads secrets on the
controller (so a bad key fails before any SSH connection), and runs the deploy.

## Layout

```
src/ops_deploy/
  core/config.py      BaseServiceConfig, ServiceName, UnixUser
  core/secrets.py     SecretRef, SecretValues, SecretStore protocol
  core/rsync.py       injectable controller-side rsync runner
  core/templates.py   Jinja2 rendering of package templates
  ops/sync_tree.py    sync_tree: rsync a controller directory to the host
  ops/secret_file.py  secret_file (install a secret via stdin, temp file, rename), secret_stdin
  helpers/            system_user, sudoers, systemd, uv/Django, Traefik, PostgreSQL, read-only checks
  base/               host-level deploys: hostname, unit masks, headless mode, authorized keys, uv, Node.js, shell basics
  infra/              shared host services: PostgreSQL (server, config, databases), Redis,
                      Traefik (deploy, backup, restore, remove)
  services/toy/       toy service exercising the pieces above
  services/toyweb/    toy uv/Django service using every helper
  services/nyxmon/    nyxmon (port of the nyxmon_deploy role)
  services/opaq_app/  opaq_app (port of the opaq_app_deploy role)
  services/fastdeploy/ fastdeploy (port of the fastdeploy_deploy role)
  services/delve/     delve (port of the delve_deploy role)
  testing/harness.py  run_deploy_fake(): in-process runs against @fake
tests/                pytest, no network, well under 10 s
```

## Versions

- Python 3.12 or newer on the controller.
- pyinfra pinned to `3.10.*`. pyinfra 3.10 deprecates `MaskString`; use
  `pyinfra.api.hiddenvalue.HiddenValue` (ruff bans the old name here).
