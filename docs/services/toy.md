# toy

A small service used to exercise the building blocks and the test harness. It
runs `python3 -m http.server` bound to localhost as a systemd unit. It has no
secrets.

```python
from ops_deploy.services.toy import ToyConfig, deploy_toy

deploy_toy(ToyConfig(source_path=Path("~/src/toy").expanduser()))
```

## Configuration (`ToyConfig`)

| Field | Default | Notes |
|---|---|---|
| `service_name` | `toy` | systemd unit is `<service_name>.service` |
| `user` | `toy` | owns the site directory, synced files and config; must exist on the host |
| `site_path` | `/home/toy/site` | |
| `source_path` | `None` | local directory synced to `<site_path>/app/`; must exist |
| `app_port` | `10099` | 1024-65535 |
| `greeting` | `hello` | written to the config file |

## What the deploy does

1. Creates `site_path` (`0755`, owned by `user`).
2. If `source_path` is set: rsync dry run on the controller; when it reports
   changes, syncs to `<site_path>/app/` with `--delete`, `--chown=user:user`
   and the mandatory excludes `.git`, `.venv`, `__pycache__`, `.env`. The rsync
   target is `ssh_user@ssh_hostname` from host data (`root` and the host name
   by default).
3. Writes `<site_path>/toy.conf` from `toy.conf.j2`.
4. Installs `/etc/systemd/system/<service_name>.service` from `toy.service.j2`.
5. Runs `systemctl daemon-reload` only when the unit changed.
6. Ensures the unit is enabled and running.
7. Restarts it only when the source, config or unit changed.

A second run against an unchanged host performs no changes.

Pass `rsync=` to replace the rsync runner (tests use `RecordingRsyncRunner`).
