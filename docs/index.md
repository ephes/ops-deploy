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
  core/git_source.py  fetch_source: a service's code from its git remote, on the controller
  core/templates.py   Jinja2 rendering of package templates
  ops/sync_tree.py    sync_tree: rsync a controller directory to the host
  ops/secret_file.py  secret_file (install a secret via stdin, temp file, rename), secret_stdin
  helpers/            system_user, sudoers, systemd, uv/Django, Traefik, PostgreSQL, read-only checks, deployed-commit record
  base/               host-level deploys: hostname, unit masks, headless mode, authorized keys, uv, Node.js, shell basics,
                      SSH guard, dpkg foreign architectures
  infra/              shared host services: PostgreSQL (server, config, databases), Redis,
                      Traefik (deploy, backup, restore, remove), certbot DNS-01 lineage
  infra/bind/         authoritative BIND primary/secondary (port of the bind_authoritative_deploy role, deploy only)
  services/toy/       toy service exercising the pieces above
  services/toyweb/    toy uv/Django service using every helper
  services/nyxmon/    nyxmon (port of the nyxmon_deploy role)
  services/nyxmon_site_checks/ one Nyxmon service and its checks, upserted in Nyxmon's database
  services/opaq_app/  opaq_app (port of the opaq_app_deploy role)
  services/fastdeploy/ fastdeploy (port of the fastdeploy_deploy role)
  services/delve/     delve (port of the delve_deploy role)
  services/weeknotes_home/ weeknotes.home (port of the weeknotes_home_deploy role)
  services/echoport/  echoport (port of the echoport_deploy role)
  services/work_app/  work_app (port of the work_app_deploy role)
  services/zellij_ingress/ redirect-only Traefik route (port of the zellij_ingress_deploy role)
  services/gotosocial/ GoToSocial from a pinned release (port of the gotosocial_deploy role)
  services/thermal_monitoring/ thermal exporter, cached endpoint and Nyxmon freshness check (two roles)
  services/unifi/      UniFi configuration convergence on an existing installation (no bootstrap or upgrades)
  services/metube/    Native Git + staged Angular + uv MeTube
  services/navidrome/ Confirmed original Navidrome removal
  services/jellyfin/   Jellyfin deploy and confirmed removal
  services/vaultwarden/ vaultwarden from the vendor's .deb packages (port of the vaultwarden_deploy role)
  services/_nyxmon_json_metrics/ the Nyxmon json-metrics check upsert host monitoring deploys share
  services/_metrics_httpd/ the Python/Rust metrics-httpd switch of the endpoint deploys (thermal, logyard, static_site)
  services/_traefik_routes/ Traefik dynamic-file writes and removals that wait for Traefik transactions
  testing/harness.py  run_deploy_fake(): in-process runs against @fake
tests/                pytest, no network, well under 10 s
```

## Versions

- Python 3.12 or newer on the controller.
- pyinfra pinned to `3.10.*`. pyinfra 3.10 deprecates `MaskString`; use
  `pyinfra.api.hiddenvalue.HiddenValue` (ruff bans the old name here).

## Mastodon incident upgrade

`ops_deploy.services.mastodon_upgrade.upgrade_mastodon(domain)` is a targeted
upgrade of an existing `/home/mastodon/live` installation from 4.6.9 to 4.7.4.
It is not a bootstrap deploy or general Mastodon lifecycle implementation.
Run it through a private inventory wrapper, as root, one host at a time,
with staging verified before production. The controller must use this checkout.

The procedure requires a clean checkout, healthy web/Sidekiq/streaming/nginx
services, an inactive maintenance job, and at least 20 GiB free.
The fixed layout is the `mastodon` Unix user and PostgreSQL database,
`mastodon-web`, `mastodon-sidekiq`, `mastodon-streaming`, and `mastodon-nginx`
units, an enabled `mastodon-maintenance.timer`, and loopback ports 10042 (web)
and 10043 (streaming). Preflight verifies timer enablement, `DB_NAME`, and
both endpoints before taking a backup or changing source. Other layouts,
including the normal deploy's default ports, are outside this procedure.
It creates a root-only `/opt/backups/mastodon/security-4.7.4` directory with a
PostgreSQL
custom dump, global roles, environment/bundler/unit/maintenance configuration,
and local media excluding refetchable `public/system/cache`. Application
services stop during the backup and restart on exit; the maintenance timer is
paused during source updates and restored after successful verification.

It installs Ruby 4.0.9 and Node 24.19.0 before switching source, installs
dependencies, builds assets, runs pre-deployment migrations, updates the three
application units and maintenance unit/script, restarts the application, then
runs post-deployment migrations. Existing systemd drop-ins stay in place.
The fetched v4.7.4 tag must resolve to
`d04059fc80be5cbba6b4dd5a8b94d63ffff09f2c` before runtime installation proceeds.
Between the source checkout and service restart, existing processes keep the
old runtime. A process that crashes or recycles in this window can fail to
restart against the new source. Monitor service health during this window;
after a failed dependency/asset/migration step, inspect service logs and finish
the upgrade before treating the installation as healthy. A retry's initial
service check does not by itself establish readiness.
Verification checks the loopback instance API reports 4.7.4, streaming health,
service status, bundle completeness and absence of pending migrations.

A dry run only plans operations; it does not execute remote script preflight.
Re-running a completed backup verifies its checksums and preserves it. A partial
backup directory is deliberately refused: inspect it and move it aside before
retrying. An upgrade failure stops further operations; inspect the last step
and services before retrying. Once migrations have run, do not merely check out
the old tag: restoring the old application requires a coordinated restore of
the database and configuration from the protected backup. Backups contain
credentials and must remain root-readable only, including controller copies.
