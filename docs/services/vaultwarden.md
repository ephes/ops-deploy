# vaultwarden

Port of the `vaultwarden_deploy` Ansible role: [Vaultwarden](https://github.com/dani-garcia/vaultwarden),
the Bitwarden-compatible password manager, installed from the vendor's `.deb`
packages ([vaultwarden-deb](https://vaultwarden-deb.pages.dev/)) as a systemd
service behind Traefik, plus the port preflight of the playbook that runs the
role. Deploy only: backup, restore and remove stay with the Ansible roles.

```python
from ops_deploy.services.vaultwarden import VaultwardenConfig, deploy_vaultwarden

cfg = VaultwardenConfig(
    domain="https://vault.example.com",
    secrets=SecretRef("secrets/prod/vaultwarden.yml"),
    smtp_host="localhost",
    smtp_from="vault@example.com",
    traefik_entrypoint="web-secure",
)
deploy_vaultwarden(cfg, store.load(cfg.secrets))
```

ops-control registers it (see its `docs/PYINFRA.md`).

## Secrets

| Key | Required | Used for |
|---|---|---|
| `admin_token` | while the admin panel is enabled | `ADMIN_TOKEN` in `/etc/vaultwarden.env` |
| `admin_enabled` | no (`true`) | the playbook reads the admin panel switch from the secrets file; `true` or `false` |
| `smtp_username`, `smtp_password` | no (empty) | `SMTP_USERNAME`/`SMTP_PASSWORD`; without a user name neither line is written (the role's template) |

An empty or `CHANGEME` admin token is refused while the panel is enabled, as
the role asserts; any other `admin_enabled` value than `true`/`false` is
refused. Values must be single lines (the file is line based). Errors name
keys, never values. `/etc/vaultwarden.env` reaches the host only on stdin
(`secret_file`).

## Configuration (`VaultwardenConfig`)

Defaults follow `vaultwarden_deploy/defaults/main.yml`
(`tests/test_vaultwarden_parity.py` compares them with the role when
`OPS_LIBRARY_PATH` is set).

| Field | Default | Notes |
|---|---|---|
| `domain` | required | `DOMAIN`; the route's host is the domain without scheme and path, and must be a DNS name without a port |
| `apt_repo_url` | `https://vaultwarden-deb.pages.dev` | the repository and its signing key |
| `rocket_address`, `rocket_port` | `127.0.0.1`, `8000` | IPv4 only (the role renders `http://<address>:<port>`); the port preflight and health check use them |
| `websocket_enabled`, `signups_allowed`, `invitations_allowed`, `show_password_hint`, `org_creation_users` | role defaults | `.env` |
| `smtp_host`, `smtp_port`, `smtp_security`, `smtp_from`, `smtp_from_name` | role defaults (`""`, `587`, `starttls`, `""`, `Vaultwarden`) | `smtp_from` is required with `smtp_host` (the role's assertion) |
| `smtp_auth_mechanism` | `Plain` | the template's `default('Plain')` |
| `smtp_accept_invalid_certs`, `smtp_accept_invalid_hostnames` | `false` | |
| `smtp_debug` | `None` | `None` is the role's undefined variable: no `SMTP_DEBUG` line, and config.json's `smtp_debug` is left alone |
| `experimental_client_feature_flags`, `sends_allowed`, `emergency_access_allowed`, `icon_service`, `log_level` | role defaults | |
| `traefik_enabled`, `traefik_entrypoint`, `traefik_certresolver` | `true`, `websecure`, `""` | an empty resolver renders `tls: {}` |
| `healthcheck_enabled`, `healthcheck_timeout` | `true`, `30` | `GET /alive`, `timeout / 5` tries 5 s apart |

`service_name`, `user` and `site_path` are fixed by the packages
(`vaultwarden`, `/var/lib/vaultwarden`). `.env` values must be single lines.

Not ported, as the playbook uses none of them: package version pins
(`vaultwarden_package_version`, `vaultwarden_web_vault_package_version`) and
the apt hold (`vaultwarden_packages_hold`): the deploy installs whatever the
repository offers when a package is missing, never upgrades, and never
touches an existing hold. `vaultwarden_debian_codename` is always the host's
release, `vaultwarden_service_enabled`/`_state` are always enabled/started,
and the Molecule helpers (`vaultwarden_skip_*`) do not exist.

## What the deploy does

1. Checks the secrets and renders `/etc/vaultwarden.env`; reads the host's
   release (`/etc/os-release`): `bullseye`, `bookworm`, `trixie`, `jammy` or
   `noble`, the Ubuntu ones using the `bookworm` suite (the role's
   validation). Anything else fails before any operation.
2. Port preflight (read-only, the playbook's `bind: loopback`): a TCP
   listener on the Rocket port at a loopback or wildcard address, or at the
   configured `rocket_address` (any address when that is `0.0.0.0`), fails
   the deploy unless every process behind it runs in `vaultwarden.service`.
3. `apt-transport-https`, `ca-certificates`, `curl` and `gnupg` (cache
   refreshed when older than an hour); `/etc/apt/keyrings` `0755`; the
   signing key `vaultwarden-deb-repo-keyring.gpg` downloaded once (an
   existing key is kept, its mode set to `0644`, as `get_url` without
   `force`); `/etc/apt/sources.list.d/vaultwarden.list` with the line
   `apt_repository` writes (`root:root 0644`); `apt-get update` only when the
   key or the list changed.
4. `vaultwarden` and `vaultwarden-web-vault` installed when missing; a
   read-only step then requires an installed version for each and prints
   them (the role's "Report installed package versions").
5. `/var/lib/vaultwarden/data` and `/var/log/vaultwarden`,
   `vaultwarden:vaultwarden 0750`.
6. `/etc/vaultwarden.env`, `root:vaultwarden 0640`, through `secret_file`.
7. With `smtp_host` set and `data/config.json` present (the admin panel saved
   settings, which then override the environment): the role's SMTP settings
   (`smtp_host`, `smtp_port` as a number, `smtp_security`, `smtp_from`,
   `smtp_from_name`, the two `accept_invalid` flags as booleans, and
   `smtp_debug` when set) merged into it **on the host** by
   `files/smtp_config_sync.py` (stdin request, `python3 -I`). A read-only
   check while planning compares every setting by value and JSON type and
   the file's `vaultwarden:vaultwarden 0600`; only a difference runs the
   merge. Every other key is kept. A rewrite writes the merged object as
   Ansible's `to_nice_json` does (sorted keys, indent 4, ASCII escapes, no
   final newline) to a temporary file renamed over `config.json`; an owner
   or mode difference alone is fixed in place. The file (which holds the
   admin token once the panel saved it) never leaves the host and is never
   printed. A symlink, another file type (a FIFO is opened without waiting
   for a writer), invalid JSON or a JSON value that is not an object fail
   the deploy.
8. `/etc/systemd/system/vaultwarden.service.d/override.conf` (`0644`) with
   the role's hardening.
9. The Traefik route `/etc/traefik/dynamic/vaultwarden.yml` (`0644`), when
   `traefik_enabled`.
10. `service_rollout` of `vaultwarden.service`: systemd reloaded when the
    drop-in changed; enabled and started; restarted when a package was
    installed or the env file, config.json or drop-in changed (not right
    after this run started it).
11. The health check, when enabled.

A config.json check that fails (rather than answering) does not stop
planning: the merge runs, and the check runs again as a read-only operation
that fails the deploy unless it then answers `current`.

## Parity with the role and playbook

`tests/test_vaultwarden_parity.py` renders the vendored role templates
(`tests/parity/ansible/vaultwarden_deploy__*`, checked against ops-library
main `540ede2b`, 2.56.0) the way Ansible does and requires **byte-identical**
`/etc/vaultwarden.env`, drop-in and route; the templates the deploy ships are
the same files. With `OPS_LIBRARY_PATH` it also compares the defaults, the
paths, owners and modes, the packages, the repository line and the
config.json settings with the role's tasks.
`tests/test_vaultwarden_smtp_sync.py` runs the config.json script as the
deploy does. `tests/parity/ops_library_roles.json` records
`vaultwarden_deploy`.

Differences:

- Traefik is never restarted (the role's handler restarts it after a route
  change; its file provider watches the directory). systemd is reloaded only
  for a changed drop-in, and Vaultwarden is restarted after the files are
  written, before the health check (the role's handlers run after it).
- config.json is compared by meaning: a file whose settings already match
  but whose layout is not `to_nice_json`'s (the admin panel writes its own)
  is left alone, where the role rewrites it and restarts Vaultwarden.
- The apt cache is refreshed when older than an hour, not on every run.
- `vaultwarden.list` is kept `root:root 0644`; `apt_repository` sets the mode
  only when it creates the file.
- No pins and no hold (above). A missing `python3` on the host fails the
  config.json step (the role's Ansible needs it anyway).
