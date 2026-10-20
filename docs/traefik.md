# Traefik

`ops_deploy.infra` also ports the base Traefik roles of ops-library:
`traefik_deploy` (full deploy only), `traefik_backup`, `traefik_restore` and
`traefik_remove`. Like the other infra deploys each is a frozen, strict config
plus a `@deploy` function outside the size-capped helpers/ops/core layer. None
of them takes a secret. Per-service routes stay with
[`traefik_route`](concepts/helpers.md).

```python
from ops_deploy.infra import (
    FileCertificate,
    TraefikDeployConfig,
    TraefikRemoveConfig,
    deploy_traefik,
    deploy_traefik_backup,
    deploy_traefik_remove,
    deploy_traefik_restore,
)

deploy_traefik(
    TraefikDeployConfig(
        version="3.7.14",
        checksum="sha256:d08641f5...",
        letsencrypt_email="ops@example.org",
        file_certificates=(
            FileCertificate(
                cert_file="/etc/letsencrypt/live/x/fullchain.pem", key_file="/etc/letsencrypt/live/x/privkey.pem"
            ),
        ),
    )
)
deploy_traefik_remove(TraefikRemoveConfig(confirm=True))
```

## Transaction-managed hosts are refused

Hosts enrolled in the guarded Traefik transaction workflow
(`roles/traefik_deploy/TRANSACTIONS.md` in ops-library) take binary and
static-config changes only through that workflow. The role's `guard.yml`
refuses full deploy, restore and removal there, and so do these deploys:
with `transaction_required` set, or when `/var/lib/traefik-transactions`
exists on the host, `deploy_traefik`, `deploy_traefik_restore` and
`deploy_traefik_remove` stop while planning, before any change. Backup only
reads and is allowed everywhere. The transaction, prepare and health-probe
entries of the role are not ported.

## Nothing unchecked goes live

Traefik fronts every service on a host; a static config it cannot read takes
all routes down at the next restart. So:

- the rendered static config is parsed as TOML on the controller, and must
  have `[entryPoints]`, `[providers]` and `[certificatesResolvers]`, before
  any operation is added; a config that fails stops the deploy with nothing
  written and nothing restarted (`tests/test_infra_traefik.py`);
- the config itself refuses entrypoints sharing a port and an unbracketed
  IPv6 metrics address, which Traefik cannot listen on;
- the file-provider certificate list is parsed as YAML the same way, and every
  certificate and key file must exist on the host. Traefik watches the dynamic
  directory and loads the list as soon as it is written;
- a newly installed binary must report the wanted version before the restart;
  if it does not, the deploy fails before restarting;
- Traefik restarts only when the static config, certificate list, unit or
  binary changed, and only if it was running (a stopped Traefik is started
  with the new files). The run ends with read-only checks: port `http_port`
  open, unit active.

## Coexistence with the roles

`traefik.toml`, `traefik.service`, `dynamic/certificates.yml` and
`/etc/logrotate.d/traefik` are byte-identical to the role's
(`tests/test_infra_traefik.py` renders the vendored templates, the log
rotation one included).

The log rotation has two blocks, as in the role (2.39.2): `traefik.log` is
rotated with `copytruncate` (Traefik never reopens its own log; lines written
between the copy and the truncate are lost), `access.log` is renamed and
Traefik is sent `SIGUSR1` in `postrotate` (only if `traefik.service` is
active) so it reopens the file. The unit has no `ExecReload`, so the former
`systemctl reload traefik || true` never worked: Traefik kept writing to the
renamed `access.log.1` and the fresh `access.log` stayed empty. The binary is only replaced when its version differs, as in the role,
and UFW rules are the ones `community.general.ufw` adds. A host set up by one
tool shows no change and no restart when the other runs; ops-control's
`just smoke-traefik-coexistence` checks this both ways, and that each tool
restores the other's ACME backup payload and finishes the other's removal.
That historical smoke does not establish dynamic-route recovery.

## deploy_traefik

`deploy_traefik(cfg)`

| Field | Default | |
|---|---|---|
| `version` | `"3.7.13"` | the role's default |
| `checksum` | required | `sha256:<hex>` of the release archive; the role allows none |
| `arch` | `None` | `None`: from `uname -m` (`x86_64`, `aarch64`, `armv7l`, `armv6l`) |
| `letsencrypt_email` | required | the role refuses its `CHANGEME@` placeholder; here a plain address is required |
| `config_dir`, `log_dir`, `binary_path` | `/etc/traefik`, `/var/log/traefik`, `/usr/local/bin/traefik` | |
| `dynamic_dir`, `acme_dir`, `static_config`, `acme_storage` | `None` | `None`: below `config_dir` as in the role |
| `file_certificates` | `()` | `FileCertificate(cert_file, key_file)`; `certificates.yml` is written only when set |
| `log_level`, `log_format` | `INFO`, `json` | |
| `dashboard_enabled`, `dashboard_port`, `dashboard_firewall_open` | `True`, `8090`, `False` | |
| `http_port`, `https_port`, `http_redirect_to_https` | `80`, `443`, `True` | |
| `metrics_enabled`, `metrics_bind_address`, `metrics_port` | `True`, `127.0.0.1`, `8080` | the bind is used only without the dashboard |
| `force_update` | `False` | reinstall the binary even at the wanted version |
| `configure_firewall` | `True` | UFW rules on Debian-family hosts with `ufw` |
| `logrotate_days` | `7` | |
| `mask_conflicting_web_services`, `conflicting_web_services` | `True`, nginx/apache2/caddy/lighttpd | |
| `transaction_required` | `False` | refuse the host (see above) |
| `alias_policy` | `{}` | entrypoint to `delete`; must cover every rendered entrypoint and needs 3.7.12+ (the role's assert) |

Steps: refuse transaction-managed hosts; render and validate; directories
(`acme` `0700`, the others `0755`, root); the release archive downloaded,
checked against `checksum` and the binary renamed into place when the
installed version differs (or `force_update`), then its version checked;
static config, certificate list and unit; `acme.json` created `0600` if
missing (never rewritten); log rotation; UFW `allow <port>/tcp` for HTTP and
HTTPS (and the dashboard when `dashboard_firewall_open`) when missing; installed
distro web servers among `conflicting_web_services` stopped, disabled, masked
and their failed state cleared; `daemon-reload` when the unit changed;
Traefik enabled and running; restart on change; read-only port and unit
checks.

Differences from the role, on purpose:

- A checksum is required, so nothing unverified is installed.
- Only the `traefik` binary is installed, renamed over the old one; the role
  unpacks the whole archive (including `LICENSE.md` and `CHANGELOG.md`) into
  the binary's directory.
- A replaced binary restarts Traefik; the role keeps the old process running
  until something else restarts it.
- Armv7/armv6 hosts get the `armv7`/`armv6` release (the role's `arm` has no
  release archive). Only Linux is supported.
- The static config and certificate list are validated before anything is
  written, and certificate files must exist on the host.

## deploy_traefik_backup

`deploy_traefik_backup(cfg)`; `TraefikBackupConfig` fields: `root`
(`/opt/backups/traefik`), `prefix` (`manual`), `dynamic_dir`
(`/etc/traefik/dynamic`), `include_dynamic` (`True`, matching ops-library
2.48.1), `acme_path`, `include_acme` (`False`), `create_archive` (`True`),
`fetch_local` (`True`) and `local_dir` (`None`: `~/backups/traefik`).

The default now captures the **whole dynamic directory**, including nested,
hidden and non-YAML files, into `dynamic/` regardless of the source directory's
basename or trailing slash. Entries below `dynamic/` keep their source
permissions; `dynamic/` itself is reset to `root:root 0700` after the copy (a
plain `cp -a` would give it the source directory's owner and mode), inside the
root-only `<root>/<prefix>-<timestamp>/` container. `metadata.yml` (`0600`) records the
timestamp, both configured sources and both inclusion flags in the role's
format. Optional ACME state is copied into `acme/` as `root:root 0600`.

The payload directory is the only top-level entry in
`<root>/<prefix>-<timestamp>.tar.gz` (`umask 077`). With `fetch_local`, the
controller directory is `0700` and the fetched archive is restricted to `0600`.
The controller directory itself must be a real, accessible directory: a symlink
(such as a link to an external volume) deliberately refuses with an explicit
error. Configure the real destination path instead. This fetch-phase refusal
can leave a completed remote backup; it does not mean the backup was fetched.
An existing linked or special archive destination also refuses before download;
the permission checks use no-follow file descriptors. Dynamic configs can
contain authentication hashes or credentials, so these protections apply even
when ACME is disabled. `include_acme` controls only the separate ACME payload;
all regular files within the selected dynamic tree are included.

With `include_dynamic=False` the tree is neither inspected nor copied. With
`create_archive=False`, only the remote payload directory is produced; nothing
is fetched. Missing enabled sources fail before any operation. Source and
backup roots cannot overlap or contain parent traversal, both as configured and
after resolving symlinks on the host (`realpath -m`, so an absent root under an
aliased ancestor is resolved too; this needs GNU coreutils, and an unresolvable
answer refuses). Link checks apply to the path with trailing `/` and `.`
components removed, so `link/` or `link/.` still counts as a link. The backup
root must be a real directory (or absent); an existing payload/archive attempt, including
a dangling link, refuses before writes rather than overwriting history. Use a trusted source
tree: unlike the role's recursive copy, this implementation refuses symlinks
and special entries rather than following them outside the chosen tree, and
rechecks the copied tree before allowing an archive. A failed copy never packs
or fetches the partial payload. No retention or pruning policy is added.

**Backup coverage does not qualify restoration.** Dynamic payloads are never
published by `deploy_traefik_restore`: it remains ACME-only, has no `dry_run`
option and still refuses transaction-managed hosts. Do not copy an archived
Native route into a watched directory; recovery needs the owning service's
reviewed canonical/quarantine workflow. No new private lifecycle registration,
deployment or positive restore/removal qualification is implied by this change.

## deploy_traefik_restore

`deploy_traefik_restore(cfg)`; `TraefikRestoreConfig` fields: `archive`
(`latest`, a name below `root` or an absolute path), `root`, `staging_dir`
(`/tmp/traefik-restore`), `acme_path`, `include_acme` (`False`) and
`transaction_required`.

`latest` picks the newest `*.tar.gz` in `root` by modification time. The
archive is unpacked into a fresh `staging_dir` (`0700`), its first top-level
directory is the payload, and with `include_acme` its `acme/acme.json` is put
back as `root:root 0600` (directory `0700`); `staging_dir` is removed. As in
the role, Traefik is not restarted. Without `include_acme` nothing is
restored.

## deploy_traefik_remove

`deploy_traefik_remove(cfg)`; `TraefikRemoveConfig` fields: `confirm`
(`False`; required), `preserve_certificates` and `preserve_dynamic_configs`
(`True`), `force_complete` (`False`; overrides both), `binary_path`,
`config_dir`, `log_dir`, `remove_firewall_rules` (`True`), `http_port`,
`https_port`, `dashboard_port` and `transaction_required`.

Steps: refuse transaction-managed hosts and unconfirmed runs; stop and
disable Traefik (failures ignored, as in the role); remove the unit file and
reload systemd; remove the binary and `traefik.toml`; the dynamic configs and
the ACME directory unless preserved; `config_dir` when nothing but hidden
entries is left in it (the role's `find` skips hidden entries; never `/etc`);
the log directory and log rotation; the UFW rules for the HTTP, HTTPS and
dashboard ports; every non-hidden `/tmp/traefik*` entry. Each step runs only
when there is something to remove, so a second run changes nothing.
