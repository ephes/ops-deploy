# compose_app

One deploy for the Docker Compose apps: a compose file rendered from a typed
model, a `Type=oneshot` unit that runs `docker compose up -d`, env files with
secret and host values, images pinned by digest, a Traefik route, typed API
steps and read-only checks. Each app is a `ComposeAppConfig` (data only); the
step code never branches on the app. torrent (gluetun, qBittorrent, Jackett)
is the first consumer; the *arr apps follow (see the worked example below).
logyard and the graphyard runtime keep their byte-parity modules.

```python
from ops_deploy.services.compose_app import ComposeAppConfig, deploy_compose_app

cfg = ComposeAppConfig.model_validate(spec)  # ops-control builds the mapping
deploy_compose_app(cfg, store.load(cfg.secrets))
```

The operations are named `Deploy <service_name> | ...`. ops-control builds
the config from an `AppSpec` (`pyinfra_support/compose_apps.py`, see its
`docs/PYINFRA.md`). The design is ops-meta
`specs/pyinfra-port/COMPOSE-APP.md` (owner decisions of 2026-10-17).

## The model

| Part | What it is |
|---|---|
| `service_name`, `title`, `unit`, `project`, `site_path`, `compose_file` | names: the unit (default `service_name` with `-` for `_`), the Compose project (also the container name prefix `<project>-<service>-1`), the directory of the compose and env files |
| `user`, `users`, `groups` | system users (nologin; an existing user only gets missing supplementary groups appended) and groups (`media`) |
| `mounts_required`, `paths_required` | `findmnt --mountpoint` and `test -e` before any change (`paths_required` with a hint), and `RequiresMountsFor=` in the unit |
| `directories` | owner and group both by name or both by numeric id (a container's user without a name here), mode with setgid (`"2775"`) |
| `external_networks` | created when missing, never removed |
| `env_files` | `<site_path>/<name>`, one `KEY='value'` line per entry, read by the services that list it |
| `config_files` | YAML or JSON from data with `Secret` leaves (YAML also `{"env_var": "NAME"}` leaves, written as `!env_var NAME` for apps that read a value from their environment, such as Recyclarr); `restarts` names the services that read it, never a namespace provider (restarting it would replace the namespace under running dependents) |
| `services` | `ComposeService`: the keys the apps on the fleet use, nothing passed through (below) |
| `docker` | Docker Engine and Compose, as the `docker_install` role installs them (run inside the deploy) |
| `route` | `/etc/traefik/dynamic/<name>.yml`: `internal`, `internal_or_basic_auth` or `public` |
| `steps` | typed API steps: `qbittorrent_preferences`, `json_key_copy` |
| `checks` | the wait for running and healthy services, `http` checks |
| `legacy_dirs`, `legacy_files` | old paths: empty directories are removed after a successful run (a non-empty one is kept and reported); files are removed before the apply |

`ComposeService` offers `image`, `container_name`, `command`, `entrypoint`,
`user`, `profiles`, `network_mode` (`host` with a `host_network_reason`, or
`service:<name>`), `networks`, `ports` (`PublishedPort`: loopback unless an
`exposure_reason` says why not), `env_files`, `environment` (literals only),
`binds`, `cap_add` (`NET_ADMIN`, `SYS_ADMIN`), `devices` (`/dev/net/tun`),
`sysctls`, `shm_size`, `mem_limit`, `cpus`, `pids_limit`, `restart`,
`depends_on` and `healthcheck`. Unknown keys fail. There is no `privileged`
and no `build`. Validation also refuses: a bind source that is not a declared
directory, config file or the site directory (or below a declared directory
or required path); a `service:X` that is not a service of the app; a
namespace provider without a healthcheck; ports on a service that joins
another's namespace; a route port the app does not publish.

### Values

| Value | Meaning | Resolved |
|---|---|---|
| `"text"` | literal | controller |
| `Secret(secret=key)` | a key of the app's decrypted secrets; `form="int"` (digits, a number in JSON) or `form="first_ipv4"` (the first IPv4 entry of a comma-separated address list, the WireGuard `Address =` line) | controller, in memory |
| `HostId(user=...)`, `HostId(group=...)` | a uid or gid on the target (`PUID`, `PGID`); never configured by hand | host |
| `HostSecret(host_secret=path, bytes=24)` | a secret created once on the host (`secrets.token_urlsafe`, root `0600`); an existing file is adopted unchanged; never sent to the controller | host |

A tuple of values is their concatenation (a JSON value that carries a host
secret). `required_secret_keys` lists every `Secret` key of the config.

## The canonical file set

| File | Owner, mode | Content |
|---|---|---|
| `<site_path>/compose.yml` | root, `0644` | `# Managed by ...`, then `name: <project>` and the services in a fixed key order (`yaml.safe_dump`); every `$` doubled (the model's values are literal); binds in long syntax with `bind.create_host_path: false`, so a missing or unmounted source fails instead of becoming an empty directory; `env_file` with absolute paths |
| `<site_path>/<env file>` | root, its `mode` | `# Managed by ...`, then `KEY='value'` per entry |
| config files | their owner and mode | YAML (with the header comment) or JSON |
| `/etc/systemd/system/<unit>.service` | root, `0644` | below |
| `/etc/traefik/dynamic/<route>.yml` | root, `0644` | the shared helper's route (`-int`/`-ext` or `-secure`, headers, gzip) without its `-http` router: nothing listens for the app on the HTTP entrypoint |

The unit:

```ini
[Unit]
Description=<title> (Docker Compose project <project>)
Requires=docker.service
After=docker.service network-online.target
Wants=network-online.target
RequiresMountsFor=<mounts_required>

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=<site_path>
ExecStart=/usr/bin/docker compose -p <project> -f <compose file> up -d --remove-orphans
ExecReload=/usr/bin/docker compose -p <project> -f <compose file> up -d --remove-orphans
ExecStop=/usr/bin/docker compose -p <project> -f <compose file> down|stop
TimeoutStartSec=300
```

Env values are refused (the error names the key, never the value) when they
contain `'`, a backslash (Compose lets it escape the closing quote, and its
parse error then prints the value), a line break or NUL, or leading or
trailing whitespace. Compose reads single-quoted values literally (no `${}`
interpolation). An env file with a `HostSecret` or a `HostId` is completed on
the host (`files/compose_host.py`, `python3 -I`, the template with its secrets
on stdin), atomically, without following symlinks; the others go through
`secret_file`.

## Images: pinned by digest

An image is `repo[:tag]@sha256:<digest>`: the tag is for people, the digest
makes it immutable. Floating or tag-only references are refused. In ops-control the pins of an app
live in a module-level literal dict `<APP>_IMAGES = {"<service>": "repo:tag@sha256:..."}`
(`pyinfra_support/*.py`), so the software inventory can find them with `ast`
without importing the module. A pinned
image that is missing on the host is pulled (`docker pull`) before the apply,
so the downtime is the recreation, not the download; converged runs never
pull and nothing updates by itself. An update is a reviewed bump of the pin.
Old images stay; pruning belongs to the host-level cleanup timer. An `update:
track` policy (floating tags, pulled every run) is designed but not built;
it is never allowed for leak-relevant images (gluetun, qBittorrent).

## What a run owes (the applied stamp)

Every decision is made while planning, from read-only probes, so a converged
host gets no mutating operation and `just pyinfra-check` shows what a deploy
would do. `/var/lib/ops-deploy/<service_name>/` (`root:root 0700`) holds:

- `applied.json` (`0600`): the fingerprint of the last successful apply: the
  digest of the compose file and of every env and config file (host values
  symbolic), a digest per service (its compose mapping and the env files it
  reads), the image pins, and the uid/gid values the env files were
  completed with, resolved on the host when the stamp is written;
- `pending`: written before a run changes any input, removed with the stamp.

| Situation (while planning) | What the run does |
|---|---|
| stamp current, files on the host as rendered, every service running on its pinned image, unit active, nothing pending | nothing |
| only the unit file differs, or systemd reports `NeedDaemonReload=yes` | write it, `daemon-reload`; no container is touched |
| the stamp differs, a file on the host differs (a hand edit), `pending` is left, a service is missing, stopped or on another image, an image is missing, an orphan container exists, a legacy file exists, or the unit is not active | the apply (below) |
| a config file with `restarts` differs from the stamp or on the host (or `pending`) | after the apply, `docker compose restart <readers>` (Compose does not see a change in a mounted file) |

The apply: mark `pending`, remove legacy files, write the compose, env and
config files, pull missing images, write the unit (`daemon-reload` if
needed), then `systemctl reload <unit>` (`up -d --remove-orphans`: Compose
recreates exactly the services whose configuration or image changed), or
`systemctl start` when the unit is not active. After the route, the API
steps and the checks have succeeded, the stamp is written and `pending`
removed. A run that stops anywhere before that (a failed `up`, a killed
deploy) leaves `pending`, and the next run applies again, restarts the
readers of every config file and treats every namespace provider as
replaced; a revert to the last stamped inputs is applied the same way. A
routine deploy never runs `systemctl restart` (`down` + `up`).

**Namespace providers.** When a service that others join with `network_mode:
service:X` may be recreated (its mapping, its env files, its image, a hand
edit, `pending`, a stopped container or an inactive unit), its dependents
are stopped first: `docker compose stop <dependents>`, then the reload. The
dependents are rendered with `depends_on: {X: {condition: service_healthy,
restart: true}}`, so Compose starts them again only once X is healthy. If X
never becomes healthy, `up` fails, the dependents stay stopped (they never
run outside the new namespace), the deploy fails and `pending` stays.

## Route

Built on `helpers.traefik_route` with `restart="none"`: the file provider
watches the directory, so Traefik is never restarted. The bcrypt hash is
computed on the controller and reused while it still verifies against the
password, so a converged run does not rewrite the file.

The helper's `-http` router is left out: no router serves the app on the
HTTP entrypoint (the static config redirects that entrypoint to HTTPS).

| `access` | Routers | Needs |
|---|---|---|
| `internal` | `<name>-int`: `Host && ClientIP(internal ranges)` | – |
| `internal_or_basic_auth` | `<name>-int` (priority 120, no auth) and `<name>-ext` (priority 100, Basic Auth) | `basic_auth_user`, `basic_auth_password` (`Secret`) |
| `public` | `<name>-secure` | `public_reason` |

## API steps

Data only; a new need is a new public kind, never a hook. Each kind is a
host-side script with a read-only `probe` (run while planning) and an
`apply`; it prints `changed`, `noop` or the drifting key names, never a value
or a response body, and gets its secrets on stdin.

- `qbittorrent_preferences`: the WebUI (`Host: localhost`) on a loopback port.
  The login succeeds with 204 (qBittorrent 5.2+) or 200 `Ok.`; when the
  desired credentials fail, the temporary password from `docker compose logs
  --tail=500 <service>` logs in as `admin` and sets them. The preferences
  are compared as a subset (strings without a trailing slash), set when they
  differ, and compared again; a remaining difference fails with the key
  names. The probe lists drift (`credentials` when the login fails); after a
  run that recreated the containers the apply runs (it prints `noop` when
  nothing had to change).
- `json_key_copy`: waits (`wait_seconds`) until a JSON file an app generates
  holds one of `keys`, then writes `dest`: `template` with every `"{value}"`
  string replaced by it, as JSON with a 4-space indent (torrent: Jackett's
  API key into qBittorrent's `jackett.json`).
- `http_json_settings` and `http_json_items`: an app's JSON API on a loopback
  port it publishes (`port`, `prefix`, `path`), authenticated by a header
  (`auth`: `X-Api-Key` by default) whose value is a `Secret` or a
  `HostSecret` (read on the host from its file, reached without following
  symlinks; a missing file fails the step, it is never created here).
  Values compare exactly; `path_keys` (Servarr root folder `path`) ignore one
  trailing slash. Values in `desired`/`items` are literals,
  `{"secret": ...}` or `{"host_secret": "<path>"}` (another app's API key).
  - `http_json_settings`: one object, `GET <path>` and `PUT <path>/<id>` with
    the `desired` subset merged in (Servarr `/api/v3/config/host`, `naming`,
    `mediamanagement`).
  - `http_json_items`: every listed item of `GET <path>` exists, matched by
    `match` (`name`, or `path` for root folders): `POST <path>` when missing,
    starting from the `schema` entry whose `key` (`implementation`) equals the
    item's; `PUT <path>/<id>` when it differs. Items that are not listed are
    never changed or deleted. Servarr shapes: `fields` is a mapping written
    into the API's `[{"name", "value"}]` list; `tags` given as labels become
    ids through `tags_path` (missing tags are created there);
    `force_save: true` adds `?forceSave=true` (no connection test on save).
  - `write_only` (`password`, `fields.apiKey`): values the API masks on reads.
    They are not compared; a sha256 of their desired values is kept in
    `/var/lib/ops-deploy/<service>/http_json.json` (root 0600, never the
    values), and a new or changed digest is drift, so the next write sends
    them. A masked value sent back unchanged keeps the stored one.
  - The probe reads only (it creates no tags) and prints `current` or the
    drifting `<item>:<key>` names; the apply verifies with a second read.
    Errors name the method, path and status code, never a value or body.

## Checks

Read-only operations (they do not count as changes):

- the port preflight, before any change: every published host port is free
  or published by a container of this project (`docker ps` ports); anything
  else stops the run and names the port and the process holding it;
- every service without a profile runs, and is healthy if it has a
  healthcheck (polled up to `checks.timeout` seconds);
- every `service:X` container shares X's network namespace
  (`HostConfig.NetworkMode == container:<id of X>`);
- every published TCP port listens on its address only (`ss`);
- `checks.http`.

## Echoport backup target

`echoport` registers one Echoport target (`generic_paths`) for the app. It
is the last step of a run, after the stamp: Echoport must already run on the
host, or the run fails with a message. The upsert script is shared with the
other services (`services/_echoport`): a check-mode probe first, an apply
only when it does not say `unchanged`.

```python
"echoport": {
    "name": "radarr",
    "description": "Radarr database, config.xml and API key",
    "db_path": "/mnt/cryptdata/media-apps/radarr/radarr.db",
    "backup_files": (
        "/mnt/cryptdata/media-apps/radarr/config.xml",
        "/mnt/cryptdata/media-apps/secrets/radarr-apikey",
    ),
    "restore_owner": "radarr:media",
    "schedule": "15 3 * * *",
},
```

| Key | Meaning |
| --- | --- |
| `name`, `description`, `icon` | the target in Echoport's UI (`icon` defaults to `archive`) |
| `db_path` | a SQLite database, copied with SQLite's online backup |
| `backup_files` | files or whole directories, copied as they are |
| `service_name` | the unit Echoport stops around a restore; default: the app's unit |
| `restore_owner` | `user:group` every restored path is chowned to; default: the app's user and its primary group |
| `schedule` | cron schedule of a new target |
| `update_schedule` | `true`: every deploy sets the schedule; default `false`: a schedule changed in the Echoport UI is kept |

Checked before any operation: at least one path; every path below
`/home/`, `/opt/`, `/var/lib/` or `/mnt/cryptdata/` (Echoport's default
prefixes); every path a declared directory of the app, below one, or one of
the app's `HostSecret` files; no path inside another (a directory around the
database would copy it raw and restore it over the snapshot), and none of
the database's `-wal`/`-shm`/`-journal` files; basenames all different and
none `manifest.json` (the archive is flat and keeps its manifest beside them).

**Consistency while the app runs.** Backups never stop the app. The
database is a consistent snapshot (SQLite's backup API, WAL included). Files
and directories are copied one by one: each file is whole if the app writes
it atomically (replace by rename, as qBittorrent does for its resume data),
but files written at different times may be minutes apart. A file that
disappears during the copy (a torrent removed at that moment) fails that
backup run; the next scheduled run tries again. Only list what the deploy
cannot rebuild.

**Restore.** Echoport stops `service_name`, verifies the archive's checksum,
puts the database and every listed path back (a directory replaces the
current one), removes stale `-wal`/`-shm` files, chowns everything to
`restore_owner` and starts the unit again. `HostSecret` files therefore come
back owned by `restore_owner`; the next deploy sets them to root `0600`
again ("Set host secrets back to root 0600": listed ones and those inside a
listed directory, each opened without following symlinks and changed through
its descriptor; a missing one is left alone). Run the deploy once after a
restore; it also re-applies settings the API steps own.

`remove_compose_app` leaves the target and its backups in Echoport.

## Remove

`remove_compose_app(ComposeAppRemoveConfig(app=cfg, confirm=True))` stops and
disables the unit, runs `docker compose down --remove-orphans` (or removes
the project's containers when the compose file is gone), and deletes the
unit, the route, the env, config and compose files and the state directory.
Directories, data, host secrets, images and external networks stay.

## torrent: the switch from the playbook

ops-control's `playbooks/torrent/deploy.yml` wrote these files; compose_app
writes each once in its canonical form (Q1). The containers are recreated
once each, in the namespace-provider order; behaviour is proven equal, not
the bytes: the same project, container names and unit; the same environment
per container (compared through `docker inspect`); the same binds, ports,
network modes, capabilities, devices and sysctls; the same route host and
access; the same qBittorrent preferences.

| File | Playbook | compose_app | Why |
|---|---|---|---|
| `compose.yml` | inline Jinja, short bind syntax, `./gluetun`, floating tags (`gluetun:v3`, lscr `:latest`), `depends_on` healthy | the structured render: long binds with `create_host_path: false`, absolute paths, the tags pinned to the digests the containers ran (`tag@sha256`), `depends_on` healthy with `restart: true`, a header | a missing mount fails instead of filling the root disk; no image changes without a reviewed pin; dependents restart with gluetun |
| `gluetun.env`, `apps.env` | unquoted `KEY=value`, an "ansible" header | `KEY='value'`, the compose_app header; the same keys and values | literal values (no `${}` or ` #` surprises) |
| `torrent.service` | no `ExecReload`, `TimeoutStartSec=0` | `ExecReload`, `TimeoutStartSec=300`, `RequiresMountsFor=/mnt/cryptdata`, the title with Jackett | a change recreates only the services that changed; the stack waits for the encrypted volume |
| `/etc/traefik/dynamic/torrent.yml` | `torrent-internal`/`torrent-external`, the hash re-salted on every run and Traefik restarted | the helper route: `torrent-int`/`torrent-ext` (no HTTP router, as before), security headers and gzip, the hash reused while it verifies, no Traefik restart | no rewrite and no restart on converged runs |

Also different: images are pulled only when a pin is missing (the playbook
pulled `latest` on every run and restarted on a new image); the gluetun
control key at `/home/torrent/site/gluetun-control-apikey` is adopted as a
`HostSecret`, unchanged.

## Worked example: an *arr app (for session arr, P3)

One compose project and one unit per app (Q11), all on the external network
`media`; config under `/mnt/cryptdata/media-apps/<app>`, the media tree at
the same path inside and outside; `PUID` the app's user, `PGID` the shared
`media` group, `UMASK=002`; the UI on loopback with an `internal` route; the
API key a `HostSecret` given to the app through its env file (Servarr reads
`<APP>__AUTH__APIKEY` and `<APP>__AUTH__METHOD` from the environment).

```python
RADARR = {
    "title": "Radarr",
    "project": "radarr",
    "user": "radarr",
    "site_path": "/home/radarr/site",
    "groups": ("media",),
    "users": ({"name": "radarr", "groups": ("media",), "home": "/home/radarr"},),
    "mounts_required": ("/mnt/cryptdata",),
    "paths_required": ({"path": "/mnt/cryptdata/media", "hint": "run just deploy-one media_storage first"},),
    "directories": (
        {"path": "/mnt/cryptdata/media-apps/radarr", "owner": "radarr", "group": "media", "mode": "2775"},
        {"path": "/mnt/cryptdata/media-apps/radarr/secrets", "mode": "0700"},
        {"path": "/home/radarr/site", "mode": "0755"},
    ),
    "external_networks": ("media",),
    "env_files": (
        {
            "name": "radarr.env",
            "mode": "0600",
            "entries": (
                {"key": "TZ", "value": "Europe/Berlin"},
                {"key": "PUID", "value": {"user": "radarr"}},
                {"key": "PGID", "value": {"group": "media"}},
                {"key": "UMASK", "value": "002"},
                {"key": "RADARR__AUTH__METHOD", "value": "Forms"},
                {
                    "key": "RADARR__AUTH__APIKEY",
                    "value": {"host_secret": "/mnt/cryptdata/media-apps/radarr/secrets/apikey"},
                },
            ),
        },
    ),
    "services": (
        {
            "name": "radarr",
            "image": "lscr.io/linuxserver/radarr:<version>@sha256:<digest>",
            "networks": ("media",),
            "ports": ({"published": 17878, "target": 7878},),
            "env_files": ("radarr.env",),
            "binds": (
                {"source": "/mnt/cryptdata/media-apps/radarr", "target": "/config"},
                {"source": "/mnt/cryptdata/media"},
            ),
            "healthcheck": {"test": ("CMD-SHELL", "curl -fsS http://127.0.0.1:7878/ping >/dev/null")},
        },
    ),
    "route": {"host": "radarr.home.example", "port": 17878, "access": "internal"},
    "checks": {"http": ({"url": "http://127.0.0.1:17878/ping"},)},
}
```

Sonarr and Prowlarr have the same shape (their own user, port, config
directory and `SONARR__`/`PROWLARR__` keys; Prowlarr needs no media bind).
Recyclarr runs as a service (its image schedules its own syncs, `CRON_SCHEDULE`);
its config file names the API keys as `{"env_var": "RADARR_API_KEY"}`
leaves (`!env_var` in YAML), and its env file carries them as the apps'
`HostSecret` files, so the config file holds no key.
qBittorrent is reached from the *arr containers at `gluetun:8080` once
gluetun joins the `media` network: that is the first P3 change to torrent's
`AppSpec` (`external_networks: ("media",)` and `networks: ("media",)` on
gluetun; one gluetun recreation, run the leak checklist after it).

Wiring the apps uses `http_json_settings` and `http_json_items` (root
folders, download clients, Prowlarr applications and indexer proxies). Each
app registers its backups with the `echoport` part ([above](#echoport-backup-target)):
the SQLite database, `config.xml` and its `HostSecret` API key. Not built yet:
`update: track`.
