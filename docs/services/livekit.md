# livekit

Port of the `livekit_deploy` Ansible role: the LiveKit SFU (`livekit-server`)
and LiveKit Egress (`livekit-egress`, server-side recording with headless
Chrome) as one Docker Compose project, run by [compose_app](compose_app.md),
plus the role's own Traefik route. Redis and the S3 bucket are external
services on the host; the deploy only points the config files at them.

```python
from ops_deploy.services.livekit import LivekitConfig, deploy_livekit

cfg = LivekitConfig(
    secrets=SecretRef("secrets/prod/livekit.yml"),
    server_image="livekit/livekit-server:v1.12.0@sha256:<digest>",
    egress_image="livekit/egress:v1.13.0@sha256:<digest>",
    node_ip="192.0.2.10",
    webhook_url="https://recorder.example.invalid/api/livekit/webhook",
    traefik_host="livekit.example.invalid",
)
deploy_livekit(cfg, secrets)
```

The operations are named `Deploy livekit | ...` (the Compose app) and
`Deploy livekit route | ...` (the route).

## Inputs

| Field | Default | Role variable |
|---|---|---|
| `server_image`, `egress_image` | required, `repo:tag@sha256:<digest>` | `livekit_server_image`/`_tag`, `livekit_egress_image`/`_tag` (tags only) |
| `node_ip` | required, IPv4 | `livekit_node_ip` (`rtc.node_ip`, the ICE candidate clients get) |
| `webhook_url` | required, http(s) | `livekit_webhook_url` |
| `traefik_host` | required; `None` writes no route | `livekit_traefik_host` (`livekit_traefik_enabled`) |
| `site_path`, `config_dir` | `/opt/livekit`, `/etc/livekit` | `livekit_site_dir`, `livekit_config_dir` |
| `http_port`, `rtc_tcp_port` | `7880`, `7881` | `livekit_http_port`, `livekit_rtc_tcp_port` |
| `rtc_port_range_start`, `rtc_port_range_end` | `50000`, `50100` (UDP) | the same names |
| `redis_address` | `127.0.0.1:6379` | fixed in the role's templates |
| `s3_endpoint`, `s3_bucket` | `http://127.0.0.1:9001`, `recorder` | `livekit_s3_endpoint`, `livekit_s3_bucket` |
| `healthcheck_timeout` | `60` (seconds of the HTTP check) | `livekit_healthcheck_timeout` |
| `project`, `title`, `service_name` | `livekit`, `LiveKit Stack`, `livekit` | the Compose project (the role's site directory name), the unit |

Secrets (`required_secret_keys`): `api_key`, `api_secret`, `redis_password`,
`s3_access_key`, `s3_secret_key`. Each must be set and not `CHANGEME`
(the role's asserts); the run stops, naming the key only, before any
operation. Unlike the role, an empty Redis password is refused instead of
leaving `redis.password` out.

Images are pinned by digest like every compose_app image: the consumer pins
the digests its containers run, so the switch from the role changes no image.

## What it writes

| File | Owner, mode | Content |
|---|---|---|
| `/opt/livekit/docker-compose.yml` | root `0644` | compose_app's render: project `livekit`, containers `livekit-server` and `livekit-egress`, `network_mode: host` (WebRTC media reaches the NIC; Redis and S3 listen on host loopback), Egress with `SYS_ADMIN` and `shm_size: 1g`, each config file bind-mounted read-only (long syntax, `create_host_path: false`), `restart: unless-stopped`, no published ports |
| `/etc/livekit/livekit.yaml` | root `0600` | the role's values: `port`, `rtc` (TCP port, UDP range, `use_external_ip: false`, `node_ip`), `redis`, `keys: {<api_key>: <api_secret>}` (a `SecretKeyed` mapping), `webhook`, `logging` |
| `/etc/livekit/egress.yaml` | root `0640` | the role's values: `redis`, `api_key`, `api_secret`, `ws_url`, `s3` (region `us-east-1`, `force_path_style`), `logging`; the Egress image's user has primary group root (gid 0), so group read is enough |
| `/etc/systemd/system/livekit.service` | root `0644` | compose_app's unit (`ExecReload` = `up -d --remove-orphans`, `-p livekit`) |
| `/etc/traefik/dynamic/livekit.yml` | root `0644` | the role's template byte for byte (header included): router `livekit` on `web-secure` with `tls: {}`, middleware `livekit-headers` (`X-Forwarded-Proto: https`, `X-Forwarded-Host`), service `livekit` at `http://127.0.0.1:<http_port>` |
| `/var/lib/ops-deploy/livekit/` | root `0700` | compose_app's applied stamp |

The route is open to every client, as the role's is (no `ClientIP` rule):
LiveKit authenticates every connection with a token signed by the API secret.
Traefik is never restarted; its file provider watches the directory.

## Restarts and recreations

Every decision comes from the applied stamp and read-only probes
([compose_app](compose_app.md#what-a-run-owes-the-applied-stamp)):

| Situation | What the run does |
|---|---|
| nothing changed (files, stamp, both containers running on their pins) | nothing; no container command at all |
| `livekit.yaml` changed (webhook, node IP, ports) | rewrite, `systemctl reload livekit`, `docker compose restart livekit-server` |
| `egress.yaml` changed (bucket, endpoint, S3 keys) | rewrite, reload, `docker compose restart livekit-egress` |
| a key both read (API key or secret, Redis password) | both files, reload, restart both |
| an image pin changed | rewrite the compose file, pull the pin, reload: Compose recreates that container; no restart |
| a stopped container | reload (`up -d` starts it) |
| only the route differs | rewrite the route; no container is touched |

The role restarted the whole unit (`down` + `up`, both containers) on any
change to a config file, the compose file or the unit, and restarted Traefik
when the route changed. The port never runs `systemctl restart`, and an
unchanged config never recreates or restarts a container (tests:
`tests/test_livekit.py`). A restart or recreation of `livekit-server` ends
running calls; one of `livekit-egress` ends running recordings.

## The switch from the role

Running the port over a role-deployed host (no stamp yet) applies once: it
writes the compose file, both config files and the unit, reloads systemd,
`systemctl reload livekit` recreates both containers (the compose file
changed: digest pins, long bind syntax, `name:`), then restarts both readers
of the rewritten config files. No image is pulled when the pins are the
running images, and the route is unchanged. `egress.yaml` goes to `0640` if
an older role run left it `0644`. The next run changes nothing.

Differences from the role's files (`tests/test_livekit_parity.py`):

| File | Role | Port |
|---|---|---|
| compose file | short bind syntax, tags, `shm_size: "1gb"`, no `name:` | long binds with `create_host_path: false`, `tag@sha256` pins, `1g` (the same 1 GiB), `name: livekit` |
| config files | Jinja templates, values in double quotes | YAML from data (the same values; quoted where YAML needs it), compose_app's header |
| unit | no `ExecReload`, `TimeoutStartSec=0`, no `-p` | `ExecReload`, `TimeoutStartSec=300`, `-p livekit`, the title with the project |
| route | the template | the same bytes |

Not ported: the role's TCP wait before the HTTP check (compose_app waits for
both containers to run, then polls `GET http://127.0.0.1:<http_port>/` for
200 up to `healthcheck_timeout` seconds). There is no remove (the role has
none).
