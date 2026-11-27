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
| `traefik_internal_ip_ranges` | `None` (everyone) | with ranges, the HTTP router also requires `ClientIP` in them |
| `turn_domain`, `turn_tls_port` | `None` (TURN off), `5349` | see "Media from outside the LAN" |
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
| `/etc/livekit/livekit.yaml` | root `0600` | the role's values: `port`, `rtc` (TCP port, UDP range, `use_external_ip: false`, `node_ip`), `redis`, `keys: {<api_key>: <api_secret>}` (a `SecretKeyed` mapping), `webhook`, `logging`; with `turn_domain` also `turn` |
| `/etc/livekit/egress.yaml` | root `0640` | the role's values: `redis`, `api_key`, `api_secret`, `ws_url`, `s3` (region `us-east-1`, `force_path_style`), `logging`; the Egress image's user has primary group root (gid 0), so group read is enough |
| `/etc/systemd/system/livekit.service` | root `0644` | compose_app's unit (`ExecReload` = `up -d --remove-orphans`, `-p livekit`) |
| `/etc/traefik/dynamic/livekit.yml` | root `0644` | the role's template byte for byte (header included): router `livekit` on `web-secure` with `tls: {}`, middleware `livekit-headers` (`X-Forwarded-Proto: https`, `X-Forwarded-Host`), service `livekit` at `http://127.0.0.1:<http_port>`; with `turn_domain` also the TCP router `livekit-turn` |
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

Differences from the role's files (`tests/test_livekit_golden.py` keeps the
port's files as they are on the host, against `tests/golden/livekit`):

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

## Per-container replacement CA store

`ca_store_root` optionally names an absolute host directory containing prepared
`<container-name>/bundle.pem` and `<container-name>/empty` stores. The
container retains its pinned application image and receives a read-only mount
at `/run/managed-ca`, with `SSL_CERT_FILE` and `SSL_CERT_DIR` pointing there.
Prepare from each image’s own trust material before deployment, verify the
specific runtime honors the overrides, and refresh preparation after image or
custom CA changes. The default is unset and preserves existing image behavior.
This option replaces default native trust paths; explicit application CA
overrides still require a separate audit.

Refreshing store files alone does not trigger compose change detection. Explicitly
restart/recreate affected containers to discard loaded trust contexts, then repeat
negative and positive TLS probes. The preparation role owns root:root 0755 for
the managed store root; LiveKit declares the same metadata for bind validation.

`egress_chrome_policy_path` optionally binds a prepared managed Chrome policy file read-only at `/etc/opt/chrome/policies/managed/99-emudhra.json` in Egress only. Use the collection `chrome_ca_distrust` role to prepare the policy; native SSL certificate environment settings do not affect Chrome Root Store. Recreate Egress after changing the single-file binding so it sees the new inode. The policy preserves other managed policies and does not touch browser profiles.

When replacement trust is enabled, preconditions require the prepared bundle, empty directory and manifest before any service changes. A missing store fails deployment; prepare the target image first rather than allowing Compose to create a missing source.

## Media from outside the LAN

A client reaches the media ports (`rtc_port_range_*` over UDP, `rtc_tcp_port`)
only where they are routed to it, and LiveKit advertises `node_ip` only.
Behind a home router that forwards 443 alone, that is the LAN. ICE over TCP
(`rtc_tcp_port`) cannot share 443: it is plain TCP without a server name.
TURN over TLS can, because Traefik routes it by SNI.

`turn_domain` switches on LiveKit's embedded TURN server for those clients:

- `livekit.yaml` gains `turn` with `enabled`, `domain: <turn_domain>`,
  `tls_port: <turn_tls_port>`, `external_tls: true`, no `udp_port` (TURN over
  UDP stays off). LiveKit then listens for plain TCP on `tls_port` (all
  addresses) and hands every participant `turns:<turn_domain>:443?transport=tcp`
  with its own short-lived credentials (port 443 is fixed in LiveKit).
- Peers: `allow_restricted_peer_cidrs: [<node_ip>/32]` lets a relay reach the
  SFU's own candidate (a private address is denied by default), and
  `deny_peer_cidrs` lists every other IPv4 address (the complement of
  `node_ip`, 32 networks) and `::/0`. The deny list takes precedence, so a
  relay can reach `node_ip` and nothing else.
- The route file gains a TCP router `livekit-turn` on `web-secure` with
  `HostSNI(<turn_domain>)` and `tls: {}`: Traefik terminates TLS with a
  certificate from its store that covers the name and forwards the stream to
  `127.0.0.1:<turn_tls_port>` with a PROXY protocol v2 header (TCP
  `serversTransports.livekit-turn`). HTTP routers for other names are
  untouched.
- `proxy_protocol: true`: LiveKit reads that header (trusted from loopback
  only, its default) and uses the client's address; without it TURN would
  report Traefik's `127.0.0.1` as the client's mapped address, which Firefox
  rejects. A connection to `turn_tls_port` without the header, or from
  anywhere but loopback, is closed; a process on the host itself could send
  a header, and still needs TURN credentials like any client.

**Needs livekit-server v1.13.10 or newer.** Older servers (v1.12.0 bundles
pion/turn v5.0.4) accept RFC 6062 TCP relays without a peer permission check,
so a holder of TURN credentials could open TCP connections to services on the
host's networks. v1.13.10 (upstream #4992) refuses every TCP relay and limits
relays to the host's own addresses to the media UDP ports. The deploy does
not read the image's version: the consumer's pin decides it.

`turn_domain` must be a dotted DNS name (LiveKit refuses others at start,
and TLS clients send no SNI for an IP), must differ from `traefik_host` (case
ignored) and needs it (the TCP router
lives in the same route file); `turn_tls_port` must differ from `http_port`
and `rtc_tcp_port`. Setting or changing either rewrites `livekit.yaml` and
restarts the server, which ends running calls. Without `turn_domain`
`livekit.yaml` and the route are byte for byte as before.
