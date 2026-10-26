# Metrics endpoints

`services.metrics_endpoint` deploys an authenticated mail health endpoint.
`services.torrent_vpn_metrics_endpoint` deploys an authenticated cached VPN
health endpoint and its root collector/timer. They preserve the existing
role templates and service identities. These modules do not provision mailboxes,
relay probes, VPN containers or Nyxmon check rows.

```python
from ops_deploy.services.metrics_endpoint import MetricsEndpointConfig, deploy_metrics_endpoint
from ops_deploy.services.torrent_vpn_metrics_endpoint import (
    TorrentVpnMetricsEndpointConfig,
    deploy_torrent_vpn_metrics_endpoint,
)

mail = MetricsEndpointConfig(
    auth_user="monitor",
    secrets="secrets/metrics.yml",  # endpoint_password
    bind="tailscale-interface",
    services=("postfix",),
)
deploy_metrics_endpoint(cfg=mail, secrets=secrets)

vpn = TorrentVpnMetricsEndpointConfig(
    auth_user="monitor",
    secrets="secrets/metrics.yml",
    bind="tailscale",
)
deploy_torrent_vpn_metrics_endpoint(cfg=vpn, secrets=secrets)
```

Both configs use a `metrics` system user/group, preserve an existing account's
home, and store bcrypt credentials as `root:<group> 0640`. An already verifying
hash is reused. Passwords are sent through protected file delivery, and the
Python endpoints verify request passwords through `htpasswd -vi` stdin.
No authentication password enters a command argument. The mail wrapper keeps
legacy bcrypt suffix equivalence only when all selected-user records are
bcrypt, and preserves the 255-byte request bound. APR/SHA and other schemes
reject CR/LF suffixes. Requests with a NUL in the password return 401 instead of an old Python exception.

## Shared configuration

| Field | Meaning |
|---|---|
| `secrets` | file providing `endpoint_password` |
| `auth_user` | Basic Auth username |
| `user`, `group` | endpoint account; default `metrics` and its same-named group |
| `bind` | explicit IPv4; `tailscale` requires one result from `tailscale ip --4`; `tailscale-interface` follows the interface IPv4 with loopback fallback, like Ansible facts |
| `service_name`, `port`, `path` | endpoint unit and URL; defaults below |
| `server_path` | Python wrapper location |
| `htpasswd_dir`, `htpasswd_file` | credentials directory and optional independent file override |
| `packages` | role package list |
| `httpd_impl` | `python` or `rust`; default `python` |
| `httpd_rust_version`, `httpd_rust_sha256` | existing [metrics-httpd switch](metrics_httpd.md) release inputs |

The existing switch installs and validates a selected release even when Python
continues serving. Rust uses the same versioned binary, drop-in, sandbox and
pin/prune behavior as the roles. HTTP probes verify the selected process and the
unauthenticated 401 response. Read-only bind preflight admits the existing
endpoint unit and rejects a conflicting listener before changes.

## Mail endpoint

`MetricsEndpointConfig` defaults to `metrics-endpoint.service`, port **9100**,
`/.well-known/health`, `/usr/local/bin/metrics_httpd.py`, and
`/etc/metrics-endpoint/htpasswd`.

`script_path` defaults to `/usr/local/bin/mail-metrics.sh`, `script_timeout` to
10 seconds, `queue_path` to `/var/spool/postfix`, and `vmail_path` to
`/mnt/cryptdata/vmail`. The default service list is `postfix`, `dovecot`,
`rspamd`; callers can select the service list explicitly. `probe_states` accepts
`{name, path}` entries and preserves relay-probe sections. Built-in section names
cannot be shadowed.

Queue ACLs use the role's recursive `rX` setting and its `setfacl --test` change
detection. New queue entries are new ACL drift and are reconciled recursively.
A zero-mutating repeat assumes no new entries arrive between the plans.
Missing queue directories are left alone. The unit restarts only
when its inputs change; a converged repeat performs no mutating operations.

## Torrent VPN endpoint

`TorrentVpnMetricsEndpointConfig` defaults to
`torrent-vpn-metrics-endpoint.service`, port **9102**,
`/.well-known/vpn-egress`, `/usr/local/bin/torrent_vpn_metrics_httpd.py`, and
`/etc/torrent-vpn-metrics-endpoint/htpasswd`.

`site_path` defaults to `/var/lib/torrent-vpn-metrics`; the JSON file is `vpn.json`
below it unless `json_file` overrides it. `collector_path` defaults to
`/usr/local/bin/torrent_vpn_metrics_collect`. The root oneshot and enabled timer
keep `torrent-vpn-metrics-collector` identities and the 300-second interval.
Container names, provider checks, tunnel interface, public-IP URL, collector
request timeout and interval remain configurable with the role defaults.

Unlike Ansible's unconditional oneshot start marked `changed_when:false`, this
deploy collects initially when the payload is missing, malformed, stale (older
than twice its interval), when collector inputs change, or when the timer has
no next elapse. The latter seeds `OnUnitActiveSec` after a reboot even if a
persisted payload is still fresh. It preserves and
checks the enabled, armed timer. Timer-driven timestamp changes remain normal
live activity; they are not reported as deploy mutations. A converged repeat
neither rewrites the payload nor restarts the endpoint. A collector change
refreshes the payload and timer without restarting an unchanged HTTP wrapper.

## Linux fixture verification

Run `METRICS_ENDPOINT_SMOKE=1 just smoke tests/smoke/test_metrics_endpoints_smoke.py` against an isolated worker-owned VM.
It exercises fresh deployment, a normal input update, and zero-mutating repeats
for both services, with real HTTP 401/wrong-password/200 responses, queue ACL
access, reused credentials and the rendered wrapper hash. The fixture deliberately
has no VPN stack: its fresh collector payload reports an error, proving the
endpoint exposes negative state rather than claiming a healthy VPN. The fixture
never uses inventory credentials or production data.
