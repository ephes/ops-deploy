# zellij_ingress

Port of the `zellij_ingress_deploy` Ansible role: one Traefik dynamic config
on the edge host that sends allowlisted clients of a friendly host name to a
fixed URL with a temporary redirect. The Zellij web client itself stays on
the backend host's loopback behind an HTTPS front end (for example Tailscale
Serve); that setup, the backend host and its access policy are out of scope.

```python
from ops_deploy.services.zellij_ingress import ZellijIngressConfig, deploy_zellij_ingress

cfg = ZellijIngressConfig(
    traefik_host="zellij.example.invalid",
    redirect_target="https://backend.example.invalid/",
)
deploy_zellij_ingress(cfg)
```

The deploy has no secrets. ops-control registers it as `zellij_ingress`
(see its `docs/PYINFRA.md`).

## What it writes

| Path | Owner, mode | |
|---|---|---|
| `/etc/traefik/dynamic` | `root:root 0755` | ensured, like the role |
| `/etc/traefik/dynamic/zellij.yml` | `root:root 0644` | the route (`traefik_config_path`) |

The route has exactly two routers, `zellij-secure` (the configured entry
points, `tls: {}` or `tls.certResolver`) and `zellij-http` (entry point
`web`). Both match `Host(...) && (ClientIP(...) || ...)` over the allowlist,
use the middleware `zellij-redirect-target` (`redirectRegex`, regex `.*`,
the fixed target, `permanent: false`) and Traefik's built-in
`noop@internal` service. There is no `services` section and no backend:
clients outside the allowlist get Traefik's 404, never the redirect.

The role's template is shipped unchanged, including its
`# Managed by Ansible` header, and rendered like Ansible's `template` module
(`trim_blocks`, trailing newline kept). The file is byte-identical to the
role's for the same inputs (`tests/test_zellij_ingress.py` renders the
vendored copy independently), so a host the role deployed sees no change on
the first run unless its file differs.

## Configuration (`ZellijIngressConfig`)

The role's variables without the `zellij_ingress_` prefix, with its defaults.

| Field | Default | Notes |
|---|---|---|
| `traefik_enabled` | `true` | `false` is the role's no-op: no operation at all, an existing route file is left in place (not removed) |
| `traefik_host` | `""` | required when enabled; a DNS host name |
| `redirect_target` | required | always required (the role asserts it even when disabled); see below |
| `traefik_entrypoints` | `web-secure` | non-empty (an empty list would render as every entry point); plain names YAML reads as strings |
| `traefik_cert_resolver` | `""` | empty: `tls: {}` (a file-provider certificate covers the host) |
| `traefik_config_path` | `/etc/traefik/dynamic/zellij.yml` | a `<name>.yml` directly in `/etc/traefik/dynamic` |
| `allowed_ip_ranges` | `127.0.0.1/32`, `::1/128`, `100.64.0.0/10`, `fd7a:115c:a1e0::/48` | non-empty when enabled; IP networks in CIDR notation |

`redirect_target` is a fixed `http` or `https` URL: a host name, an optional
port and a plain path (letters, digits, `. _ ~ / -`). Credentials, query,
fragment, quotes, backslashes, whitespace, `%` and `$` (a capture-group
reference in Traefik's `redirectRegex` replacement) are refused. Every check
runs when the config is built, before any operation; errors never quote the
value.

## Differences from the role

- The role's handler reloads Traefik after a change (and restarts it when
  the reload fails). This deploy never touches Traefik: like the other
  ports' routes (`traefik_route(..., restart="none")`), it relies on the file
  provider watching `/etc/traefik/dynamic`, which the role's README assumes
  too. Nothing touches systemd, certificates, Traefik's static config, the
  backend host or its HTTPS front end.
- The inputs are checked more strictly than the role's length assertions
  (see above); values the role would render into a broken or wider route
  are refused instead.
- `traefik_config_path` is limited to the watched dynamic directory.

## Converged runs

A second run gathers facts only: no upload and no command. Drift in the
route's content rewrites only that file; drift in its owner or mode is
repaired without rewriting the content.
