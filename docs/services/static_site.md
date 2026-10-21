# static_site

Port of the `static_site_deploy` Ansible role: a generated, read-only site
(for example a report snapshot) published from a controller directory and
served on loopback by a tiny stdlib HTTP server under a hardened systemd unit,
behind a Traefik route. No database, no state besides the published files.

```python
from ops_deploy.services.static_site import StaticSiteConfig, deploy_static_site

cfg = StaticSiteConfig(
    service_name="benchmarks-static",
    source_path=Path("/absolute/path/to/generated/site"),
    site_path="/srv/benchmarks-static/site",
    port=10061,
    traefik_host="benchmarks.example.com",
    traefik_cert_resolver="letsencrypt",
    restrict_to_required_files=True,
    healthcheck_contains="registry snapshot",
    verify_public=True,
)
deploy_static_site(cfg)
```

The service has no secrets. ops-control registers it as `benchmarks_static`
(staging only, see its `docs/PYINFRA.md`).

## Configuration (`StaticSiteConfig`)

Defaults follow the role's `defaults/main.yml`; `user`, `site_path` and
`server_path` default from `service_name`.

| Field | Default | Notes |
|---|---|---|
| `service_name` | `static-site` | `^[a-z][a-z0-9-]{1,62}$`; also the systemd unit and Traefik route name |
| `user`, `group` | `service_name`, `user` | no-login system account; the group may differ |
| `source_path` | required | absolute controller directory (letters, digits, `_ . / -`), not `/`, not a symlink |
| `site_path` | `/srv/static-sites/<service_name>` | document root on the host |
| `required_files` | `index.html`, `report.md`, `snapshot.json` | must exist in the source as regular files |
| `restrict_to_required_files` | `false` | exactly the required files, nothing nested |
| `rsync_delete` | `true` | remove published files that left the source |
| `private` | `false` | `0750`/`0640` instead of `0755`/`0644`; verified with `find -perm /o=rwx` |
| `python_path`, `server_path` | `/usr/bin/python3`, `/usr/local/libexec/<service_name>-httpd.py` | |
| `bind_host`, `port` | `127.0.0.1` (only value), `10061` | port 1024 to 65535 |
| `healthcheck_contains` | `""` | marker the index must contain (loopback, and public with `verify_public`) |
| `traefik_enabled` | `true` | then `traefik_host` is required |
| `traefik_host` | `None` | not `static.example.com` |
| `traefik_entrypoints`, `traefik_http_entrypoint` | `("web-secure",)`, `web` | the HTTP entrypoint serves the redirect router and must not be an HTTPS one |
| `traefik_cert_resolver` | `""` | empty: `tls: {}` |
| `traefik_allowed_networks` | `()` | strict CIDRs; non-empty adds an `ipAllowList` to both routers (403 before any redirect) |
| `verify_public`, `public_healthcheck_retries`, `public_healthcheck_delay` | `false`, `20`, `3` | HTTPS check from the host, certificate validated |
| `httpd_impl` | `python` | the HTTP server: the role's Python script or the pinned Rust `metrics-httpd static` (the role's `static_site_impl`); see [metrics-httpd switch](metrics_httpd.md) |
| `httpd_rust_version`, `httpd_rust_sha256` | `""`, `""` | the release pin (`metrics_httpd_rust_version`/`_sha256`); with a version the release is installed and checked even on Python; `rust` needs both |

## What the deploy does

1. Validates the source on the controller, before any host operation: a real
   directory, the required files as regular files, no symbolic links anywhere,
   no sockets/FIFOs/devices; with `restrict_to_required_files` exactly the
   required files at the top level.
2. System group and user
   (`/usr/sbin/nologin`, home `/home/<user>` not created, as the role does;
   an existing user is left alone with a warning). Like the role, the deploy
   needs `rsync` on the host already and fails at the content sync without it.
3. Parent directories (`0755 root:root`) and the document root
   (`root:<group>`, `0755` or `0750`).
4. Content: `sync_tree` with `--checksum`, `--chown=root:<group>` and
   `--chmod=D0755,F0644` (private: `D0750,F0640`). It is only a change when
   content, ownership or a mode differs.
5. Server script (`0755 root:root`), systemd unit, the HTTP server switch's
   select step ([metrics-httpd switch](metrics_httpd.md); `--check-config`
   runs as the service user with every hardening line of the unit), Traefik
   route (`/etc/traefik/dynamic/<service_name>.yml`, the role's own
   template). Traefik is not restarted; its file provider watches the
   directory.
6. `service_rollout`: daemon-reload when the unit or the drop-in changed;
   restart when either or the server script changed (a content update never
   restarts the server). Then the switch's verify step: the unit runs the
   selected server and answers 200 for `/`; then the pin and the prune.
7. Read-only checks: loopback `GET /` answers 200 (10 tries, 1 s apart) with
   the marker; with `verify_public` the HTTPS route likewise; with `private`
   no entry is accessible to others.

## Differences from the role

- Not ported, the playbook never sets them: `static_site_systemd_unit_name`,
  `static_site_systemd_unit_path` and `static_site_traefik_config_path`
  (unit and route are named after `service_name`), and a dotted
  `traefik_cert_resolver`.
- rsync never transfers (or deletes) `.git`, `.venv`, `__pycache__` and
  `.ops-deploy-*`/`.pyinfra-*`; the role would publish them.
- Files are compared by checksum, not by size and time, and times are not
  copied. After an ops-deploy run, Ansible's next sync sees different times
  and rewrites every file (same bytes, so nothing changes for readers); the
  other direction is a no-op.
- The service restarts before the health checks (the role's handlers run
  before them too), but is started once, not started and restarted, on a
  first install; `daemon-reload` only runs when the unit changed.
- The role's validation messages are reproduced as errors; ports and path
  characters are validated when the config is built.

## Tests

`tests/test_static_site_parity.py` (unit, server script and route against the
vendored role templates, four variants), `tests/test_static_site.py` (fake
connector: first run, converged no-op, content/server/unit/route changes,
private mode, public probe, source validation, config validation),
`tests/test_sync_tree.py` (the `chmod` flag, including real rsync) and
`tests/smoke/test_static_site_smoke.py` (first run, converged rerun, content
update without restart, headers, allowlist 403 through Traefik, owners and
modes, private variant, strict-source refusal on the smoke VM).
