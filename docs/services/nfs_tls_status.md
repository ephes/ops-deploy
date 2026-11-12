# nfs_tls_status

A per-host status report for an NFS-over-TLS mount (`tlshd`, `xprtsec=mtls`)
as an authenticated JSON endpoint, and the Nyxmon json-metrics check that
reads it. Nyxmon has no systemd-unit or certificate-expiry check of its own;
this report turns them into JSON values Nyxmon compares. Native to ops-deploy
(no Ansible role behind it), shaped like
[thermal_monitoring](thermal_monitoring.md): an exporter on a systemd timer
writes one JSON file, an endpoint serves it through the shared
[metrics-httpd switch](metrics_httpd.md) in `json-file` mode, and the check
is upserted either on the endpoint's host or, with a separate check-only
config, into the Nyxmon of another host.

```python
from ops_deploy.services.nfs_tls_status import (
    NfsTlsStatusCheckConfig,
    NfsTlsStatusConfig,
    deploy_nfs_tls_status,
    deploy_nfs_tls_status_check,
)

# The NFS server.
server = NfsTlsStatusConfig(
    secrets="secrets/example.yml",  # provides endpoint_password
    port=9109,
    units=["nfs-server.service", "tlshd.service"],
    certificates=["/etc/tlshd/server.pem", "/etc/tlshd/nfs-ca.pem"],
)
deploy_nfs_tls_status(server, secrets)

# The client: the mount only once it is switched to NFS over TLS.
client = NfsTlsStatusConfig(
    secrets="secrets/example.yml",
    port=9109,
    units=["tlshd.service"],
    mounts=[
        {
            "where": "/mnt/cryptdata/media",
            "source": "192.0.2.10:/fast/media",
            "required_options": ["xprtsec=mtls"],
            "unit": "mnt-cryptdata-media.mount",
        }
    ],
    certificates=["/etc/tlshd/client.pem", "/etc/tlshd/nfs-ca.pem"],
)
deploy_nfs_tls_status(client, secrets)

# On the Nyxmon host: the check of the server's endpoint.
check = NfsTlsStatusCheckConfig(
    secrets="secrets/example.yml",
    nyxmon_check={
        "service_name": "server",
        "name": "Server NFS TLS",
        "check_interval": 300,
        "auth_username": "nyxmon",
        "data": {
            "url": "http://server.example.invalid:9109/.well-known/nfs-tls",
            "timeout": 10.0,
            "retries": 1,
            "retry_delay": 2.0,
            "checks": server.check_conditions(),
        },
    },
)
deploy_nfs_tls_status_check(check, secrets)
```

For the client, which runs Nyxmon itself, `nyxmon_check` can sit on the
`NfsTlsStatusConfig` directly (its `auth_username` must be the endpoint's
`auth_user`).

## Configuration (`NfsTlsStatusConfig`)

| Field | Default | Meaning |
|---|---|---|
| `units` | (required) | systemd units that must be active, e.g. `tlshd.service` |
| `mounts` | `()` | `NfsStatusMount` entries (below) |
| `certificates` | `()` | certificate files (PEM; the first certificate in the file counts) |
| `warn_days` | `60` | a certificate with fewer whole days left is a warning |
| `port` | (required) | the endpoint's TCP port; pick a free one per host |
| `bind` | `tailscale` | an IPv4 address, or `tailscale`: what `tailscale ip --4` prints |
| `path` | `/.well-known/nfs-tls` | the endpoint's URL path |
| `auth_user` | `nyxmon` | the basic-auth user; the password is the secret `endpoint_password` |
| `service_name` | `nfs-tls-status-endpoint` | the endpoint unit |
| `user` / `group` | `metrics` / the user | the endpoint's system account; the report's group |
| `site_path` | `/var/lib/nfs-tls-status` | the report directory (`status.json`) |
| `htpasswd_dir` | `/etc/nfs-tls-status` | `htpasswd` and the exporter's `config.json` |
| `exporter_path`, `server_path` | under `/usr/local/lib/nfs-tls-status/` | the exporter and the Python HTTP server |
| `timer_name` | `nfs-tls-status-collector` | the collector's `.service` and `.timer` |
| `timer_interval` | `300` | seconds between reports (60 to 3600) |
| `nyxmon_check` | `None` | a json-metrics check upserted into a Nyxmon on this host |
| `httpd_impl`, `httpd_rust_version`, `httpd_rust_sha256` | `python`, `""`, `""` | the [metrics-httpd switch](metrics_httpd.md) |

`NfsStatusMount`: `where` (the mount point), `source` (as the kernel shows it,
e.g. `host:/export`), `fstype` (default `nfs4`), `required_options` (each
must appear among the mount's options, mount and superblock options together,
e.g. `xprtsec=mtls`) and `unit` (optional: a mount unit that must be active as
well).

`NfsTlsStatusCheckConfig`: `nyxmon_check` plus `service_name`, `user` and
`site_path` of the Nyxmon instance (defaults `nyxmon`, `nyxmon`,
`/home/nyxmon/site`); the check must write that instance's database.

Unit names, mount points and certificate paths become report keys: lowercase,
every run of other characters one `_`, leading and trailing `_` dropped
(`nfs-server.service` is `nfs_server_service`, `/etc/tlshd/nfs-ca.pem` is
`etc_tlshd_nfs_ca_pem`). The keys must start with a letter and be distinct
within each section, or the config is refused.

## The report

`/var/lib/nfs-tls-status/status.json` (`root:<group> 0640`, written to a
temporary file and renamed), served with a `meta` object added by the
endpoint (`age_seconds` is the file's age):

```json
{
  "schema": 1,
  "collected_at": "2026-11-12T10:00:00+00:00",
  "collected_at_epoch": 1794477600,
  "warn_days": 60,
  "ok": true,
  "units": {
    "tlshd_service": {"unit": "tlshd.service", "load_state": "loaded", "active_state": "active",
                      "sub_state": "running", "ok": true, "problems": []}
  },
  "mounts": {
    "mnt_cryptdata_media": {"where": "/mnt/cryptdata/media", "present": true, "fstype": "nfs4",
                            "source": "192.0.2.10:/fast/media", "options": ["rw", "relatime", "vers=4.2", "xprtsec=mtls"],
                            "expected_fstype": "nfs4", "expected_source": "192.0.2.10:/fast/media",
                            "required_options": ["xprtsec=mtls"], "missing_options": [],
                            "unit": "mnt-cryptdata-media.mount", "unit_active_state": "active",
                            "ok": true, "problems": []}
  },
  "certificates": {
    "etc_tlshd_client_pem": {"path": "/etc/tlshd/client.pem", "not_after": "2027-11-12T10:00:00+00:00",
                             "not_after_epoch": 1826013600, "days_left": 365, "ok": true, "problems": []}
  },
  "meta": {"generated_at": "2026-11-12T10:00:00+00:00", "generated_at_epoch": 1794477600, "served_at_epoch": 1794477630, "age_seconds": 30}
}
```

- A unit is `ok` when `systemctl show` reports `ActiveState=active`; a unit
  that does not exist is `inactive` with load state `not-found`.
- A mount is `ok` when the topmost mount at `where` in `/proc/1/mountinfo`
  (the host's mount table; the collector's own is a read-only sandbox copy)
  has the expected type and source, every required option and, with `unit`,
  that unit is active. An automount trigger alone (`autofs`) is not enough.
- A certificate's `days_left` are whole days until `notAfter`
  (`openssl x509 -noout -enddate`), rounded down, negative once expired; it is
  `ok` when `days_left >= warn_days`. A missing or unreadable file has
  `days_left: null`. Error texts never include the file's content.

Every entry is checked on its own: a missing unit, mount or file, or a failing
tool, is `ok: false` with a reason in `problems`, never a missing report.

## The Nyxmon rules (`check_conditions()`)

| Path | Rule | Severity |
|---|---|---|
| `$.meta.age_seconds` | `< 3 * timer_interval` (900 s by default) | warning |
| `$.units.<key>.ok` | `== true` | critical |
| `$.mounts.<key>.ok` | `== true` | critical |
| `$.certificates.<key>.ok` | `== true` (at least `warn_days` left) | warning |
| `$.certificates.<key>.days_left` | `> 0` (null fails) | critical |

A mount listed in `mounts` is critical as long as it is absent, so a client
lists it only once it has switched to the TLS mount.

## What the deploy does

`deploy_nfs_tls_status`:

1. Checks the password (non-placeholder, at most 72 bytes, no control
   characters) and the bind address before any operation, then that the port
   is free or already this endpoint's (read-only).
2. Installs `python3`, `apache2-utils` and `openssl`, the `metrics` account
   and the directories (`/etc/nfs-tls-status` and the report directory
   `root:metrics 0750`).
3. The exporter, its `config.json`, the collector unit (`Type=oneshot`, root
   because the certificate files are root-only, `ProtectSystem=strict`,
   `ReadWritePaths=<site_path>`) and its timer (`OnActiveSec=30s`,
   `OnUnitActiveSec=<timer_interval>s`). The collector runs once while there
   is no report or the exporter, its config or its unit changed.
4. The endpoint: the Python `json-file` server (os_lifecycle's), the htpasswd
   file (rewritten only when the password does not verify), the unit
   (`IPAddressAllow=localhost 100.64.0.0/10`, `ReadOnlyPaths=<site_path>`),
   then the metrics-httpd selection, restart on change, and the switch's
   verification (the unit answers `401` with realm `nfs-tls-status`).
5. With `nyxmon_check`, the json-metrics upsert into the local Nyxmon.

`deploy_nfs_tls_status_check` only checks the password and upserts the check
into the Nyxmon on its host. The password reaches a host only as a bcrypt
hash in the htpasswd file and on the upsert's stdin; it never appears in an
operation name or a command line.
