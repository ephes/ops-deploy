# NFS export (with RPC-with-TLS)

`infra.nfs_export` serves directories over NFSv4 from rendered
`/etc/exports.d` files. It has no ops-library counterpart. It was written for
the macmini media tree on Fractal (ops-control
`docs/MACMINI_MEDIA_ON_FRACTAL.md`), where the client side is
[`base.nfs_client_mount`](../base.md#nfs_client_mount) and both sides use
[`base.tlshd`](../base.md#tlshd) for NFS over TLS with client certificates
(`xprtsec=mtls`).

```python
from pathlib import PurePosixPath

from ops_deploy.base import TlshdConfig
from ops_deploy.infra import NfsExport, NfsExportClient, NfsExportConfig, deploy_nfs_export

deploy_nfs_export(
    NfsExportConfig(
        exports=(
            NfsExport(
                name="media",
                path=PurePosixPath("/fast/media"),
                fsid=1,
                clients=(
                    NfsExportClient(
                        host="192.168.178.94",
                        options=("rw", "sync", "no_subtree_check", "no_root_squash", "sec=sys", "xprtsec=mtls"),
                    ),
                ),
            ),
        ),
        tls=TlshdConfig(role="server", ca_certificate=ca_pem, certificate=server_pem, private_key=server_key),
    )
)
```

renders `/etc/exports.d/media.exports`:

```
# Managed by ops-deploy infra.nfs_export; local changes are overwritten.
/fast/media 192.168.178.94(rw,sync,no_subtree_check,no_root_squash,sec=sys,xprtsec=mtls,fsid=1)
```

## Config

| Model | Field | |
|---|---|---|
| `NfsExportConfig` | `exports` | at least one; names, paths and `fsid`s unique |
| | `tls` | `TlshdConfig` with `role="server"`, or `None`; required when any client option is `xprtsec=tls` or `xprtsec=mtls` (also inside a `:` list) |
| `NfsExport` | `name` | `^[a-z0-9][a-z0-9_-]*$`, the file stem of `/etc/exports.d/<name>.exports` |
| | `path` | absolute, normalized, letters, digits and `._-/` only, not `/` |
| | `fsid` | integer ≥ 1, appended to every client's options: fixed, so client file handles survive a server restart or a dataset remount |
| | `clients` | at least one, hosts unique |
| `NfsExportClient` | `host` | an IPv4 address or network in CIDR form (`192.168.178.0/24`; host bits must be zero) |
| | `options` | `exports(5)` options, `key` or `key=value`, each key once, no commas inside an item, never `fsid=` |

## What the deploy does

In order, all read while planning so `--dry` shows the real plan and a
converged host runs only the two read-only checks:

1. `nfs-kernel-server` is installed when missing, with
   `NEEDRESTART_SUSPEND=1 NEEDRESTART_MODE=l DEBIAN_FRONTEND=noninteractive`
   and `--no-install-recommends` (needrestart restarts nothing). Whether
   `zfs-share.service` and `remote-fs-pre.target` are enabled is read before
   the install; the ones that were are enabled again right after it (the NFS
   over TLS lab test of 2026-11-12 saw package changes toggle them). Nothing
   is started or stopped for them. `static` units (`remote-fs-pre.target` on
   noble) have nothing to enable.
2. `/etc/nfs.conf.d/ops-deploy.conf` (root, 0644) with `[mountd]`
   `manage-gids=n`. **Mandatory:** Ubuntu ships `manage-gids=y`, with which the
   server ignores the groups an `AUTH_SYS` client sends and looks them up in
   its own user database; client-only accounts (Radarr, Sonarr, qBittorrent)
   then get `EACCES` in `root:media 02775` directories although they are in
   `media`. With `n` the client's groups (up to 16) are used.
3. `/etc/exports.d/<name>.exports` per export (root, 0644).
4. With `tls`: the server side of [`base.tlshd`](../base.md#tlshd).
5. `nfs-server.service` enabled and running. `systemctl restart
   nfs-mountd.service nfs-server.service` **only when the `nfs.conf.d` file
   changed** (`rpc.mountd` reads it at start); that also restarts
   `zfs-share` (its `share -a` is a no-op without `sharenfs`) and blocks
   client I/O for a few seconds. On a fresh install this is the restart that
   replaces the package's start with the default `manage-gids=y`.
6. `exportfs -ra` only when an exports file changed.
7. Read-only check: `exportfs -v` lists every export path (a long path stands
   alone on its line; the check reads the first field of each line).

ZFS `sharenfs` is not used and not touched: the exports are files, like every
other config in ops-deploy. An exports file whose export was removed from the
config is not deleted (delete it and run `exportfs -ra` by hand).

The deploy opens no firewall port. On Fractal (2026-11-12) `ufw` is inactive
and the only rules are Tailscale's chains, which accept everything else on the
LAN, so NFS (TCP 2049; NFSv4 needs no other port) is reachable from the LAN;
access is decided by the export's client list and, with `xprtsec=mtls`, the
client certificate.

## Tests

`tests/test_infra_nfs_export.py`: the design's exports line byte for byte,
several clients, `manage-gids=n`, config refusals (bad names, paths, `fsid`,
hosts, options, `fsid=` in client options, TLS options without `tls`, a
`tls` with the client role, duplicates); a fresh host's plan (install with
the needrestart environment, `zfs-share` enabled again, files, tlshd, the
`manage-gids` restart before `exportfs -ra`, the check last, no `zfs`
command, the key in no operation name or argument); a converged host with no
mutating change; an exports change re-exports without a restart; an
`nfs.conf.d` change restarts mountd and the server once and nothing else.
