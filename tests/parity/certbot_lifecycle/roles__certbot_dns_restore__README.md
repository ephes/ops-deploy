# Certbot DNS Restore Role

Restore Certbot state (`/etc/letsencrypt`) from an archive and validate with a dry-run renewal.

## Description

Restores a `certbot_dns_backup` archive into `certbot_dns_dir`, fixes ownership and the
credentials file permissions, and optionally runs `certbot renew --dry-run` to verify the
restored state.

The archive stores the directory by name (`letsencrypt/live/...`). The role:

1. checks every archive member before anything changes: it must be a relative path below
   `letsencrypt/` (the basename of `certbot_dns_dir`) without `..`, symlinks must stay
   inside that tree and no hardlink may point at a symlink. A bad archive fails here and leaves the host untouched;
2. extracts into a `.restore-staging-*` directory next to `certbot_dns_dir`;
3. keeps the current directory as `/etc/letsencrypt.pre-restore-<UTC timestamp>-<suffix>`
   and moves the restored tree into `/etc/letsencrypt`;
4. removes the staging directory and reports the pre-restore copy.

Pre-restore copies are never removed by the role; inspect and prune them by hand. Earlier
versions extracted into `/`, which created `/letsencrypt` and left `/etc/letsencrypt`
unchanged; remove a stray `/letsencrypt` from such a run with `certbot_dns_deploy`'s
`certbot_dns_stray_config_dirs`, which checks it first.

## Role Variables

```yaml
certbot_dns_restore_archive: ""          # Path to backup archive (required)
certbot_dns_dir: "/etc/letsencrypt"      # Certbot directory
certbot_dns_credentials_file: "/etc/letsencrypt/dns-credentials.ini"
certbot_dns_rfc2136_credentials_file: "/etc/letsencrypt/dns-rfc2136-credentials.ini"  # mode fixed when present
certbot_dns_restore_run_dry_renew: true  # Run certbot renew --dry-run after restore
```

## Example Playbook

```yaml
- hosts: macmini
  become: true
  vars:
    certbot_dns_restore_archive: "/opt/backups/certbot-dns/manual-20251202T2200.tar.gz"
  roles:
    - role: local.ops_library.certbot_dns_restore
```

## Notes

- The archive must contain `letsencrypt/...` members, as `certbot_dns_backup` writes them. The
  top-level directory is set to `certbot_dns_restore_dir_mode` (default `0700`); the credentials
  file is set to 0600.
- Dry-run renewal can be disabled with `certbot_dns_restore_run_dry_renew: false`.
