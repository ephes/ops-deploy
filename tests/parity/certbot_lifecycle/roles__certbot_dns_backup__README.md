# Certbot DNS Backup Role

Back up Certbot state (`/etc/letsencrypt`) including certificates, renewal configs, account data, and credentials.

## Description

Creates a timestamped archive of the Certbot directory and optionally fetches it to the control host. Intended to preserve DNS-01 issued certificates and account keys.

## Role Variables

```yaml
certbot_dns_backup_root: "{{ backup_root_prefix | default('/opt/backups') }}/certbot-dns"
certbot_dns_backup_prefix: manual
certbot_dns_backup_src: "/etc/letsencrypt"
certbot_dns_backup_archive_format: gz   # produces .tar.gz
certbot_dns_backup_fetch_local: true
certbot_dns_backup_local_dir: "{{ lookup('env', 'HOME') }}/backups/certbot-dns"
```

## Example Playbook

```yaml
- hosts: macmini
  become: true
  vars:
    certbot_dns_backup_prefix: "manual"
  roles:
    - role: local.ops_library.certbot_dns_backup
```

## Notes

- Ensure credentials file permissions are preserved (source directory should have mode 0600 on credential files).
- The archive contains secrets; store securely.
