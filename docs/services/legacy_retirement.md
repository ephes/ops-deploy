# Legacy retirement

`ops_deploy.services.legacy_retirement` retires accounts, systemd units, paths
and PostgreSQL databases that predate the declared deploys and that no role
or deploy owns. It is an explicit, one-off route: no normal deploy runs it.
It is not a port of an Ansible role.

```python
from ops_deploy.services.legacy_retirement import LegacyRetirementConfig, RetiredDatabase, retire_legacy

cfg = LegacyRetirementConfig(
    archive_dir="/var/backups/example-legacy-retirement",
    accounts=("alice", "app"),
    units=("app.service",),
    paths=("/etc/traefik/dynamic/app.traefik.yml",),
    databases=(RetiredDatabase(name="app", owner="app"),),
    protected_accounts=("keeper",),
)
retire_legacy(cfg)
```

## Configuration

| Field | Meaning |
|---|---|
| `archive_dir` | required; a directory directly below `/var/backups`, created `root:root 0700` |
| `accounts` | user names; each must have uid >= `min_uid` and the home `/home/<name>` |
| `units` | unit names with a type suffix; only their files in `/etc/systemd/system` (unit file and `<unit>.d`) are removed |
| `groups` | groups removed after the accounts (gid >= `min_uid`; system groups such as `sudo` or `adm` are refused) |
| `paths` | other files or directories, canonical and at least three levels deep (an application directory directly in `/opt` or `/srv` is allowed); not below `/home`, `/etc/systemd/system`, kernel filesystems or `archive_dir` |
| `databases` | `RetiredDatabase(name, owner)`: the database and its owner role (lowercase SQL identifiers; `postgres`, `template0`, `template1` and the `postgres` role are refused) |
| `protected_accounts` | names the config refuses to list; `root`, `postgres`, `nobody`, `www-data`, `daemon` and `sshd` are always refused |
| `min_uid` | `1000` (it cannot be lower) |

## What a run does

One read-only probe (`python3 -I -B`, the request as its argument) reports
the accounts, units, paths, archives and databases. A probe that fails stops
the run before any change. Then, while planning, the run refuses (and changes
nothing) when

- a listed account has processes, a lingering user manager or a crontab, a
  uid below `min_uid` or a home other than `/home/<name>`, or `/home/<name>` is a symbolic
  link (also for an account already gone); nothing is killed;
- a listed unit is not `inactive` or `failed`, or its unit file or a drop-in
  lies outside `/etc/systemd/system`; nothing is stopped;
- a listed database has connections, or its owner role owns another database;
- a listed group has a gid below `min_uid`, or an account that is not retired
  as a member or with it as primary group;
- databases are listed and the host has no PostgreSQL.

Otherwise, in this order, for whatever still exists:

1. Archives in `archive_dir`, each written as `.<name>.partial`, checked
   (`tar -tzf`, `pg_restore -l`), set to `0600` and published with `ln`, which
   fails rather than replace an archive that already exists. An existing
   archive is never replaced: it was written before any removal of its source.
   Every source has its own archive, so a source listed later is archived too:
   - `path-<name>-<hash>.tar.gz`: each listed unit file, each unit's `.d`
     directory and each listed path (`<hash>`: the first twelve hex digits of
     the SHA-256 of the absolute path);
   - `postgres-<db>.dump`: `pg_dump -Fc` of each listed database (the role is
     not dumped; restore with `pg_restore --no-owner` or create the role first);
   - `home-<user>.tar.gz`: `/home/<user>` and `/var/mail/<user>`.

   The tar archives keep numeric owners, permissions, ACLs and extended
   attributes (`tar --numeric-owner --acls --xattrs -czpf`).
2. Units: `systemctl disable` where enabled, their files removed (each command
   checks again that the unit is inactive or failed, and that its archive
   exists), `daemon-reload`, `reset-failed`.
3. Paths: removed after checking their archive; a path below the Traefik
   dynamic directory only while no route transaction holds its lock.
4. Databases: dropped only while their dump exists and they have no
   connection, then their owner roles (`DROP ROLE` fails loudly if the role
   still has privileges elsewhere).
5. Accounts: `userdel`, again only without processes, lingering user manager
   or crontab and with the home archive; the home and the mail spool removed;
   the same-named group removed if `userdel` left it. A run interrupted after
   `userdel` resumes: the probe reports `/home/<user>`, `/var/mail/<user>` and
   the group also when the account is gone, and the next run archives (if
   needed) and removes them.
6. Groups: `groupdel` for each listed group that still exists.

A second run, and a run on a host where everything is gone, plans no
operation. Files the accounts own outside their homes are not searched for
and stay, with their numeric owner.
