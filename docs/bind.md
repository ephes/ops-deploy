# BIND

`ops_deploy.infra.bind` ports the `bind_authoritative_deploy` role (deploy
only; checked against ops-library main `56564cce`, 2.63.2): an authoritative
BIND primary or secondary with static zones from the controller, dynamic
(RFC 2136) zones and TSIG keys. `named.conf`, `named.conf.options`,
`named.conf.local` and `named.conf.keys` are byte-identical to the role's
templates, so the role and this deploy take turns on a nameserver without
rewriting a file or reloading named.

```python
from pydantic import SecretStr
from ops_deploy.infra.bind import BindConfig, deploy_bind

deploy_bind(
    BindConfig(
        zone_files_dir="/path/to/files/bind",
        tsig_keys=[{"name": "xfer"}, {"name": "acme"}],
        zones=[
            {"name": "example.org", "file": "db.example.org", "type": "master", "allow_transfer": ('key "xfer"',)},
            {
                "name": "home.example.org",
                "file": "db.home.example.org",
                "type": "master",
                "dynamic": True,
                "update_policy": ('grant "acme" name _acme-challenge.home.example.org. TXT',),
            },
        ],
    ),
    {"xfer": SecretStr(xfer_secret), "acme": SecretStr(acme_secret)},
)
```

## Fields

The role's `bind_*` variables without the prefix, with the role's defaults:

| Field | Default | |
|---|---|---|
| `enabled` | `True` | `False` makes the deploy a no-op, like the role |
| `packages` | `bind9`, `bind9-utils`, `dnsutils` | installed when missing |
| `service_name` | `named` | |
| `config_dir`, `working_dir`, `dynamic_zone_dir` | `/etc/bind`, `/var/cache/bind`, `/var/lib/bind` | static zones, transfer-backed zones and dynamic zones live there |
| `builtin_zones_file` | `None` | `None`: the role's choice, `named.conf.root-hints` on Debian 13 and later, else `named.conf.default-zones` (read from `/etc/os-release`, as Ansible's facts are) |
| `zone_files_dir` | required | controller directory with the zone files (the role's default derives it from the playbook directory) |
| `config_owner`, `config_group`, `config_mode`, `service_user` | `root`, `bind`, `0644`, `bind` | |
| `zone_default_type`, `zone_transfer_backed_types` | `master`, `slave`/`secondary` | |
| `zones` | required, at least one | `name`, `file`, optional `type`, `dynamic`, `primaries`, `update_policy`, `allow_transfer`, `extra_config` (lists rendered verbatim, joined with `; `) |
| `recursion`, `recursion_acl`, `allow_query`, `allow_query_cache`, `allow_transfer`, `dnssec_validation` | `True`, `localhost`/`localnets`, `any`, `recursion_acl`, `none`, `auto` | |
| `listen_on`, `listen_on_v6`, `extra_options` | `()`, `any`, `()` | |
| `verify_enabled`, `verify_server`, `verify_zone_types`, `verify_retries`, `verify_delay` | `True`, `127.0.0.1`, master/primary/slave/secondary, `12`, `5` | the `dig` check |
| `firewall_check_enabled` | `True` | UFW warnings |
| `tsig_keys`, `tsig_keys_file`, `tsig_keys_mode` | `()`, `<config_dir>/named.conf.keys`, `0640` | key `name` and `algorithm` (default `hmac-sha256`); the secrets are the deploy's second argument |

The role's `validate.yml` assertions are config validation here: at least one
zone, non-empty `primaries` for transfer-backed zones, `dynamic` only on
`master`/`primary` zones with a non-empty `update_policy`, a non-empty
`allow_transfer`, and (while planning) every controller zone file present.

## Steps

1. A read-only probe (`files/bind_host.py probe`, `python3 -I` as root) gets
   every candidate file on stdin and answers per path: missing, the same,
   different, or not a regular file; whether owner and mode match; whether a
   `<file>.jnl` journal exists; and the UFW state. A dynamic zone's file and
   journal are only looked up, never read or compared.
2. Missing packages are installed (apt cache refreshed first). `config_dir`
   `root:bind 0755`, `working_dir` (with transfer-backed zones) and
   `dynamic_zone_dir` (with dynamic zones) `bind:bind 0775`, special bits
   cleared as Ansible's `file` does.
3. Only when the probe found a difference: one host-side transaction
   (`files/bind_host.py apply`, the request again on stdin) under an
   exclusive lock on `config_dir`:
    - decides again what differs (the plan's refusals, below, are repeated);
    - checks every new zone file with `named-checkzone <zone> <file>` and
      refuses a changed static zone whose serial is not greater (RFC 1982)
      than the serial of the file it replaces;
    - stages every file in a private directory next to its destination
      (owner, mode, fsync), keeps a hard link to each file it replaces, and
      renames them into place in the role's order (keys, options, local,
      zones, seeds, `named.conf`); a keys file that is no longer wanted is
      moved aside;
    - runs `named-checkconf <config_dir>/named.conf` on the result. If it
      fails, or anything fails in between, every replaced file is restored,
      every new file removed, and the step fails: named is not reloaded and
      keeps the files it had. SIGHUP, SIGINT and SIGTERM are blocked from the
      first change to the last restore and take effect afterwards.
    - A file that cannot be restored keeps its backup (`old-*`) in the
      staging directory (`.ops-deploy-bind.*` next to it), which stays in
      place; so does one that a killed run left behind. The probe reports
      such a directory and every later run is refused before any change
      until it has been checked against the configuration and removed by
      hand.
4. named enabled and running; `systemctl reload named` only when step 3
   changed something.
5. Read-only `dig @<verify_server> <zone> SOA +comments +norecurse` per
   authoritative zone (`verify_zone_types`) until it answers `NOERROR` with
   the `aa` flag (`verify_retries` × `verify_delay`). UFW warnings as in the
   role (inactive, or active without a 53 rule).

A converged host plans no mutating operation: the probe, and the `dig` checks
(read-only).

## Dynamic zones

A zone with `dynamic: true` takes RFC 2136 updates (ACME DNS-01 TXT records,
DDNS); named writes them to `<file>.jnl` and periodically back into the zone
file, and bumps the serial. The controller file is only a seed:

- An existing dynamic zone file is never read, compared, replaced, chowned or
  chmodded, whatever it contains, and its journal is never touched (the
  role's `copy` with `force: false`). The deploy never resets its serial.
- It is seeded (`bind:bind 0644`, after `named-checkzone`) only when neither
  the file nor its journal exists. The transaction links the seed in with
  `link()`, which never replaces a file that appeared meanwhile.
- **Refused:** a missing dynamic zone file whose journal still exists (the
  role would seed it, and named would then refuse the zone because the
  journal no longer matches). Restore the file, or remove the journal
  deliberately, first.
- A reload never rewrites a dynamic zone: `rndc reload` keeps it in memory
  with its journal.

Change a live dynamic zone's static records with `nsupdate`, or with
`rndc freeze <zone>`, edit, bump the serial, `rndc thaw <zone>`.

## TSIG keys

The secrets are a deploy argument (one per configured key name, no more, no
fewer), base64 key material, not empty and not `CHANGEME`. `named.conf.keys`
is the only file that holds them; it travels inside the JSON request on the
probe's stdin (pyinfra logs it as `<stdin redacted>`) and the transaction's
(through `secret_stdin`; the operation's arguments show `SecretContent(<redacted>)`),
the host compares it with the installed file in memory and answers only
`same` or `differs`. No secret and no digest of one is printed, put on a
command line or in an operation's arguments. Output of `named-checkconf` that
names the keys file is withheld.

## Differences from the role, on purpose

- All configuration files are validated together after the swap and restored
  on failure. The role writes `named.conf.options` and `named.conf.local`
  unvalidated and checks them only through `named.conf`'s `validate`, which
  does not run when `named.conf` itself is unchanged; a broken file then
  stays on disk and the reload fails.
- A changed static zone needs a greater serial than the zone file it
  replaces; the role installs it anyway, and secondaries never transfer it.
- A missing dynamic zone file with a leftover journal, a static zone file
  that would change while a `.jnl` exists next to it, and a managed path that
  is not a regular file (a symlink, a directory) are refused while planning,
  before any change.
- The apt cache is refreshed only before an install (the role refreshes it on
  every run).
- Stricter values (each is rendered verbatim into the configuration): no
  control characters, zone and key names from a fixed character set, known
  zone types and HMAC algorithms, a zone `file` that is one file name below
  its directory (an absolute path only for transfer-backed zones), base64
  secrets. Static zones may share a file; a dynamic or transfer-backed zone
  may not.
- Debian-family hosts with systemd only.
- A deploy that dies after the transaction and before the reload is not
  noticed by the next run (files already current); `rndc reload` by hand, as
  with the role.

## Tests

- `tests/test_infra_bind_parity.py`: byte parity with files Ansible
  (ansible-core 2.21) rendered from the role's templates for four input sets
  (`tests/parity/bind_authoritative_deploy/<case>/`: defaults, a primary with
  dynamic zone and keys on Debian 13, a secondary on Debian 12, string ACLs
  and moved paths); with `OPS_LIBRARY_PATH`, the defaults, task order and
  seed semantics against the role.
- `tests/test_infra_bind.py`: the deploy on the fake connector (converged,
  fresh, rotated key, attributes, dynamic zone never planned, refusals,
  secrets only on stdin, no keys, secondary, verify, UFW, Debian 13).
- `tests/test_infra_bind_host.py`: the host script on temp trees with
  stand-in checkers (rollback by bytes and inode, withheld key output, serial
  rule, seed rules, lock, symlink refusal).
- `tests/test_infra_bind_docker.py`: real named 9.18, `named-checkconf`,
  `named-checkzone`, `nsupdate` and `rndc` in an owned systemd container,
  skipped unless `BIND_DOCKER_CONTAINER` holds the full ID of a running
  container named `ops-deploy-bind-20261021`, labelled
  `ops-deploy.fixture=bind-systemd` and `ops-deploy.run=bind-20261021`, with
  `--network none`, not privileged, `--cgroupns private`, `SYS_ADMIN` as the
  only added capability, no mounts, ports or devices and systemd as PID 1.
  Built from `ubuntu:24.04` with `systemd systemd-sysv python3 python3-apt
  ansible-core bind9 bind9-utils dnsutils ca-certificates`, `named.service`
  enabled and the packaged `/etc/bind` copied to `/opt/bind-pristine` (the
  test's reset), `--tmpfs /run --tmpfs /run/lock`, AppArmor unconfined and an
  entry point that remounts its cgroup2 tree writable before `exec
  /sbin/init`. It covers a first run (validate, install, reload, every zone
  answering `aa`) and a second run without a change or reload (named's
  `rndc status` "last configured" time); a TSIG-signed `nsupdate` to the
  dynamic zone plus `rndc sync`, after which a converged run and a run with
  a changed seed leave the zone file, its journal (bytes, inode, mtime) and
  serial untouched, and a static change reloads without touching them; a
  configuration `named-checkconf` rejects, rolled back without a reload; an
  unbumped serial and a lone journal refused without a change; a secondary
  configuration; and with `OPS_LIBRARY_PATH` the role (`bind_packages: []`,
  the fixture has no network) and this deploy taking turns without a change
  or a reload.
