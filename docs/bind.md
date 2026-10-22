# BIND

`ops_deploy.infra.bind` ports the `bind_authoritative_deploy` role (deploy
only; checked against ops-library main `06394c81`, 2.64.5): an authoritative
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
| `config_dir`, `working_dir`, `dynamic_zone_dir` | `/etc/bind`, `/var/cache/bind`, `/var/lib/bind` | static zones, transfer-backed zones and dynamic zones live there; the deploy refuses other values (see [Paths and zone files](#paths-and-zone-files)) |
| `builtin_zones_file` | `None` | `None`: the role's choice, `named.conf.root-hints` on Debian 13 and later, else `named.conf.default-zones` (read from `/etc/os-release`, as Ansible's facts are); the deploy refuses a set value |
| `zone_files_dir` | required | controller directory with the zone files (the role's default derives it from the playbook directory) |
| `config_owner`, `config_group`, `config_mode`, `service_user` | `root`, `bind`, `0644`, `bind` | |
| `zone_default_type`, `zone_transfer_backed_types` | `master`, `slave`/`secondary` | |
| `zones` | required, at least one | `name`, `file`, optional `type`, `dynamic`, `primaries`, `update_policy`, `allow_transfer`, `extra_config` (lists rendered verbatim, joined with `; `) |
| `recursion`, `recursion_acl`, `allow_query`, `allow_query_cache`, `allow_transfer`, `dnssec_validation` | `True`, `localhost`/`localnets`, `any`, `recursion_acl`, `none`, `auto` | |
| `listen_on`, `listen_on_v6`, `extra_options` | `()`, `any`, `()` | |
| `verify_enabled`, `verify_server`, `verify_zone_types`, `verify_retries`, `verify_delay` | `True`, `127.0.0.1`, master/primary/slave/secondary, `12`, `5` | the `dig` check |
| `firewall_check_enabled` | `True` | UFW warnings |
| `tsig_keys`, `tsig_keys_file`, `tsig_keys_mode` | `()`, `<config_dir>/named.conf.keys`, `0640` | key `name` and `algorithm` (default `hmac-sha256`); the secrets are the deploy's second argument; the deploy refuses another key file |

The role's `validate.yml` assertions are config validation here: at least one
zone, non-empty `primaries` for transfer-backed zones, `dynamic` only on
`master`/`primary` zones with a non-empty `update_policy`, a non-empty
`allow_transfer`, and (while planning) every controller zone file present.

### Paths and zone files

`BindConfig` takes the role's paths as the role does (the templates render
them), but the deploy only writes into the role's default layout. Before it
contacts the host it refuses:

- a `config_dir`, `working_dir` or `dynamic_zone_dir` other than `/etc/bind`,
  `/var/cache/bind` and `/var/lib/bind`, a `tsig_keys_file` other than
  `/etc/bind/named.conf.keys` and any `builtin_zones_file` (a host with
  another layout stays on the role);
- a zone `file`, of any zone type, that is not `db.` followed by
  dot-separated labels of letters, digits, `-` and `_` (Debian's naming, as in
  `db.example.org` or `db.192.0.2`), that another zone uses too, that holds
  `.jnl`, or that is one of the `bind9` package's own zone files in
  `/etc/bind` (`db.0`, `db.127`, `db.255`, `db.empty`, `db.local`, which its
  builtin zones load). An absolute `file`, which the role allows for a
  transfer-backed zone, is refused as well.

So every file the deploy writes or removes is one of the four `named.conf`
files in `/etc/bind`, a static zone file there, or a dynamic zone file it
seeds (and never replaces) in `/var/lib/bind`; no two of them can be the same
file, and none of them is the builtin zones file, a staged
`.ops-deploy-new.*` file, a journal, `rndc.key`, `bind.keys` or a zone file of
the package.

## Steps

The steps follow the role's order and do what it does. The files are compared
and installed by one small bash script, `files/bind_config.sh`, run as root
with `bash -c` (paths, owners, modes and sizes as arguments, the file
contents as base64 lines on stdin). It uses standard tools only: `cmp`,
`stat`, `named-checkzone`, `named-checkconf`, `install`, `mv`, `ln`. Before
any of the steps, the paths and zone file names are checked (see
[Paths and zone files](#paths-and-zone-files)).

1. A read-only probe (`bind_config.sh probe`) decodes the candidates into a
   private directory under `/run` and compares each with the installed file
   (content, owner, mode). It prints the files that would change, staged
   files a killed run left behind, refusals (below) and `reload-pending`. When
   files would change and BIND is installed, it also runs the checks of
   step 3, so a configuration named would reject fails while planning. A
   dynamic zone's file and journal are only looked up, never read or compared.
2. Missing packages are installed (apt cache refreshed first). `config_dir`
   `root:bind 0755`, `working_dir` (with transfer-backed zones) and
   `dynamic_zone_dir` (with dynamic zones) `bind:bind 0775`, special bits
   cleared as Ansible's `file` does.
3. Only when the probe found a difference: `bind_config.sh apply` (the same
   input again, under an `flock` on `config_dir`) compares once more, then
   checks every candidate before it touches a file:
    - `named-checkzone <zone> <file>` for each changed static zone and each
      seed (the role's `validate`), and a serial greater (RFC 1982) than the
      installed file's for a changed static zone;
    - `named-checkconf -t <tree> <config_dir>/named.conf` on a copy of
      `config_dir` (and the key file) under `/run` with every candidate in
      place and a retired key file removed. `-t` chroots, so the absolute
      `include`s of `named.conf` resolve inside the copy.
   Any refusal or failed check fails the step: nothing was changed and named
   is not reloaded. Otherwise each changed file is written next to its
   destination (`.ops-deploy-new.<name>`, with `install`: owner and mode) and
   renamed into place (`mv`), in the role's order (keys, options, local,
   zones, seeds, `named.conf`); a seed is linked in with `ln`, which never
   replaces a file, and a key file that is no longer wanted is removed last.
4. named enabled and running; `systemctl reload named` (under the same
   `flock` on `config_dir`, so named never loads the tree while another run
   renames files) when step 3 ran for a change, or when the probe printed
   `reload-pending`.
5. Read-only `dig @<verify_server> <zone> SOA +comments +norecurse` per
   authoritative zone (`verify_zone_types`) until it answers `NOERROR` with
   the `aa` flag (`verify_retries` × `verify_delay`). UFW warnings as in the
   role (inactive, or active without a 53 rule).

A converged host plans no mutating operation: the probe, and the `dig` checks
(read-only).

There are no backups and no rollback. Everything is checked before the first
rename, so a configuration named rejects is never installed. If a rename
itself fails (a full disk, an I/O error) or the run is killed between renames,
the files installed so far stay (each was checked as part of the whole set),
named is not reloaded, and the next run installs the rest; the role leaves
the same state behind. The script removes its staged files when it exits; a
staged file a killed run left (`SIGKILL`, a lost connection) is reported by
the probe and removed by the next run, which then installs or does nothing.

`reload-pending` replaces the role's handler for a run that ended after its
files and before its reload: when named is running, the probe compares the
modification times of the installed configuration and static zone files with
named's last configuration load (`rndc status`, "last configured", whole
seconds) and plans a reload if one is newer. So that a file installed in the
same second as that load still counts as newer, the install step waits for
the next second before it writes (two seconds at most: a clock behind named's
last load, as after the clock was set back, is refused before any change;
restarting named, or waiting, clears it). It keeps no state of its own. The
staged files are shared between runs: only the run holding the lock removes
them.

## Dynamic zones

A zone with `dynamic: true` takes RFC 2136 updates (ACME DNS-01 TXT records,
DDNS); named writes them to `<file>.jnl` and periodically back into the zone
file, and bumps the serial. The controller file is only a seed:

- An existing dynamic zone file is never read, compared, replaced, chowned or
  chmodded, whatever it contains, and its journal is never touched (the
  role's `copy` with `force: false`). The deploy never resets its serial.
- It is seeded (`bind:bind 0644`, after `named-checkzone`) only when neither
  the file nor its journal exists. The seed is linked in with `ln`, which
  never replaces a file that appeared meanwhile.
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
is the only file that holds them; it travels on the probe's stdin (pyinfra
logs it as `<stdin redacted>`) and on the install step's (through
`secret_stdin`; the operation's arguments show `SecretContent(<redacted>)`).
On the host it is decoded into the script's private `0700` directory under
`/run` (a tmpfs) and compared with `cmp`; the probe answers only whether the
file would change. No secret and no digest of one is printed, put on a
command line or in an operation's arguments. Lines of `named-checkconf`
output that name the keys file are withheld (a parse error can quote part of
a secret).

## Differences from the role, on purpose

- Every candidate is checked before any file changes, with `named-checkconf`
  on the whole configuration. The role writes `named.conf.options` and
  `named.conf.local` unvalidated and checks them only through `named.conf`'s
  `validate`, which does not run when `named.conf` itself is unchanged; a
  broken file then stays on disk and the reload fails.
- Refusals, before any change: a changed static zone whose serial is not
  greater than the installed file's (the role installs it, and secondaries
  never transfer it); a missing dynamic zone file with a leftover journal
  (the role would seed it, and named would refuse the zone); a static zone
  file that would change while a `.jnl` exists next to it; a managed path
  that is not a regular file (a symlink, a directory).
- Only the role's default paths, and zone files that are `db.*` names of
  their own (see [Paths and zone files](#paths-and-zone-files)); the role
  writes wherever its variables point, also one static file for several
  zones.
- A run that ended after its files and before its reload is followed by a
  reload on the next run (`reload-pending`); the role's handler is lost then
  and needs `rndc reload` by hand.
- The apt cache is refreshed only before an install (the role refreshes it on
  every run).
- Stricter values (each is rendered verbatim into the configuration): no
  control characters, zone and key names from a fixed character set, known
  zone types and HMAC algorithms, a zone `file` that is one file name below
  its directory (an absolute path only for transfer-backed zones), base64
  secrets.
- Debian-family hosts with systemd, `bash` and `/run` only; the checks need
  root (`named-checkconf -t` chroots). An `include` in `extra_options` or
  `extra_config` must point into `config_dir` or the check fails.

## Tests

- `tests/test_infra_bind_parity.py`: byte parity with files Ansible
  (ansible-core 2.21) rendered from the role's templates for four input sets
  (`tests/parity/bind_authoritative_deploy/<case>/`: defaults, a primary with
  dynamic zone and keys on Debian 13, a secondary on Debian 12, string ACLs
  and moved paths; rendered from ops-library `56564cce`, whose role is
  unchanged up to `06394c81`); with `OPS_LIBRARY_PATH`, the defaults, task
  order and seed semantics against the role.
- `tests/test_infra_bind.py`: the deploy on the fake connector (converged,
  fresh, changed file, refusals, `reload-pending`, leftovers, secrets only on
  stdin, fish-safe command lines, no keys, secondary, verify, UFW, Debian 13,
  other paths and zone file names refused before the host is contacted) and
  the config validation.
- `tests/test_infra_bind_docker.py`: real named 9.18, `named-checkconf`,
  `named-checkzone`, `nsupdate` and `rndc` in an owned systemd container,
  skipped unless `BIND_DOCKER_CONTAINER` holds the full ID of a running
  container named `ops-deploy-bind-20261022`, labelled
  `ops-deploy.fixture=bind-systemd` and `ops-deploy.run=bind-20261022`, with
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
  configuration `named-checkconf` rejects, neither installed nor reloaded,
  with nothing left under `/etc/bind`, `/var/lib/bind` or `/run`; the host
  script refusing a broken key stanza with the message withheld; a missed
  reload made by the next run, also one in the second of named's last load;
  only the lock holder removing staged files; a symlinked directory in
  `/etc/bind` never written; a clock behind named's last load refused before
  any change; an unbumped serial and a lone journal refused without a change;
  removing the keys; a secondary configuration; and with
  `OPS_LIBRARY_PATH` the role (`bind_packages: []`, the fixture has no
  network) and this deploy taking turns without a change or a reload.
