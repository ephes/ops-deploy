# Persistent disk policy, Sanoid and Samba

These four Linux/apt/systemd APIs port `hdparm_tune`, `sanoid`,
`samba_timemachine` and `samba_share` from ops-library `cf3a0c74`.
`infra.hd_idle` (idle spindown) is new, with no ops-library counterpart.
They configure existing storage. They do not create pools, datasets or backups,
prune data, recursively change permissions, remove accounts or prune snippets.

## Persistent hdparm policy

```python
from ops_deploy.infra.hdparm_tune import HdparmDevice, HdparmTuneConfig, deploy_hdparm_tune

deploy_hdparm_tune(
    cfg=HdparmTuneConfig(
        devices=(HdparmDevice(device="/dev/disk/by-id/owned-disk", apm=127, spindown_time=241),),
        apply_now=True,
    )
)
```

`devices` defaults to empty; `apply_now` defaults to false. Each device requires
at least one setting: APM 1–255, spindown 0–253, or acoustic management 0–254.
Paths must be below `/dev` without parent segments. The named Ansible block in
`/etc/hdparm.conf` retains its original markers and unowned surrounding text.

**Convergence change:** `apply_now=True` applies settings only after an actual
owned block change. An unchanged block issues no physical setting command and
never queries or attests hardware state. The original command order remains all
APM, then all acoustic settings, then all spindown settings. A write followed by
failed or interrupted physical application is nontransactional: a later
unchanged deploy cannot establish that the drive accepted the policy. Retain the
explicit legacy Ansible play for deliberate physical reassertion/recovery. Such
a reassertion can wake drives and is separate from a no-change deployment.

### Boot apply unit

`/etc/hdparm.conf` alone does not survive a reboot on every disk. Ubuntu's udev
hook (`/lib/udev/hdparm`) hands APM (`-B`) and spindown (`-S`) to
`/usr/lib/pm-utils/power.d/95hdparm-apm`, which applies them only when udev sets
`ID_ATA_FEATURE_SET_APM=1`. Fractal's WD120EFGX disks get only `ID_ATA=1`, so
after every reboot they ran at factory APM 128 with no standby timer and never
spun down. Like ops-library `29b353c4`, the deploy therefore installs:

- `/usr/local/sbin/hdparm-tune-apply` (root, 0755): waits up to
  `boot_device_wait_sec` seconds for each device node, then runs
  `hdparm -B -M -S` (only the configured settings) per device. A missing device
  or a failing call is logged and makes the unit fail; the other devices are
  still applied.
- `/etc/systemd/system/hdparm-tune.service` (root, 0644): `Type=oneshot`,
  `RemainAfterExit=yes`, `After=local-fs.target`, `WantedBy=multi-user.target`.

The deploy reloads systemd when the unit changed and **enables** the unit. It
never starts or restarts it, so a deploy wakes no disk; immediate application
stays with `apply_now`. Both files are byte-equal to the role's templates.

| Setting | Default |
| --- | --- |
| `apply_on_boot` | true; `False`, or an empty `devices`, disables the unit if present and removes unit and script |
| `boot_service_name` | `hdparm-tune.service` |
| `boot_script_path` | `/usr/local/sbin/hdparm-tune-apply` |
| `boot_device_wait_sec` | 60 |

**Standby timer on fractal's disks:** on 2026-11-03 the WD120EFGX drives
ignored the standby timer. With APM 127 and `-S 120` and no I/O they were
still active/idle after 11.5 minutes; only an explicit `hdparm -y` spins them
down (fractal's quiet-hours hook and post-replication scripts). So
`spindown_time` has no effect on these drives. The boot unit still restores APM
127 and the configured state after a reboot. The idle-based spindown is the
separate `infra.hd_idle` deploy ([below](#idle-spindown-with-hd-idle)).

The unit requires a systemd host. To apply the settings by hand without a
reboot, run `systemctl restart hdparm-tune.service` (`restart`, because the unit
stays active after boot) and check the result with
`journalctl -b -u hdparm-tune.service`; this can wake standby disks.

## Idle spindown with hd-idle

```python
from ops_deploy.infra.hd_idle import HdIdleConfig, HdIdleDisk, deploy_hd_idle

deploy_hd_idle(
    cfg=HdIdleConfig(
        disks=(HdIdleDisk(device="/dev/disk/by-id/ata-owned-disk", idle_time=1800),),
    )
)
```

For drives that ignore the ATA standby timer (above), `infra.hd_idle` spins a
disk down after `idle_time` seconds without reads or writes in
`/proc/diskstats`. It configures the distribution's `hd-idle` package
(Ubuntu 24.04: 1.05+ds-2, the original C daemon; it has no `-c`/command
option and no symlink-policy option):

- `apt` installs `hd-idle` if missing (no upgrade).
- `/etc/default/hd-idle` (root, 0644) sets
  `HD_IDLE_OPTS="-i 0 -a <disk> -i <idle_time> ..."`. The package's own
  default is `-h` (print usage and exit), so nothing spins down until this
  file is written. The leading `-i 0` applies to every other `sd*` disk and is
  fixed: only the listed disks are ever spun down.
- `/etc/systemd/system/hd-idle.service.d/10-ops-deploy.conf` resets the
  unit's `EnvironmentFile=` to exactly `/etc/default/hd-idle` and adds
  `Wants=`/`After=` on each disk's `.device` unit (the `systemd-escape --path`
  name of its by-id link), so the daemon starts after the links exist.
- `hd-idle.service` is enabled and started; a config change restarts it, a
  drop-in change reloads systemd first. An unchanged deploy runs no command.

`disks` is required and nonempty; each `device` must be a whole-disk
`/dev/disk/by-id/` link (no `-partN`, no kernel name like `/dev/sda`), unique,
with `idle_time` of at least 60 s. There is no `absent` mode and no `-l`
logfile option (hd-idle calls `sync()` after logging a spin-up, which can wake
another disk).

**Kernel names.** hd-idle matches disks by their `/proc/diskstats` name. For
`-a`, 1.05 calls `readlink()` on the by-id link once at startup, strips
trailing digits and keeps the basename (`../../sda` → `sda`). The mapping is
therefore re-resolved on every service start, including every boot, so
`sdX` renames between boots are harmless. A rename while the daemon runs
(hot-unplug and replug) is not followed; restart `hd-idle.service`. If a link
is missing at start (its device job timed out), the name stays unresolved,
matches no disk, and that disk falls back to the global `-i 0`: it is
never spun down rather than a wrong disk.

**What hd-idle does to the disks** (source of 1.05+ds-2, `hd-idle.c`):

- Every `min(idle_time)/10` seconds (180 s for 1800) it reads
  `/proc/diskstats` and compares each `sd*` disk's completed reads and writes
  with its last sample. Startup only parses options, resolves the links and
  daemonizes; it opens no disk and queries no power state. A start or restart
  therefore wakes nothing; it only resets the idle clocks, so the first
  possible spindown is `idle_time` after the start.
- After `idle_time` with unchanged counters it calls `spindown_disk()` once and
  marks the disk spun down; it sends nothing more until the counters change
  again. `spindown_disk()` opens `/dev/<name>` read-only and issues SCSI
  START STOP UNIT with start=0 (`1b 00 00 00 00 00`) via `SG_IO`. Linux
  libata (6.8, `ata_scsi_start_stop_xlat` → `ata_dev_power_init_tf`)
  translates that into ATA STANDBY IMMEDIATE (`ATA_CMD_STANDBYNOW1`), the
  command `hdparm -y` sends. hd-idle never checks the power state first, so a
  disk that another tool already put into standby (and that saw no I/O since)
  gets one STANDBY IMMEDIATE. ATA defines that command for a drive in Standby
  as a transition to Standby without spin-up; this is the same command the
  quiet-hours hook would send without its `smartctl -n standby` precheck. It
  has not been tested on the WD120EFGX drives.
- `SG_IO` pass-through commands are not counted in `/proc/diskstats`
  (`blk_do_io_stat()` excludes pass-through requests). So `smartctl -n standby`,
  `hdparm -C` and hd-idle's own spindown neither reset hd-idle's idle clock nor
  look like I/O to it; only real reads and writes (ZFS) do.

Check it with `systemctl is-active hd-idle`, `ps -o args= -C hd-idle` and
`hdparm -C <by-id link>` (CHECK POWER MODE does not spin a disk up).

## Sanoid policy and timer

```python
from ops_deploy.services.sanoid import SanoidConfig, SanoidDataset, deploy_sanoid

deploy_sanoid(
    cfg=SanoidConfig(
        templates={"owned": {"autosnap": "yes", "autoprune": "yes", "daily": 7}},
        datasets=(SanoidDataset(name="owned/data", template="owned"),),
    )
)
```

Templates and datasets are required. Supported template options are
`autosnap`/`autoprune` (`yes` or `no`) and nonnegative integer `frequently`,
`hourly`, `daily`, `weekly`, `monthly`, `yearly` retention counts. Other native
Sanoid extensions, including hooks, are refused. Dataset rows accept `name`,
`template`, optional `autosnap`/`autoprune`, and `sanoid_skip`; skipped rows are
omitted and need no template reference. Template references remain bare names.

| Setting | Default |
| --- | --- |
| `enabled`, `manage_systemd`, `disable_package_timers` | true |
| `packages` | `("sanoid",)`; ensure present, do not upgrade installed packages |
| `config_path`, owner/group/mode | `/etc/sanoid/sanoid.conf`, root/root/0644 |
| `service_name`, `timer_name` | `sanoid-ops-library.service`, `sanoid-ops-library.timer` |
| `on_calendar`, `randomized_delay_sec` | `hourly`, `15m` |
| `executable`, `cron_args` | `/usr/sbin/sanoid`, `--cron` |

The deploy validates INI structure and candidate units before installation. It
manages only the timer, never manually invokes Sanoid/ZFS or starts its snapshot
oneshot for health checking. Only `sanoid.timer` and `sanoid-prune.timer` are
stopped/disabled if present; the packaged prune service is left alone. A small
root-owned restart-owed record survives interrupted file/reload/timer updates.
The record is `/var/lib/ops-deploy/sanoid/restart-owed.json` (root0600).
An exact retry recovers it even when file bytes are already current. The record
is not dataset-state attestation; changing its unit settings while debt remains
is refused. An unchanged deployment leaves the timer running without restart.

Native Sanoid `--readonly` is a fixture validation tool, **not a production
probe**: it queries ZFS and writes cache/run state. It does not prove physical
hardware behavior or retention/pruning correctness on production datasets.

## Samba Time Machine and batched shares

```python
from ops_deploy.core.secrets import SecretValues
from ops_deploy.services.samba_share import SambaShare, SambaSharesConfig, deploy_samba_shares


def deploy_owned(prepared_secrets: SecretValues) -> None:
    deploy_samba_shares(
        cfg=SambaSharesConfig(
            shares=(SambaShare(name="owned", path="/srv/owned", valid_users=("owned",)),),
            users=("owned",),
        ),
        secrets=prepared_secrets,
    )
```

`SambaTimeMachineConfig(users=(...))` and `deploy_samba_timemachine(cfg=..., secrets=...)`
use the same secret `users` JSON list. Time Machine requires a nonempty,
nonplaceholder password for every declared name, even if that account exists.
Generic accounts permit an empty password until the native inventory establishes
that an account is missing; a missing account then requires a nonempty password.
Only declared names and then only missing-account credentials reach host stdin.
The private caller remains responsible for requiring secret entries for every
share's `valid_users`. Passwords never belong in config, argv, environment or
logs. No decrypted file is written by these APIs.

Time Machine defaults retain `/fast/timemachine`, share `timemachine`, quota `6T`,
owner/group `timemachine` (UID/GID 2000), mode0770, browseable, SMB3 and the role's
`fruit_metadata="stream"`, `fruit_model="MacSamba"`, POSIX rename and Time Machine
mode enabled. Its directory must already exist. Optional `required_dataset`
adds the original caller's explicit native ZFS-name existence preflight; the
public default is none. This is a metadata query, not a no-I/O assertion.

The generic API accepts a nonempty batch of distinct `SambaShare` rows. Each row
requires `name` and `path`; defaults are browseable, writable, nonguest, no
`valid_users`, masks0660/0770, no forced user/group, no root metadata override and
no extra options. `path_owner`, `path_group`, `path_mode` affect only that root,
never descendants or ACL policy. `SambaSharesConfig.groups` (default none) lists
`SambaShareGroup(name=..., gid=...)` rows for groups the shares need, typically
for `force_group`: the deploy creates a missing one as a system group with that
gid (before any share is configured) and refuses, before any change, when the
name exists with another gid or the gid belongs to another group; an existing
group with that gid is left alone. Names and gids must be distinct. Extra options must be single lines and cannot
inject sections/includes, including whitespace aliases of include/copy/config
backend. Reserved global/globals/homes/printers section names are refused. Account management defaults to true with group
`sambashare`; Time Machine uses its dedicated group. Unix accounts always use
`create_home=False` **and** `ensure_home=False`; existing homes are not created
or chowned. Like both cf3 roles, account management **does** enforce
`/usr/sbin/nologin` even for an existing named Unix account, and appends its
configured group. This can remove a human account's interactive login shell;
review that declared policy and preflight existing identities before deploying.
The home guarantees do not imply that all Unix account metadata stays unchanged.
Existing primary-group membership does not trigger repeated usermod.

Both APIs default to Samba/VFS and native Python Samba/tdb packages, present
without upgrading installed versions. Common paths are `/etc/samba/smb.conf` and
`/etc/samba/smb.conf.d`; the Time Machine snippet defaults to
`/etc/samba/smb.conf.d/timemachine.conf`, generic snippets to `<name>.conf`.
The **generated missing-file base** defaults to workgroup `WORKGROUP`, minimum
protocol `SMB3`, disabled printing and the original role server string. These
fields do not enforce options in an existing smb.conf. The existence decision
happens after package installation, exactly like cf3: Ubuntu's samba-common
postinst creates its distro smb.conf, which is preserved as existing unowned
configuration, including its printing/guest/protocol choices. On that normal
fresh apt path, generated-base fields therefore do not override the package's
globals. A still-missing file uses the generated base. No packaged configuration
is replaced or relabeled as owned to make advertised defaults appear enforced. `service_enabled=True` and
`service_state="started"` manage both smbd/nmbd. Stopped/restarted are explicit
caller choices. The running path waits for loopback445 without a data operation.

Existing smb.conf globals/unowned includes and shares are preserved, except for
the global section repair below. A minimal
base is created only if missing. Candidate fragments and the complete candidate
are checked by native `testparm` before installation. Known config writes record
restart debt first; a failed/interrupted rollout keeps it for an exact retry at
`/var/lib/ops-deploy/samba/restart-owed.json` (root0600). Do not delete the debt
to manufacture a current result.
The whole batch gets one staged candidate-validation phase and one deduplicated
rollout, so each daemon restarts at most once. Installed config is also checked
after writes and before consuming restart debt.
**Reload for snippet-only changes:** when a batch changes only share snippets
and smb.conf itself is already current (no new include, global or fruit block
change; a change of only the managed `restrict anonymous` line counts as
current, see below), the debt record is `{"units": ["smbd", "nmbd"], "action":
"reload-config"}` and the rollout runs `smbcontrol all reload-config` instead
of restarting smbd/nmbd. Open sessions (a running Time Machine backup, mounted
shares) survive; new tree connects get the new share options, while a client
that is already connected to the changed share keeps the old ones until it
reconnects. A change to smb.conf records the plain restart debt (`{"units":
["smbd", "nmbd"]}`), a recorded restart debt is never downgraded to a reload,
an explicit `service_state="restarted"` still restarts, and any other record
is refused. Rolling the pin back to an ops-deploy before this change while a
reload record is still owed (a failed rollout): the older helper refuses that
record; replace it with the plain restart record (which only makes the next
rollout restart) rather than deleting it.
A current config/account/service deployment issues no managed command.

**Global section repair (include placement, guest settings):** the original
cf3 role inserts includes immediately after `[global]`, and its base template
also places one before later globals. Samba then parses every later global
line into the last included share section: global-only settings are ignored
(with a "Global parameter ... found in service section" warning) and share
settings become options of that share only. The config helper therefore moves
owned include lines, and every include whose operand lies directly in
`snippet_dir` (snippets of the other Samba deploy on the same host, the
distro-era `smb.conf.d/*.conf`), to the end of the textual `[global]` body,
directly before the next section header, in their existing order; new owned
includes follow them. Other includes and all other unowned lines keep their
place and bytes, with one exception: in `[global]`, `map to guest` with a value
other than `never` and `usershare allow guests = yes` are commented out
(`# ops-deploy: no guest access: <original line>`), because the managed shares
refuse guests and the distro defaults would otherwise start to apply once
`[global]` is parsed whole. An owned include that already sits in a later
section is left there and not duplicated. The managed vfs_fruit block in
`[global]` holds only fruit's global-only options (`fruit:model`,
`fruit:nfs_aces = no`); the share options (`vfs objects = fruit
streams_xattr`, `fruit:metadata`, `fruit:posix_rename`,
`fruit:veto_appledouble = no`, `fruit:wipe_intentionally_left_blank_rfork`,
`fruit:delete_empty_adfiles`) are appended to the Time Machine snippet, so a
host's other shares do not start loading vfs_fruit (which would also convert
their existing `._*` AppleDouble files). The block in `[global]` may only
hold those global-only options (`fruit:aapl`, `fruit:copyfile`,
`fruit:model`, `fruit:nfs_aces`): on a host from before this change the old
block still carries the share options, so every deploy other than
`samba_timemachine` (which rewrites the block) refuses with "managed fruit
block holds share options; deploy samba_timemachine first" instead of
promoting them to defaults for every share. Deploy `samba_timemachine` first
there; it repairs the whole file alone. Vendored templates retain original
source bytes; both refinements happen in the helper and in
`samba_timemachine.render.snippet`. On an installed file with the old order
the first deploy rewrites smb.conf and restarts smbd and nmbd once.

**Anonymous access (`restrict anonymous`):** `SambaBaseConfig.restrict_anonymous`
(both APIs; `0`, `1` or `2`, default `2`) is written as `restrict anonymous =
<value>` directly after the `[global]` header, before every include, so it is
always parsed as a global. `2` refuses anonymous (null session) access,
including the anonymous share list (`smbclient -L <host> -N`); authenticated
listing and access are unchanged. An existing line is used only when it is
the single `restrict anonymous` line in `[global]` and no include precedes it:
it is kept, or rewritten in place when its value differs (so value changes add
no lines). Otherwise every such line in `[global]` is commented out (`#
ops-deploy: managed global replaces: <original line>`) and the managed line is
inserted. Lines in share sections are left alone. Samba applies the
setting on `smbcontrol all reload-config`, so an smb.conf change that touches
only managed global lines records the reload debt, not a restart (open
sessions such as a running Time Machine backup survive); together with any
other smb.conf change it still restarts. `SambaSharesConfig` refuses a
guest share (`guest_ok`, or `guest ok`, `public` or `guest only` set to yes
in `extra_options`) while `restrict_anonymous` is `2`. The setting applies to the
whole host, but both APIs enforce it on every deploy: on a host with both
`samba_timemachine` and `samba_share`, give both the same value. Different
values are not detected; each deploy would rewrite the line (and owe a reload)
to its own value, and a `samba_share` guest share admitted with a lower value
would be refused anonymous access again by the next Time Machine deploy at the
default `2`.

### Existing credentials and native creation limits

The qualified backend is native **tdbsam**, Samba4.19 with current schema4.0.
The complete inventory reads names/flags and validates the schema before an
existing native backend is opened; tool, schema, corrupt DB or incomplete
inventory failures cannot masquerade as account absence. Existing passwords are
neither read/exported for comparison nor rotated; disabled accounts stay disabled.

Missing accounts use native `PDB.add_sam_account`, which refuses duplicate
insertion. A complete native SAMU is created in an isolated child using a private
0700 ephemeral tmpfs directory/0600 candidate DB and stdin password. SAM material
passes only through private pipes, is checked for canonical roundtrip, and is
inserted with the existing machine SID plus a newly allocated RID. There is no
actual-backend `pdbedit -a`, update or separate enable operation. The upstream
`pass_must_change_time` property is derived and has no working setter; its
roundtrip is still checked. Isolation also avoids Samba's cached backend handle.

Serialization covers our invocations; the native add-only primitive also refuses
a concurrent external creation rather than replacing its credential. RID
allocation is nontransactional: failed/racing creation can consume a RID. This
is managed failed-create activity, not read-only/global-zero-write work. A
missing/damaged machine identity is refused before native backend construction:
only its known public SID record is opened read-only and validated, then native
SID equality is checked in memory before insertion. Mere secrets.tdb existence
is insufficient; no credential record or SID content is exported.

### Qualification boundary

Owned Ubuntu24 ARM fixtures use matching hdparm9.65, Samba4.19.5, Sanoid2.2.0 and
real loaded ZFS2.2.2 with a file-vdev pool. Tests cover configuration, native parser,
accounts, synthetic loopback SMB access/masks and interrupted rollouts. ARM fixture
results do not attest physical SATA/APM behavior or production AMD64/share state.
Inventory deployment and protection receipts are separate operator gates.
The hdparm boot unit is covered by an Ansible template oracle, fake-host
rollouts and a local run of its script with a stub `hdparm`; no fixture boots it.
