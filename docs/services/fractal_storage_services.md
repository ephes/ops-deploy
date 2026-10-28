# Persistent disk policy, Sanoid and Samba

These four Linux/apt/systemd APIs port `hdparm_tune`, `sanoid`,
`samba_timemachine` and `samba_share` from ops-library `cf3a0c74`.
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
APM, then all acoustic settings, then all spindown settings. Existing package
boot/udev/resume hooks remain responsible for their native lifecycle reassertion.
No marker, timer or hardware-state cache is added. A write followed by failed or
interrupted physical application is nontransactional: a later unchanged deploy
cannot establish that the drive accepted the policy. Retain the explicit legacy
Ansible play for deliberate physical reassertion/recovery. Such a reassertion
can wake drives and is separate from a no-change deployment.

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
never descendants or ACL policy. Extra options must be single lines and cannot
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

Existing smb.conf globals/unowned includes and shares are preserved. A minimal
base is created only if missing. Candidate fragments and the complete candidate
are checked by native `testparm` before installation. Known config writes record
restart debt first; a failed/interrupted rollout keeps it for an exact retry at
`/var/lib/ops-deploy/samba/restart-owed.json` (root0600). Do not delete the debt
to manufacture a current result.
The whole batch gets one staged candidate-validation phase and one deduplicated
rollout, so each daemon restarts at most once. Installed config is also checked
after writes and before consuming restart debt.
A current config/account/service deployment issues no managed command.

**Fresh include placement exception:** the original cf3 role inserts includes
immediately after `[global]`, and its base template also places one before
later globals. Samba can keep parsing in the last included share section;
later globals then produce warnings or lose their intended scope. New includes
are placed at the end of the textual global body before its next explicit
section. Only the generated include in a newly created base is relocated.
Already-existing includes and their byte order are never rearranged, including
on a current installation. Vendored templates retain original source bytes;
this documented refinement happens during candidate reconciliation.

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
