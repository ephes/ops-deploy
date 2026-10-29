# Base deploys

`ops_deploy.base` ports the base/bootstrap roles of ops-library. Each is a
typed config plus a `@deploy` function. Some are run on their own against a
host (hostname, unit masks, headless mode, journald, shell basics, authorized keys,
SSH guard, dpkg foreign architectures, stale binary restart), the others are
steps a service deploy calls (uv, Node.js):

```python
from ops_deploy.base import HostnameConfig, deploy_hostname

deploy_hostname(HostnameConfig(hostname="web-1"))
```

They are deploys, not shared helpers, so they live outside the size-capped
helpers/ops/core layer ([development](development.md#size-cap-on-the-shared-layer)).
The configs reject unknown keys and are frozen, like service configs, but they
carry no secrets and do not derive from `BaseServiceConfig`. Everything they
check (OS, architecture, installed versions, unit states) is read while
planning, so `--dry` shows the real plan and a converged host reports no
change.

| Module | Role | Config | Deploy |
|---|---|---|---|
| `hostname` | `hostname_set` | `HostnameConfig` | `deploy_hostname` |
| `headless_mode` | `headless_mode` | `HeadlessModeConfig` | `deploy_headless_mode` |
| `systemd_unit_masks` | `systemd_unit_masks` | `SystemdUnitMasksConfig`, `UnitMask` | `deploy_systemd_unit_masks` |
| `journald_config` | `journald_config` | `JournaldConfig` | `deploy_journald_config` |
| `ssh_authorized_keys` | `ssh_authorized_keys_manage` | `SshAuthorizedKeysConfig`, `AuthorizedKey` | `deploy_ssh_authorized_keys` |
| `uv_install` | `uv_install` | `UvInstallConfig` | `deploy_uv_install` |
| `nodejs_install` | `nodejs_install` | `NodejsInstallConfig` | `deploy_nodejs_install` |
| `shell_basics` | `shell_basics_deploy` | `ShellBasicsConfig` | `deploy_shell_basics` |
| `ssh_guard` | `ssh_guard_deploy` | `SshGuardConfig` | `deploy_ssh_guard` |
| `dpkg_arch_remove` | `dpkg_arch_remove` | `DpkgArchRemoveConfig` | `deploy_dpkg_arch_remove` |
| `stale_exe_restart` | none (pyinfra only) | `StaleExeRestartConfig`, `StaleExeUnit`, `StaleExeHttpProbe` | `deploy_stale_exe_restart` |

Field names follow the role variables without the role prefix
(`headless_mode_apply_now` is `apply_now`). Defaults are the role defaults
unless noted below.

## hostname

`hostname` (required; letters, digits, `.`, `_`, `-`, not starting with a
symbol). On Linux, runs `hostnamectl set-hostname` when `uname -n` differs.
On Darwin, compares `HostName`, `ComputerName` and `LocalHostName` through
`scutil`; if any differs it sets all three like Ansible's Darwin strategy.
The Bonjour name uses that strategy's scrub transformation (dots removed,
underscores replaced with hyphens, repeated hyphen pairs removed).
An unchanged native deployment writes no files and issues no setter command.

The role defaults to the inventory host name; callers must pass the intended
machine name explicitly when an inventory alias differs. Native operations
use the caller's existing privileged connection or standard sudo context;
this API does not provision SSH access or alter login policy.

## headless_mode

| Field | Default | |
|---|---|---|
| `default_target` | `multi-user.target` | must end in `.target` |
| `display_manager_service` | `""` | e.g. `gdm3`; a name without suffix is a `.service` |
| `disable_services` | `()` | more units to disable |
| `apply_now` | `True` | also stop them now |

Fails on a host whose PID 1 is not systemd, and on a unit systemd does not
know (as the role's `systemd_service` does). Unit state is read per requested
name, so an alias such as `gdm3` (for `gdm.service`) is handled. A `static`
unit is stopped but not disabled (there is nothing to disable).

## systemd_unit_masks

| Field | Default | |
|---|---|---|
| `units` | `()` | `UnitMask(unit=..., reason=...)`; the unit needs its type suffix |
| `unmask` | `()` | units to unmask (must not also be in `units`) |
| `stop_now` | `True` | stop a running unit before masking it |
| `reset_failed` | `True` | clear a `failed` state left on a masked unit |

A unit already masked persistently and not failed is left alone (a
`masked-runtime` unit still gets the persistent mask). A unit that is running is
stopped (a failing stop is ignored, as in the role), masked and its failed
state cleared; one that is in the failed state gets `reset-failed`.
`systemctl mask` (and so the deploy, like the role) fails for a unit whose
file lives in `/etc/systemd/system`; masking is for packaged units.

## journald_config

| Field | Default | journald key |
|---|---|---|
| `state` | `present` | `absent` removes the drop-in |
| `dropin_path` | `/etc/systemd/journald.conf.d/60-ops-library.conf` | a `*.conf` file directly in that directory |
| `storage` | `persistent` | `Storage=` (`persistent`, `volatile`, `auto`, `none` or empty) |
| `system_max_use`, `system_keep_free`, `system_max_file_size` | `""` | `SystemMaxUse=` etc.: a byte count with an optional `K`..`E` suffix (`16G`, `1.5G`) |
| `system_max_files` | `""` | `SystemMaxFiles=`: a non-negative integer (`0` turns the limit off) |
| `max_retention_sec`, `max_file_sec` | `""` | `MaxRetentionSec=`, `MaxFileSec=`: a systemd time span (`21day`, `1w 2d12h`) |
| `extra_settings` | `{}` | further `[Journal]` keys in the given order; booleans render as `yes`/`no` |
| `restart_on_change` | `True` | restart journald (and flush) when the drop-in changed |

Writes one drop-in, `root:root 0644` in a `root:root 0755` directory,
byte-identical to the role's template (including its `# Managed by Ansible`
header), so taking a host over from the role rewrites nothing and restarts
nothing. An empty setting writes nothing for its key. Size and age limits are
whatever the caller passes; the deploy never vacuums or deletes journal
files itself (journald does, at the restart or the next rotation, when a
lower limit is applied).

journald has no reload. As with the role's handlers, `systemctl restart
systemd-journald` runs only when the drop-in was written, changed owner or
mode, or was removed, and `journalctl --flush` follows only a written drop-in
with `storage="persistent"` (it moves a journal that lived in `/run` to
`/var/log/journal`). A converged host gets neither: the running journald keeps
its PID. A read-only check then requires `systemctl is-active
systemd-journald` to print `active` (reported separately, see
[read-only checks](concepts/helpers.md)). Hosts whose PID 1 is not systemd are
refused.

A symlink at the drop-in path is replaced by the regular file (present) or
unlinked (absent), never followed, as the role's `template` and `file:
state=absent` do; its target is left alone. Anything else at the path (a
directory, FIFO, socket or device), or a drop-in directory that is not a
directory (a symlink included), is refused before any change, where the role
would write into the directory, delete a directory tree or follow the link.
The file types are read with `stat` in the C locale, so a host with a
non-English locale is handled the same way.

Values are checked when the config is built, before any operation, with the
role's patterns and only for `state="present"`, as in the role: with
`state="absent"` the settings are dropped unchecked (they are not used), while
`dropin_path` is still checked. Numbers from YAML (`system_max_files: 2000`)
are accepted as their text. Two deliberate differences: a value or extra key
ending in a newline (which the role's Python `$` lets through) is refused, and
so is a control character in `dropin_path`. Extra values are written literally
(Ansible would first expand Jinja in them). An extra key that a field already
covers (`SystemMaxUse`) is refused, as in the role.

## ssh_authorized_keys

| Field | Default | |
|---|---|---|
| `user` | `root` | |
| `group` | the user's name | |
| `home` | `/root` or `/home/<user>` | |
| `entries` | required, at least one | `AuthorizedKey(key, comment="", key_options="")`, each on one line |

Owns the **whole** `~/.ssh/authorized_keys` file: keys not in `entries` are
removed. An empty key list (or a blank key) is refused when the config is
built, so the deploy can never write a file without keys. The content is byte-identical to the role's template (including its
`# Managed by Ansible` header), so switching tools rewrites nothing. The file
is installed with [`secret_file`](concepts/operations.md) (stdin, temp file,
rename) although keys are public: the rename means an interrupted run never
leaves a truncated file that locks the operator out. The role's
`ssh_authorized_keys_manage_enabled` switch is not ported: do not call the
deploy instead.

## uv_install

| Field | Default | |
|---|---|---|
| `version` | `0.13.5` | change together with `checksums` |
| `checksums` | the role's sha256 for x86_64 and aarch64 Linux | keyed by release target |
| `install_dir` | `/usr/local/bin` | not `/` |
| `owner`, `group` | `root` | |
| `update_existing` | `True` | replace another installed version |
| `force_reinstall` | `False` | |
| `darwin` | `False` | explicitly select the native Darwin branch |

Installs when `uv` or `uvx` is missing, `uv` is a symlink, is another version (with
`update_existing`) or `force_reinstall` is set. One shell step downloads the
release archive into a private temp directory with `curl`, checks the sha256,
unpacks it and renames `uv`/`uvx` into place, then runs `uv --version`. `curl` is installed with apt first when missing.
The default path and commands remain Linux-only. `darwin=True` explicitly
selects the native Darwin installer; callers must supply the selected native
version, matching `aarch64-apple-darwin`/`x86_64-apple-darwin` checksums, and the
native ownership (normally `root:wheel`). The Mac application roles select
`0.13.5`; Linux defaults now select the same release with their own checksums.
The Darwin branch uses the target's `/usr/bin/python3`, verifies the archive
and both staged executables before publication, and retains the installed
binaries when validation fails. An already-current installation creates no
download, staging directory, chmod or home-directory change. It replaces legacy
binary symlinks when installation is selected; it does not convert Homebrew's
separate prefix. The role's deprecated `uv_create_symlinks`/`uv_symlink_dir`
are not ported.
Planning (`pyinfra-check`) only reads, which matches the role's `--check`
since ops-library 2.48.2: a host with the pinned version plans no step, a
pending install or update shows as the one install step.
`tests/parity/ops_library_roles.json` records the role (`uv_install`, checked
against ops-library main `540ede2b`, 2.56.0).
[homelab](services/homelab.md) and [graphyard](services/graphyard.md) run it
only when their `uv` field is set.

## nodejs_install

| Field | Default | |
|---|---|---|
| `major` | `24` | NodeSource release line |
| `key_url` | NodeSource's key | `https://` only |
| `keyring`, `sources_list`, `preferences` | the role's paths | |

Installs `ca-certificates`, the NodeSource key (downloaded once), a one-line
sources list and the apt pin for `nodejs`, and installs `nodejs=<major>.*`
(after `apt-get update`, downgrades allowed) when the installed package is
not from that line. A read-only check then requires `/usr/bin/node` to be
`v<major>.x` and `npm` to run; it shows as changed on every run and is
reported separately ([read-only checks](concepts/helpers.md)). Debian-family
hosts only.

The `fastdeploy` service (like its role) writes the same sources list with a
different keyring path when Node.js is missing or too old; whichever runs
last owns the file.

## shell_basics

| Field | Default | |
|---|---|---|
| `user` | `root` | must exist |
| `user_home` | from `/etc/passwd` | |
| `shell_path` | `/usr/bin/fish` | |
| `packages` | the role's list | `extra_packages` adds more |
| `switch_shell` | `True` | `usermod -s`, after checking the shell exists on the host |
| `manage_fish_config` | `True` | `fish_extra_config` lines go into the block |
| `manage_chezmoi` | `True` | `chezmoi_version` `2.73.1`, `chezmoi_install_dir` `/usr/local/bin`, `chezmoi_checksums` |
| `apt_cache_valid_time` | `3600` | |
| `fix_resolv_conf` | `True` | `resolv_fallback_nameservers` (IP addresses) |
| `set_default_editor` | `True` | `default_editor_path` `/usr/bin/vim.basic` |

- **resolv.conf**: when `/etc/resolv.conf` lists only loopback nameservers
  (or none), it is replaced by a file with the fallback nameservers, renamed
  into place, which also replaces a symlink such as systemd-resolved's stub
  (the role's `copy` does the same). Hosts with a local resolver (Unbound on
  `127.0.0.1`) are affected exactly as with the role.
- **fish**: `~/.config/fish/config.fish` keeps everything outside the block
  between `# BEGIN ANSIBLE SHELL BASICS` and `# END ANSIBLE SHELL BASICS`
  (the role's markers, so both tools edit one block); trailing blank lines are
  not preserved.
- **bat/fd**: `~/.local/bin/bat` and `fd` link to Debian's `batcat`/`fdfind`
  when those packages are in the list (or the binaries exist).
- **chezmoi**: same download-verify-rename step as uv (installs `curl` if missing).
- **parents**: a missing `~/.local` or `~/.config` is created owned by the
  user, as the role's `file` module does for the parents it creates.
- **editor**: `update-alternatives --set editor <path>`; the path must be a
  registered alternative (vim registers `vim.basic`).

## ssh_guard

fail2ban for sshd plus an sshd drop-in with per-source limits: the role's
two files, extended by the fix for fail2ban's CVE-2026-109786, explicit jail
keys, and checks of the running jail and of sshd's effective values.

| Field | Default | |
|---|---|---|
| `fail2ban_enabled` | `True` | `False` skips the package, service, filter override and jail |
| `fail2ban_package`, `fail2ban_service_name` | `fail2ban` | |
| `fail2ban_jail_name` | `sshd` | letters, digits, `_ . @ -` |
| `fail2ban_backend`, `fail2ban_filter`, `fail2ban_port` | `systemd`, `sshd`, `ssh` | |
| `fail2ban_maxretry` | `5` | an int (not a bool, string or float), > 0 while fail2ban is enabled |
| `fail2ban_findtime`, `fail2ban_bantime` | `10m`, `1h` | |
| `fail2ban_ignoreip` | `127.0.0.1/8 ::1 100.64.0.0/10` | empty: no `ignoreip` line |
| `fail2ban_sshd_filter_fix` | `auto` | not in the role: `auto` manages the CVE-2026-109786 filter override (below); `off` never touches `filter.d/sshd.local` |
| `fail2ban_banaction` | `""` | not in the role: `banaction` jail key; only `nftables…`/`iptables…` actions, optionally with `[parameters]`; empty leaves the packaged default |
| `fail2ban_journalmatch` | `""` | not in the role: `journalmatch` jail key, journalctl matches joined by ` + ` |
| `fail2ban_ban_only` | `False` | not in the role: `action = %(action_)s` (ban only, no mail or whois action) |
| `fail2ban_no_recommends` | `False` | not in the role: apt installs without Recommends (no whois or mail tools) |
| `sshd_dropin_enabled` | `True` | `False` skips the drop-in, checks and reload |
| `sshd_dropin_path` | `/etc/ssh/sshd_config.d/99-ssh-guard.conf` | a file below a directory |
| `sshd_service_name` | `ssh` | |
| `per_source_max_startups` | `"5"` | empty: directive left out; `None` is refused while the drop-in is enabled |
| `max_auth_tries`, `login_grace_time` | `""` | empty: directive left out |
| `max_startups` | `""` | not in the role: `start:rate:full` |
| `per_source_net_block_size` | `""` | not in the role: `<ipv4 0-32>:<ipv6 0-128>` (`32:64` groups an IPv6 /64) |
| `per_source_penalties` | `""` | not in the role: `no`, or `key:value` settings OpenSSH knows (`authfail:5m max:600`), each key once |
| `per_source_penalty_exempt_list` | `""` | not in the role: comma-separated addresses/networks |
| `password_authentication` | `None` | not in the role: `None` leaves the directive out; `"yes"` or `"no"` writes `PasswordAuthentication` |
| `permit_root_login` | `None` | not in the role: `None` leaves the directive out; `"yes"`, `"prohibit-password"`, `"forced-commands-only"` or `"no"` writes `PermitRootLogin` (the old spelling `without-password` is refused) |
| `timed_revert_seconds` | `0` | not in the role: `0` off; 60..3600 runs every change under a timed revert (below) |

Values written into the files must not contain line breaks or other control
characters, so a value cannot add a directive of its own. The role's two
asserts (`maxretry`, `PerSourceMaxStartups`) are checked when the config is
built, each only for the enabled part.

With only the role's fields, `/etc/fail2ban/jail.d/ssh-guard.local` and the
drop-in are byte-identical to the role's templates (including the `# Managed
by ops-library ssh_guard_deploy. Do not edit.` header). The extra jail keys
follow the role's lines in the order `banaction`, `journalmatch`, `action`;
the extra directives follow `PerSourceMaxStartups`, `MaxAuthTries`,
`LoginGraceTime` in the order `MaxStartups`, `PerSourceNetBlockSize`,
`PerSourcePenalties`, `PerSourcePenaltyExemptList`, `PasswordAuthentication`,
`PermitRootLogin`. All files are `root:root 0644`, their directories
`root:root 0755`.

`password_authentication` and `permit_root_login` default to `None`: no line,
so every existing configuration renders the same drop-in and the same checks
byte for byte. They change who can log in, so set them only with
`timed_revert_seconds` on a host whose only way back is SSH, and check a new
key login (and that a password login is refused) before the confirm. They are
plain directives in the drop-in: `PasswordAuthentication no` does not turn off
`KbdInteractiveAuthentication` (a PAM password prompt), and a `Match` block in
the main configuration can still set either for matching connections; neither
is checked here.

### Planning

One read-only probe (`ssh -V`, the packaged `filter.d/sshd.conf`, an
existing `filter.d/sshd.local`, `nftables.service`, `getent services`, what a
running jail has loaded, the ban action lines of fail2ban's other jail files)
decides the plan. The deploy is refused before any change when

- a directive the drop-in renders is newer than the host's OpenSSH:
  `PerSourceMaxStartups`/`PerSourceNetBlockSize` need 8.5,
  `PerSourcePenalties`/`PerSourcePenaltyExemptList` 9.8 (or `ssh -V` is
  unreadable while such a directive is set);
- `filter.d/sshd.local` exists but was not written by this deploy (its first
  line is not `# Managed by ops-deploy ssh_guard. Do not edit.`), or is not a
  regular file (with `fail2ban_sshd_filter_fix` `auto`);
- OpenSSH logs from `sshd-session` (OpenSSH 10) but the packaged filter's
  `_daemon` does not accept that name (fail2ban would see no failure);
- `nftables.service` is enabled: its `flush ruleset` would drop fail2ban's
  bans along with Tailscale's and Docker's rules. The deploy never enables or
  starts it;
- a service name in `fail2ban_port` does not resolve (`getent services`; the
  `netbase` package), which the nftables actions need.

### CVE-2026-109786 filter override

fail2ban's packaged sshd filter (Debian 12/13, Ubuntu 24.04 at the time of
writing) accepts `on <token>` after the host in `__suff` and
`__on_port_opt`. OpenSSH logs the offered user name verbatim, so a user name
like `x 198.51.100.23 on` makes fail2ban attribute the close line of the
session to `198.51.100.23`: an attacker bans an address of their choice.
Upstream fixed it in fail2ban commit ddd879d. With `auto` the deploy writes
`/etc/fail2ban/filter.d/sshd.local` with those two lines (fail2ban merges a
`.local` over the `.conf` before interpolation, so every failregex built from
them picks them up) while the packaged `sshd.conf` still contains `on \S+`,
or does not exist yet (a fresh install). Once the package carries the fix the
deploy removes its file again and restarts fail2ban.

### Order

1. drop-in directory; `/etc/fail2ban/jail.d` and `/etc/fail2ban/filter.d`;
2. `python3-systemd` for a `systemd` backend (it arms nothing; a fail2ban
   installed without Recommends could not load a systemd jail without it).
   Packages come from apt, each on its own, with no cache refresh (as the
   role's `package` task);
3. the filter override (written or removed), then the jail file;
4. if fail2ban was installed when planning and step 3 changed something:
   restart fail2ban (`systemctl restart` also starts a stopped unit) and run
   the gate;
5. `fail2ban`, then `nftables` for an `nftables…` ban action, the configured
   one or, without one, the one the jail inherits from fail2ban's other jail
   files (`jail.conf`, `jail.d/*.conf`, `jail.local`, `jail.d/*.local`
   without this deploy's file, in fail2ban's order: the jail's section over
   `[DEFAULT]`, a later file over an earlier one, inline comments ignored;
   e.g. Debian 13's nftables default). An interpolated value is not resolved;
   on a host without fail2ban yet nothing is known while planning, and the
   final gate stops fail2ban if `nft` is then missing. A fresh package's
   postinst starts fail2ban with the override and jail already in place; an
   installed one has already loaded them before `nft` exists;
6. restart fail2ban if a package was installed; fail2ban enabled and
   running; the final gate if anything in steps 2–6 changed;
7. the drop-in; if it changed, `sshd -t` and the `sshd -T` check, then the
   reload (or a start of a stopped ssh, the role handler's `state: reloaded`).

A converged host reports no change: nothing is restarted, checked or reloaded.
When fail2ban is running, the probe also reads what its jail has loaded: if
that still contains `on \S+` or lacks the configured ban action although the
files are right (a run interrupted before its restart), fail2ban is restarted
and checked again.

### The gate

`fail2ban-client` against the running jail (waiting up to 60 s for it to come
up after a restart). It stops fail2ban (`systemctl stop`, which also removes
fail2ban's nftables table or iptables chains) and fails the deploy when the
jail does not come up, loaded no failregex, any loaded failregex contains
`on \S+`, it has no ban action or one that is not an `nftables…`/`iptables…`
action, the configured `banaction` is not among them, or with `ban_only`
there is more than one. The final gate adds: the binaries of the ban actions
exist (`nft`; `iptables` and `ip6tables`) and, with `sshd-session`, the
loaded prefix regex accepts that name. An enabled `nftables.service` there
fails the deploy without stopping fail2ban. sshd is never touched by a gate;
a stopped fail2ban leaves OpenSSH's own limits (`PerSourcePenalties` from 9.8)
as the protection.

### sshd effective values

`sshd -t -f /etc/ssh/sshd_config` checks the whole configuration. Then
`sshd -T` must print each rendered directive with its value as sshd prints
it (lowercase; numbers without leading zeros; `LoginGraceTime` in seconds;
`PerSourcePenalties` part by part, words exactly and numbers by value, so
`authfail:5m` matches OpenSSH 10.0's `authfail:300` and 10.3's
`authfail:300.000000`; `PermitRootLogin prohibit-password` as either
`prohibit-password` or `without-password`, which OpenSSH 9.6 prints for it).
sshd takes the first value it reads for most directives,
so an earlier drop-in that sets the same one wins (as does a line of the main
configuration before its `Include`); OpenSSH 10.0 takes the last
`PerSourceNetBlockSize`. Either way the effective value differs. On any
failure the drop-in is removed and the deploy fails before the reload, with
`Invalid sshd config; removed <path>.` or `sshd -T does not show: <line>;
removed <path>.` (the role's `rescue`, extended). Role values whose printed
form is not derived here (free text `sshd -t` still accepts) are checked by
`sshd -t` only.

Differences from the role, on purpose:

- The CVE-2026-109786 filter override, the extra jail keys and directives,
  the gates, the `sshd -T` check and the package and install order above. The role (ops-library `ssh_guard_deploy`, frozen) installs
  fail2ban, lets the postinst start it with the packaged vulnerable filter,
  and writes the jail afterwards.
- The fail2ban restart is not deferred to the end. The role's handlers do not
  run once the drop-in check fails, which leaves a written jail that fail2ban
  never loads (later runs see it unchanged). Here the jail is applied before
  the drop-in is checked.
- Only a failing `sshd -t`/`sshd -T` check removes the drop-in. The role's
  `rescue` also removes it when writing the file fails (an upload or
  permission error), which would drop a valid earlier drop-in.
- `python3-systemd` is installed for the `systemd` backend (fail2ban only
  recommends it on Debian 12 and Ubuntu 24.04).
- Linux hosts with systemd and apt only. The role's `package` and `service`
  modules would also try other package managers and init systems.

Inherited from the role: with ssh stopped, Debian removes `/run/sshd`, so
`sshd -t` fails on that alone and a changed drop-in is removed (start ssh and
run again). A run interrupted between writing the drop-in and the check leaves
the file unchecked and not reloaded until it changes again. Likewise a run
interrupted between a fail2ban file write and the gate leaves the gate unrun
until something changes again.

### Timed revert

For a host whose only way back is the SSH path these changes touch.
`timed_revert_seconds: 0` (the default) is the plain deploy above; its only
addition is one read-only probe line, the transaction state, so that it
refuses while a transaction is open. With 60..3600 (on a host with the unified cgroup v2 hierarchy, the
default of current Debian and Ubuntu; the apply refuses before any change
otherwise) the deploy runs the same steps (same names, order, commands and conditions; a test compares them with
the plain operations) through the host program `files/ssh_guard_tx.py`,
installed as `/usr/local/libexec/ops-deploy/ssh-guard-tx` (`root 0755`,
standard library, `/usr/bin/python3 -I`), with its state in
`/var/lib/ops-deploy/ssh-guard-tx` (`0700`).

While planning, the program runs read-only from stdin (`plan`) and names the
steps that would run now. A converged host gets no operation. Otherwise the
deploy has three: the directory and the program, then one shell operation,
`Apply under a N s timed revert: <steps>`, which calls `run`. No pyinfra
operation writes an sshd or fail2ban file in this mode.

On the host, under one `flock` (`state-dir/lock`):

1. `run` refuses while a transaction is open (`staged`, `applying`, `armed`,
   `reverting`) or when the generation differs from the one the deploy read
   while planning (the host changed since); with nothing to change it reports
   `unchanged` and arms nothing. Otherwise it stores the bundle and a copy of
   the program under `tx/<id>/`, records `staged` with generation + 1, and
   starts `apply` in a transient unit `ssh-guard-tx-apply-<id>.service`
   (`RuntimeMaxSec=1800`), so a dropped SSH session does not stop it; it waits
   for the result.
2. `apply` snapshots every managed file (content, owner, mode, or absence),
   the managed directories, the fail2ban and ssh units' enabled/active state
   and the packages, records `applying` with the deadline, and starts the
   one-shot timer `ssh-guard-tx-revert-<id>.timer` (`systemd-run
   --on-active=N`), which runs `revert <id>` with the transaction's own copy of
   the program. Only then does it run the steps. Each step runs in its own
   process group (at most 900 s), killed as a whole when the step ends or
   times out, so nothing it started keeps writing. A failing step (a gate,
   `sshd -t`/`-T`, apt, a timeout) reverts at once, after every other process
   of the apply unit's cgroup (a child that left its process group) is
   killed; an apply that outlasts the window reverts too. Success records
   `armed` with the digests of the managed files.
3. `confirm --generation N` (run it over a new SSH connection: `ssh -o
   ControlMaster=no -o ControlPath=none HOST /usr/bin/python3 -I
   /usr/local/libexec/ops-deploy/ssh-guard-tx confirm --generation N`) needs
   an SSH connection opened after the transaction was armed: the nearest
   `sshd`/`sshd-session` process above it (the connection's own process) must
   have started after the apply finished, so a multiplexed or kept-open
   connection from before the change is refused; and `SSH_CONNECTION` set and
   different from the one recorded by `run`. Also the same boot and the
   deadline not passed. It records `confirmed`, then stops the timer.
4. `revert <id>` first kills a still running apply unit and waits until
   `systemctl show` answers that it is `inactive` or `failed` (a failed query
   never counts; after 60 s it restores nothing and fails, to be run again). It acts only on its own open transaction; anything else (a
   confirmed one, a newer one, a final status) is left alone, so a revert
   fires at most once and never touches a later transaction. An `armed`
   transaction whose files no longer have the recorded digests was changed by
   someone else since: `superseded`, nothing restored, the unit fails.
   Otherwise it records `reverting`, restores each file byte for byte with
   owner and mode (or removes it), removes directories the transaction created
   when empty, and then: fail2ban back to its enabled state and, if it ran
   before, restarted onto the restored files, else stopped (which removes its
   bans); ssh reloaded once the restored drop-in passes `sshd -t` (never
   stopped or started). A file it cannot restore makes it stop fail2ban rather
   than load it, and skip the ssh reload. The result is `reverted` or
   `revert-failed` (the unit fails); both are final.

Packages a transaction installed stay installed after a revert (inert: their
service stopped and disabled when it was not there before); the revert names
them (`packages_left_installed`). A reboot drops the transient timer: the
transaction stays open, every deploy refuses and `confirm` refuses (other
boot); decide with `revert <id>` (or inspect first). `status` prints the
state without the recorded SSH connections.

The next deploy warns about a last transaction that ended `reverted`,
`revert-failed` or `superseded`, and refuses while one is open, naming the
`confirm` and `revert` commands. Concurrent deploys of the same host are
excluded by the caller's deploy lock; a plain deploy started while a
transaction is open refuses, and one that changes a file after it is caught
by the digest check.

## dpkg_arch_remove

| Field | Default | |
|---|---|---|
| `targets` | `("i386",)` | dpkg architecture names (`[a-z0-9-]`, not starting with `-`); a single name is accepted, names are trimmed, empty ones dropped and duplicates removed, as in the role |
| `update_cache` | `True` | `apt-get update` after an architecture was removed |
| `purge_packages`, `autoremove` | `False` | **refused** when `True` (see below) |

Reads `dpkg --print-foreign-architectures` while planning. A host where no
target is a foreign architecture gets no operation at all (the converged
case, also the usual one). When targets are present, the installed packages
are listed with `dpkg-query -W -f='${Package} ${Architecture}\n'`; if any of
them has a present target architecture, the deploy fails before any change,
naming them (`libc6:i386, ...`), even if other targets have no packages.
Otherwise it runs `dpkg --remove-architecture <arch>` for each present
target, in `targets` order, then updates the apt cache. Both reads are strict:
a failing `dpkg` or `dpkg-query` fails the deploy instead of reading as "no
foreign architecture". Debian-family hosts only (the role's
`ansible_os_family == "Debian"` assert; the port requires `apt-get`).

Intended difference: the role's `dpkg_arch_remove_purge_packages` (with
`dpkg_arch_remove_autoremove`) removes the foreign-architecture packages
before dropping the architecture. The port does not remove packages: setting
either field is refused when the config is built, so the deploy behaves like
the role with its defaults, which fail on such packages. Remove the packages
deliberately first (or use the role).

## stale_exe_restart

No ops-library role: a pyinfra-only base deploy. A reload never loads a new
executable (nginx's `SIGHUP` forks new workers from the old image), and a
package's maintainer scripts only restart the units the package ships. A unit
that runs a packaged binary under its own name (an nginx started by a service's
own `web-nginx.service`, say) therefore keeps running the old, deleted image
after an upgrade until something restarts it. The file's mtime cannot tell:
dpkg keeps the archive's mtime; the identity of `/proc/PID/exe` can.

```python
from ops_deploy.base import StaleExeRestartConfig, deploy_stale_exe_restart

deploy_stale_exe_restart(
    StaleExeRestartConfig.model_validate(
        {
            "units": [
                {
                    "unit": "web-nginx.service",
                    "binary": "/usr/sbin/nginx",
                    "package": "nginx",
                    "test": "nginx",
                    "expected_argv": ["/usr/sbin/nginx", "-c", "/etc/web/nginx.conf", "-g", "daemon off;"],
                    "http_probe": {"url": "http://127.0.0.1:8080/health", "headers": {"Host": "web.example.org"}},
                }
            ]
        }
    )
)
```

| Field | Default | |
|---|---|---|
| `units` | `()` | the allowlist; empty: the timer only reports and restarts nothing; a unit listed twice is refused |
| `units[].unit` | | a `*.service` name |
| `units[].binary` | | normalized absolute path of the packaged executable |
| `units[].package` | | the Debian package that owns `binary` |
| `units[].test` | | the configuration test; only `nginx` so far |
| `units[].expected_argv` | | the unit's exact `ExecStart` argv, starting with `binary` (no NUL or newline) |
| `units[].http_probe` | `None` | `url` (`http://` to `127.0.0.1`, `::1` or `localhost` with an explicit port), `headers`, `status` (default 200) |

The deploy installs, all `root:root`:

| Path | |
|---|---|
| `/usr/local/libexec/ops-deploy/stale-exe-restart` (0755) | the host program (`base/files/stale_exe_restart.py`, standard library only, `/usr/bin/python3 -I`, Python 3.11 or newer) |
| `/etc/ops-deploy/stale-exe-restart.json` (0644) | the allowlist (`{"schema": 1, "units": [...]}`) |
| `stale-exe-restart.service` | oneshot running the program's `run` mode; `StartLimitIntervalSec=0` (the apt hook may start it after every dpkg run), no `Restart=`, `TimeoutStartSec=50min`, `StateDirectory=ops-deploy/stale-exe-restart` |
| `stale-exe-restart.timer` | hourly, `RandomizedDelaySec=5min`, `Persistent=true`; enabled and started |
| `/etc/apt/apt.conf.d/80ops-deploy-stale-exe-restart` (0644) | `DPkg::Post-Invoke` that only queues the oneshot (`systemctl --no-block start`, only with `/run/systemd/system` and the unit file present, failures ignored): no restart happens inside dpkg and the hook never fails apt |

The deploy itself never restarts, reloads or starts a consumer unit and never
starts the oneshot: it writes the files, reloads systemd when a unit file
changed, starts the timer and writes the hook last. While planning, the
packaged program runs read-only in `report` mode with the rendered allowlist
(sent on stdin, the allowlist as base64), so `--dry` logs what the next timer
run would do; a host that cannot run it fails the deploy before any change. The
deploy ends with a read-only `report` of the installed program. A converged
host gets no mutating operation. Debian-family hosts with systemd only.

`run` acts on an allowlisted unit only when every check passes, in this order:

1. **dpkg is idle**: no process holds `/var/lib/dpkg/lock-frontend` or
   `/var/lib/dpkg/lock` (`/proc/locks`, read-only), no `apt`, `apt-get`,
   `aptitude`, `dpkg` or `unattended-upgrade` process runs (a process whose name
   cannot be read counts as one), and no package is
   half-installed, unpacked, half-configured, awaiting or pending triggers or
   marked reinst-required. It waits up to 30 minutes (10 s polls), then records
   `deferred` and exits 0; the next timer run tries again.
2. **The unit runs a stale image**: loaded and active (`activating`,
   `reloading` and the like are `changing`: left for the next run; missing or
   unknown properties refuse), every process of its
   cgroup (and the cgroups below it) runs `binary` in the host's mount
   namespace and root directory, the main PID is among them, and at least one
   runs a `(deleted)` image or one with another device/inode than the file on
   disk. A process that cannot be inspected (also a cgroup that cannot be
   listed), one in another namespace or one running another executable makes
   the unit `refused`.
3. **The binary is the package's**: a regular file owned by root and writable
   only by root, `dpkg-query -S` names exactly `package` (no diversion), the
   package is `ii`, and `dpkg --verify` does not list the file (it exits 0 for
   changed files, so its output is read).
4. **The unit is the approved one**: `ExecStart` read over D-Bus
   (`busctl --json`, exact argument boundaries; `systemctl show` loses them for
   `daemon off;`) is exactly `[binary, expected_argv]`, every `ExecStartPre` is
   a `-t` run of `binary`, there is no `ExecStartPost`, and `NeedDaemonReload`
   is `no` (a pending unit edit must not ride along with the restart).
5. **One restart per binary**: no restart was attempted before for this
   binary's device, inode and sha256 (`stale_no_retry` otherwise).
6. **The configuration test passes** as the unit's `User`/`Group` (`runuser`):
   `<binary> -t <expected_argv[1:]>`, then each `ExecStartPre`; exit 0,
   `test is successful`, no `[emerg]`/`[crit]`/`[alert]` line (output in the
   journal, not in the state file). The test runs with the oneshot's limits,
   not the unit's (`LimitNOFILE`), so nginx may warn about
   `worker_connections`; warnings do not fail it.
7. **Nothing changed during the tests** (they can take minutes): dpkg idle
   again, the same main PID still on a stale image, checks 3 and 4 again, the
   same `ExecStartPre`, the same definition (`User`, `Group` and the sha256 of
   the unit file and every drop-in systemd loaded) and the same binary (device,
   inode, sha256) as tested. Otherwise `deferred`: nothing recorded, the next
   run starts over.

Then the attempt is recorded in the state file, `systemctl try-restart <unit>`
runs once (`try-restart`: a unit stopped in the last moment stays stopped), and
the post check waits up to 30 s for: active, a new main PID,
every process on the disk binary, the main process's image (`/proc/PID/exe`)
with the file's sha256; then up to 30 s for the HTTP probe's status. There is
no retry and no rollback: a failed restart or post check is recorded
(`restart_failed`, `post_failed`) and the binary is not tried again.

For an allowlisted unit that is current or inactive, checks 3 and 4 run as
well and the result says `ready` (or why a restart would be refused): an
allowlist entry that does not fit the unit (a typo in the argv, another package,
a changed unit) shows at once instead of at the next upgrade, makes the oneshot
exit 1, and makes the deploy fail while planning, before any change (so does a
unit that is not loaded).

Every other unit is only reported: units whose processes run a stale image
(`(deleted)`, or another inode than the host file at that path) or map deleted
libraries below `/usr`, `/lib*`, `/bin`, `/sbin`, `/opt` (basenames only).
Processes in another mount namespace or root directory (containers, sandboxed
units) are skipped for the path comparison, because their paths are not host
paths; only the kernel's `(deleted)` marks are reported for them, and they are
counted. Deleted libraries never trigger a restart, also not for an allowlisted
unit.

State: `/var/lib/ops-deploy/stale-exe-restart/state.json` (0644, replaced
atomically; it records each attempt before the restart, so a crash cannot turn
into a second restart). A state file that exists but cannot be read or parsed
(also one whose attempts lack a well-formed binary key, time or result)
blocks every action: `run` exits 2 and leaves it as it is, `report` names it as
`state_error`, and the deploy fails while planning until it is repaired or
removed. Fields: `result` (`ok`, `attention`, `deferred`, `config_error`, `error`),
`units` (per allowlisted unit: `status`, `reason`, PIDs, running and disk
identities), `report_only`, `attempts` (per unit: binary key, time, result),
`foreign_namespace_pids`, `unreadable_pids`, `dpkg_waited_s`. The oneshot exits
0 when nothing needs attention, 1 when an allowlisted unit is `not_loaded`,
`refused`, `stale_no_retry`, `test_failed`, `restart_failed`, `post_failed` or
`error`, or is not `ready` (so `systemctl --failed` shows it), and 2 on a configuration,
state or internal error. `stale-exe-restart report` prints the same evaluation as JSON
without testing, restarting or writing anything.

To remove it, first make the oneshot impossible to start, then drain it:

1. `systemctl disable --now stale-exe-restart.timer` (no runs from the timer);
2. delete the apt hook and `/etc/systemd/system/stale-exe-restart.service`. An
   apt process that started before reads the hook from memory, but the hook
   starts nothing once the unit file is gone;
3. `systemctl daemon-reload`: from now on no start request can load the unit;
4. `systemctl stop stale-exe-restart.service` and check that it is `inactive`.
   A run that was queued or running (it may wait up to 30 minutes for dpkg with
   the allowlist already loaded) could otherwise still restart a unit; a
   restart systemd has already started finishes on its own;
5. delete the timer unit (`daemon-reload`), the program, the allowlist and the
   state directory.

Taking a unit off the allowlist and deploying again stops its restarts, except
for a run that already loaded the old allowlist (stop the service as in step 4
if that matters).

## Tests

`tests/test_base_*.py` run each deploy against the fake connector: first run,
converged run (no change), drift and refusal cases, config validation, and the
authorized_keys and journald drop-in rendering against the vendored role
templates.
`tests/test_base_stale_exe_restart_host.py` runs the host program's decision
table against an in-memory host (every refusal, test failure, deferral, one
restart per binary, post checks, the report), and
`tests/test_base_stale_exe_restart.py` the deploy against the fake connector.

`tests/test_base_journald_docker.py` runs `journald_config` against a real
systemd and journald in an owned Docker container and is skipped unless
`JOURNALD_SYSTEMD_DOCKER_CONTAINER` holds that container's full ID. The
container must be named `ops-deploy-systemd-journald-20261020`, carry the
labels `ops-deploy.fixture=journald-systemd` and `ops-deploy.run=journald-20261020`,
and run systemd as PID 1 with no network, binds, ports or devices, a private
cgroup namespace and `SYS_ADMIN` as its only added capability (an Ubuntu 24.04
image with `systemd`, plus `ansible-core` for the takeover case; the entry
point remounts its own cgroup2 tree writable before `exec /sbin/init`, which
needs AppArmor unconfined). The test checks that the first run restarts
(new invocation ID and PID) and flushes, a converged run leaves journald and
the file alone, mode drift restarts, `restart_on_change=False` does not, the
flush moves a volatile journal to disk, `absent` restarts once, and a symlinked
drop-in is replaced or unlinked while its target stays untouched. With
`OPS_LIBRARY_PATH` set it also applies the role with Ansible inside the
container first; the deploy must then change nothing.
`tests/smoke/test_base_smoke.py` deploys each one twice on the
[smoke VM](concepts/smoke.md) (the second run must not change anything; not
`dpkg_arch_remove`, which has only fake-connector tests) and
checks the end state, including an SSH login with the managed key. It works on
a throwaway user, units and directories and restores the hostname, default
target and editor.

`tests/test_base_ssh_guard_docker.py` runs `deploy_ssh_guard` against real
sshd, fail2ban, nftables and systemd. It is skipped unless
`SSH_GUARD_DOCKER_CONTAINER` holds the full ID of a running container named
`ops-deploy-ssh-guard-*`, labelled `ops-deploy.fixture=ssh-guard`, with
`--network none`, not privileged, no mounts, `NET_ADMIN` and systemd as
PID 1. Build it from `debian:trixie` with the image's `docker-clean` apt
hook removed, `systemd systemd-sysv openssh-server fail2ban python3-systemd
netbase` installed and `nftables` only downloaded (`apt-get install
--download-only --no-install-recommends nftables`), so the deploy can install
it with no network; enable `ssh` and `fail2ban`. Run it with
`--cgroupns private --cap-add SYS_ADMIN --cap-add NET_ADMIN --security-opt
apparmor=unconfined --tmpfs /run --tmpfs /run/lock`, as entry point
`/sbin/init` after remounting `/sys/fs/cgroup` read-write. pyinfra's Docker
CLI is wrapped so it can only inspect, exec and copy.

The test first resets the container to the shape of a host exposed to
CVE-2026-109786 (packaged filter loaded, Debian's nftables default ban
action, `nft` missing, no guard files) and checks that the stock filter
blames the injected address. It then covers: the first run in the documented
order; the spoof regression on the installed filter (`fail2ban-regex` on
session strings with documentation addresses, nothing written) and legitimate
sessions unchanged; bans reaching nftables for IPv4 and IPv6 and unbans
removing them; a converged run; a running jail that still has the vulnerable
filter although the files are right (restart and gate, nothing written); jail
drift; the gate stopping fail2ban (and its nftables table) when the vulnerable
filter is loaded with `fail2ban_sshd_filter_fix` `off`, and recovery;
drop-in drift; an earlier drop-in that shadows a directive (`sshd -T`
mismatch: drop-in removed, no reload); a value `sshd -t` rejects; a stopped
ssh; and the role's defaults on the exposed host (nftables installed for the
inherited nftables action). The timed revert (60 s window): armed with every
deploy refused, then reverted by the timer (files gone, fail2ban back on the
stock filter, ssh reloaded onto the old configuration, nftables left
installed); armed and confirmed from a new connection (nothing reverts after
the deadline, the next timed run plans no operation); a stale revert of the
confirmed transaction against a newer armed one (nothing); a drop-in changed
after the transaction (`superseded`, left alone, failed unit); a value `sshd
-t` rejects (reverted at once, ssh reloaded onto the old drop-in); and a
caller killed with its process group while the apply runs (the apply
finishes in its unit, the timer reverts); and a timed-out step whose `setsid`
child would write after the rollback (killed with the unit's cgroup first). `confirm` runs over real SSH logins
to the container's loopback with a test key: a new login confirms, a login
through a ControlMaster opened before the change and a plain `docker exec`
are refused.

`tests/test_base_ssh_guard_tx.py` runs the host program against stub
`systemctl`, `systemd-run`, `dpkg-query` and `apt-get` (timers are recorded
and fired by the test): arming before the first change, byte-exact restores,
confirm rules, refusals, an old timer against a newer transaction, the digest
check, immediate revert, restore failures, a killed apply, a revert waiting
for a running apply, a timed-out step and a backgrounded child (both killed
before they can write), and bundle validation.

`tests/test_base_ssh_guard_sshd_check.py` runs the generated `sshd -t`/`-T`
check with `sh` against a stub `sshd` that prints what OpenSSH 10.0 and 10.3
print (integer and decimal penalty times): matching values keep the drop-in;
a shadowed directive, another time or mode, penalties off or missing, and a
failing `sshd -t` remove it.

`tests/test_base_stale_exe_restart_docker.py` runs `stale_exe_restart`
against real systemd, nginx, dpkg and apt. It is skipped unless
`STALE_EXE_DOCKER_CONTAINER` holds the full ID of a running container named
`ops-deploy-stale-exe-*`, labelled `ops-deploy.fixture=stale-exe-restart`,
with `--network none`, not privileged, no mounts and systemd as PID 1, built
from `debian:trixie` with `systemd systemd-sysv dbus nginx python3`,
`nginx.service` masked (a `/dev/null` link) and the installed nginx `.deb`
under `/opt/stale-exe-fixture/debs` (`apt-get download nginx` while building),
for example `--cgroupns private --cap-add SYS_ADMIN --cap-add SYS_PTRACE
--tmpfs /run --tmpfs /run/lock`, `/sbin/init` after remounting
`/sys/fs/cgroup` read-write (`SYS_PTRACE`: root reads other users'
`/proc/PID/exe`, as on a host). pyinfra's Docker CLI is wrapped so it can only
inspect, exec and copy. The test sets up a `webapp-nginx.service` shaped like
a service's own nginx unit plus units holding a copy of a library, a copy of an
executable and a sandboxed one, then checks: the first deploy installs
everything and restarts nothing, the second changes nothing; after a
package-style replacement (a copy renamed over the binary: same bytes, new
inode) the report names the stale unit and the report-only ones; the oneshot
restarts only the allowlisted unit, once; a broken configuration fails the
test and restarts nothing; a pending unit edit is refused; a held dpkg lock
makes the run wait; and a real `apt-get install --reinstall` of the cached
package queues the oneshot through the hook, which restarts the unit after apt
has finished.
