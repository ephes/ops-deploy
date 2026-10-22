# Base deploys

`ops_deploy.base` ports the base/bootstrap roles of ops-library. Each is a
typed config plus a `@deploy` function. Some are run on their own against a
host (hostname, unit masks, headless mode, journald, shell basics, authorized keys,
SSH guard, dpkg foreign architectures), the others are steps a service deploy
calls (uv, Node.js):

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

Field names follow the role variables without the role prefix
(`headless_mode_apply_now` is `apply_now`). Defaults are the role defaults
unless noted below.

## hostname

`hostname` (required; letters, digits, `.`, `_`, `-`, not starting with a
symbol). Runs `hostnamectl set-hostname` when `uname -n` differs. The role
defaults to the inventory host name; the private side passes it.

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
| `version` | `0.13.4` | change together with `checksums` |
| `checksums` | the role's sha256 for x86_64 and aarch64 Linux | keyed by release target |
| `install_dir` | `/usr/local/bin` | normalized absolute path other than `/`; parent must already exist |
| `owner`, `group` | `root` | converge both binaries to these identities and mode `0755` |
| `update_existing` | `True` | replace another installed version; never downgrade a newer version |
| `force_reinstall` | `False` | reinstall the pinned pair; still refuses downgrades |
| `previous_owners` | `()` | explicit trusted previous canonical owners to adopt |
| `aliases` | `()` | explicit `UvAliasConfig` entries; no discovery or cleanup |

Manages `uv` and `uvx` as a pair. A missing, broken, non-executable, group/other
writable or wrong-version binary triggers a checksum-verified install of both.
The existing version/checksum map remains the sole release source. Other owned
metadata drift converges with file operations even when both versions match.
With `update_existing=False`, an existing matching pair is preserved; an
inconsistent pair or repair requiring a different existing version fails closed
unless `force_reinstall=True` explicitly requests replacement.
A newer installed version refuses replacement even with `force_reinstall`.

Before executing any managed binary or scheduling mutations, explicitly managed
leaf paths must be unowned by each available package manager (`dpkg-query` and/or
`rpm` with its exact unowned-file result, including its absent-path fallback
only when the path is actually absent). Missing tools, failed/unknown queries and
package-owned paths fail closed, including absent files still in package records.
Every ancestor must
be a real root-owned directory without group/other write access. Only the final
install directory may be absent. Canonical binaries must be regular files owned
by root, `owner`, or an explicitly trusted `previous_owners` entry. Canonical
symlinks, foreign owners, directories and occupied staging paths fail closed;
this intentionally replaces the old automatic symlink replacement behavior.
`previous_owners` authorizes trusting and executing that owner's existing bytes;
use it only after establishing provenance. Group/other-writable binaries are
reinstalled without executing their existing bytes.

One shell step downloads into a private temp directory, checks the pinned sha256,
unpacks and renames both binaries, then verifies both installed versions before
aliases run. `curl` is installed with apt first when missing. Planning only reads.
An unchanged pair with correct metadata and aliases plans no mutations.

Aliases are individually configured; their parent directories must already meet
the same root-owned safety checks. For example:

```python
from ops_deploy.base import UvAliasConfig, UvInstallConfig

uv = UvInstallConfig(
    aliases=(
        UvAliasConfig(path="/usr/local/uv", binary="uv"),
        UvAliasConfig(path="/usr/local/uvx", binary="uvx"),
    )
)
```

An absent alias becomes a root-owned link to the verified canonical binary.
An already-correct root-owned link is preserved. Unexpected links are refused.
Replacing a named regular legacy file additionally requires its exact
`replace_sha256` and `replace_owner` (default `root`); pyinfra retains its normal
backup before creating the link. These approvals do not authorize other paths,
directory removal, caller discovery, cache/venv deletion or package cleanup.
No aliases are created by default, including the old role's deprecated symlinks.

Linux only. Darwin is refused before any path/version operation, preserving
Homebrew links and Cellar ownership/bytes. macOS package/alias policy and shared
lifecycle drift detection belong to their separate integration work.
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

| Field | Default | |
|---|---|---|
| `fail2ban_enabled` | `True` | `False` skips the package, service and jail |
| `fail2ban_package`, `fail2ban_service_name` | `fail2ban` | |
| `fail2ban_jail_name` | `sshd` | letters, digits, `_ . @ -` |
| `fail2ban_backend`, `fail2ban_filter`, `fail2ban_port` | `systemd`, `sshd`, `ssh` | |
| `fail2ban_maxretry` | `5` | an int (not a bool, string or float), > 0 while fail2ban is enabled |
| `fail2ban_findtime`, `fail2ban_bantime` | `10m`, `1h` | |
| `fail2ban_ignoreip` | `127.0.0.1/8 ::1 100.64.0.0/10` | empty: no `ignoreip` line |
| `sshd_dropin_enabled` | `True` | `False` skips the drop-in, check and reload |
| `sshd_dropin_path` | `/etc/ssh/sshd_config.d/99-ssh-guard.conf` | a file below a directory |
| `sshd_service_name` | `ssh` | |
| `per_source_max_startups` | `"5"` | empty: directive left out; `None` is refused while the drop-in is enabled |
| `max_auth_tries`, `login_grace_time` | `""` | empty: directive left out |

Values written into the files must not contain line breaks or other control
characters, so a value cannot add a directive of its own. The role's two
asserts (`maxretry`, `PerSourceMaxStartups`) are checked when the config is
built, each only for the enabled part.

`/etc/fail2ban/jail.d/ssh-guard.local` and the drop-in are byte-identical to
the role's templates (including the `# Managed by ops-library
ssh_guard_deploy. Do not edit.` header), `root:root 0644`; the drop-in
directory is `root:root 0755`. In the role's order: drop-in directory,
`fail2ban` from apt (no cache refresh, as the role's `package` task),
fail2ban enabled and started, jail file, drop-in.

- **fail2ban** is restarted (`systemctl restart`, which also starts a stopped
  unit) only when the jail file changed, right after it is written.
- **ssh**: only when the drop-in changed, `sshd -t -f /etc/ssh/sshd_config`
  checks the whole configuration. When it fails, the drop-in is removed and
  the deploy fails with `Invalid sshd config; removed <path>.`, before any
  reload (the role's `rescue`). When it passes, ssh is reloaded if it runs and
  started if not (the role handler's `state: reloaded`).
- A converged host reports no change and nothing is restarted or reloaded.

Differences from the role, on purpose:

- The fail2ban restart is not deferred to the end. The role's handlers do not
  run once the drop-in check fails, which leaves a written jail that fail2ban
  never loads (later runs see it unchanged). Here the jail is applied before
  the drop-in is checked.
- Only a failing `sshd -t` removes the drop-in. The role's `rescue` also
  removes it when writing the file fails (an upload or permission error),
  which would drop a valid earlier drop-in.
- Linux hosts with systemd and apt only. The role's `package` and `service`
  modules would also try other package managers and init systems.

Inherited from the role: with ssh stopped, Debian removes `/run/sshd`, so
`sshd -t` fails on that alone and a changed drop-in is removed (start ssh and
run again). A run interrupted between writing the drop-in and the check leaves
the file unchecked and not reloaded until it changes again.

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

## Tests

`tests/test_base_*.py` run each deploy against the fake connector: first run,
converged run (no change), drift and refusal cases, config validation, and the
authorized_keys and journald drop-in rendering against the vendored role
templates.

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
sshd, fail2ban and systemd. It is skipped unless `SSH_GUARD_DOCKER_CONTAINER`
holds the full ID of a running container named `ops-deploy-ssh-guard-*`,
labelled `ops-deploy.fixture=ssh-guard`, with `--network none`, not
privileged, no mounts and systemd as PID 1, built from `debian:trixie` with
`systemd systemd-sysv openssh-server fail2ban python3-systemd` (for example
`--cgroupns private --cap-add SYS_ADMIN --tmpfs /run --tmpfs /run/lock`,
`/sbin/init` after remounting `/sys/fs/cgroup` as cgroup2). pyinfra's Docker
CLI is wrapped so it can only inspect, exec and copy. The test covers the
first run, a converged run, jail drift (restart only), drop-in drift (check
and reload only), a value `sshd -t` rejects (drop-in removed, deploy failed,
no reload, sshd still running) and recovery, and a stopped ssh.
