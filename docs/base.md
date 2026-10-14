# Base deploys

`ops_deploy.base` ports the base/bootstrap roles of ops-library. Each is a
typed config plus a `@deploy` function. Some are run on their own against a
host (hostname, unit masks, headless mode, shell basics, authorized keys), the
others are steps a service deploy calls (uv, Node.js):

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
| `ssh_authorized_keys` | `ssh_authorized_keys_manage` | `SshAuthorizedKeysConfig`, `AuthorizedKey` | `deploy_ssh_authorized_keys` |
| `uv_install` | `uv_install` | `UvInstallConfig` | `deploy_uv_install` |
| `nodejs_install` | `nodejs_install` | `NodejsInstallConfig` | `deploy_nodejs_install` |
| `shell_basics` | `shell_basics_deploy` | `ShellBasicsConfig` | `deploy_shell_basics` |

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
| `version` | `0.13.0` | change together with `checksums` |
| `checksums` | the role's sha256 for x86_64 and aarch64 Linux | keyed by release target |
| `install_dir` | `/usr/local/bin` | not `/` |
| `owner`, `group` | `root` | |
| `update_existing` | `True` | replace another installed version |
| `force_reinstall` | `False` | |

Installs when `uv` or `uvx` is missing, `uv` is a symlink, is another version (with
`update_existing`) or `force_reinstall` is set. One shell step downloads the
release archive into a private temp directory with `curl`, checks the sha256,
unpacks it and renames `uv`/`uvx` into place, then runs `uv --version`. `curl` is installed with apt first when missing.
Linux only (the role also handles macOS; macOS hosts are a later phase). The
role's deprecated `uv_create_symlinks`/`uv_symlink_dir` are not ported.

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

## Tests

`tests/test_base_*.py` run each deploy against the fake connector: first run,
converged run (no change), drift and refusal cases, config validation, and the
authorized_keys rendering against the vendored role template.
`tests/smoke/test_base_smoke.py` deploys each one twice on the
[smoke VM](concepts/smoke.md) (the second run must not change anything) and
checks the end state, including an SSH login with the managed key. It works on
a throwaway user, units and directories and restores the hostname, default
target and editor.
