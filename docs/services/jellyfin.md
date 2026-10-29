# jellyfin

Port of the `jellyfin_deploy` Ansible role (with the `jellyfin_shared`
defaults it reads): the Jellyfin media server from the upstream apt
repository, run by the package's systemd unit, behind Traefik with basic auth
outside the internal networks. Deploy only: backup, restore and remove stay
with the Ansible roles.

```python
from pydantic import SecretStr
from ops_deploy.helpers import BasicAuth
from ops_deploy.services.jellyfin import JellyfinConfig, deploy_jellyfin

cfg = JellyfinConfig(
    repo_distro="ubuntu",
    repo_release="noble",
    repo_arch="amd64",
    traefik_host="media.example.com",
    media_directories=("/srv/media/video/movies", "/srv/media/video/tv"),
    media_dir_group="media",
    media_dir_mode="02775",
    mounts_required=("/srv/media",),
)
deploy_jellyfin(cfg, BasicAuth(user="admin", password=SecretStr(password)))
```

ops-control registers it with the basic auth secret from its Traefik SOPS
file (see its `docs/PYINFRA.md`).

## Basic auth

`basic_auth` is a [`BasicAuth`](../traefik.md) (user and password). It is
required while `traefik_enabled` and `basic_auth_enabled` are on (the role's
assertion) and refused otherwise; a `CHANGEME` password is refused. The
password never reaches the host: the bcrypt hash is computed on the
controller, and the hash already in the deployed route is kept while it
still matches the password (as the role does since ops-library 2.49.1), so a
converged host keeps its route file byte for byte. Errors never quote the
password.

## Configuration (`JellyfinConfig`)

Defaults follow `jellyfin_shared/defaults/main.yml` and
`jellyfin_deploy/defaults/main.yml` (`tests/test_jellyfin_parity.py`
compares them with the roles when `OPS_LIBRARY_PATH` is set).

| Field | Default | Notes |
|---|---|---|
| `repo_distro`, `repo_release`, `repo_arch` | required | the role derives them from Ansible facts; here they are fixed per host (see below) |
| `configure_repo` | `true` | keyring, list file and cache refresh; off: no repository step and no host check |
| `repo_base`, `repo_component` | `https://repo.jellyfin.org`, `main` | |
| `repo_key_url` | `None` | `None`: the role's `<repo_base>/<repo_distro>/jellyfin_team.gpg.key` |
| `repo_keyring`, `repo_list_file` | the role's paths | `/usr/share/keyrings/jellyfin-archive-keyring.gpg`, `/etc/apt/sources.list.d/jellyfin.list` |
| `packages_base`, `ffmpeg_candidates` | `jellyfin`, `apache2-utils`; `jellyfin-ffmpeg6`, `-ffmpeg5`, `-ffmpeg` | |
| `user`, `group` | `jellyfin` | owner of the data, config and log directories (`0750`) |
| `data_dir`, `config_dir`, `log_dir` | `/var/lib/jellyfin`, `/etc/jellyfin`, `/var/log/jellyfin` | |
| `media_directories` | the role's three `/mnt/cryptdata/media/video/...` roots | at least one; created when `create_media_dirs` |
| `media_dir_owner`, `media_dir_group`, `media_dir_mode` | `root`, `root`, `0755` | set exactly, special bits included (`02775` keeps setgid; `0755` clears it), as Ansible's `file` does |
| `mounts_required` | `()` | not in the role: mount points checked (read-only) before any change |
| `http_port` | `8096` | the route's backend and the health checks |
| `service_enabled` | `true` | the unit is always started (the role's `jellyfin_service_state` default) |
| `traefik_enabled`, `traefik_host` | `true`, `media.example.com` | |
| `traefik_entrypoints`, `traefik_cert_resolver`, `traefik_middlewares` | `web-secure`, `""`, none | plain names (YAML reads them back unchanged) |
| `internal_ip_ranges` | the role's five ranges | clients that skip basic auth |
| `basic_auth_enabled`, `basic_auth_remove_header` | `true`, `true` | without basic auth the route has the role's single `jellyfin-secure` router |
| `healthcheck_enabled`, `healthcheck_url`, `healthcheck_timeout`, `healthcheck_retries`, `healthcheck_expected_statuses` | the role's | `healthcheck_url` `None`: `http://127.0.0.1:<http_port>/` |

Not ported: `jellyfin_service_state` other than `started`, another
`jellyfin_traefik_config_path` (always `/etc/traefik/dynamic/jellyfin.yml`),
`jellyfin_basic_auth_password_hash` (the hash is always derived from the
password, reusing the deployed one), `jellyfin_https_port`,
`jellyfin_service_unit` and the backup/restore variables (other roles).

### Repository settings are fixed

The role picks the repository's distribution (`debian` or `ubuntu`, from
Ansible's `distribution`, falling back to `debian`), release (the release
codename) and architecture (`uname -m` mapped to `amd64`/`arm64`, falling
back to `amd64`) from facts on every run. Here they are configuration, and
the deploy reads `/etc/os-release` and `uname -m` while planning, maps them
exactly as the role does and refuses the host (before any operation) when
the result differs from the config. A distribution upgrade therefore stops
the deploy until the config follows it, instead of silently switching the
repository.

## What the deploy does

1. Checks the basic auth rules, that the host is Linux with `apt-get`, the
   repository settings (above) and every `mounts_required` mount
   (read-only `findmnt`).
2. **Repository key**: kept while the keyring exists, is not empty and is not
   ASCII-armored (`head -c 5`, read-only). Otherwise `curl` and `gpg` must
   be on the host (checked while planning: without them the deploy fails
   before any change; nothing is installed for them), and the
   key is downloaded into a private temporary directory, dearmored with
   `gpg --batch --yes --dearmor` and moved into place `root:root 0644`. The
   keyring's owner and mode are enforced either way.
3. **List file**: exactly the role's line,
   `deb [signed-by=<keyring> arch=<arch>] <repo_base>/<distro> <release> <component>`,
   `root:root 0644`.
4. **Packages**: `apt-get update` runs only before an install or after the key
   or list file changed. Missing base packages (`dpkg-query`; held packages
   and provided names count as installed, as for Ansible's `apt`) are
   installed with `apt-get install --no-remove` (`state: present`: nothing
   is upgraded, and an install that would remove a package fails instead).
   Then the ffmpeg pick: an installed `jellyfin-ffmpeg*` package (the one
   the `jellyfin` package depends on) satisfies it. Otherwise the deploy
   takes the role's pick, the first candidate whose `apt-cache policy` names
   a candidate version (`Candidate:\s+(?!\(none\))`), and installs it the
   same way; with none available a warning is logged and the deploy
   continues, as the role does. With the repository and the base packages
   in place while planning, that is decided while planning; otherwise one
   shell step makes the same decision after the base install.
5. **Directories**: data, config and log directory `jellyfin:jellyfin 0750`;
   the media directories with the configured owner, group and mode when
   `create_media_dirs`. Owner and group come from `files.directory`; the
   mode is compared with `stat -c %a` while planning and set with
   `chmod =<mode>`, which sets every bit (GNU `chmod 1777` would keep a
   directory's setgid bit, and pyinfra skips a zero mode). No other
   directory is touched, so a media root
   another deploy owns (a downloader's directory next to the library) can be
   left out of the list.
6. **Traefik route** with the role's own template (dual router: no auth
   from `internal_ip_ranges`, basic auth for everyone else; the HTTP router
   on `web` redirects). Traefik is never reloaded or restarted: its file
   provider watches the directory.
7. **Service**: `jellyfin.service` enabled (or disabled) and started. It is
   never restarted: the role has a restart handler, but no task notifies it.
8. **Health** (read-only): the port accepts connections (one try per second
   for `healthcheck_timeout` seconds), then the URL answers one of the
   expected statuses (`healthcheck_retries` tries, 3 s apart, redirects not
   followed).

A converged host gets read-only operations only (the mount check and the
health checks): no download, no `apt-get`, no upload.

## Parity with the role

`tests/test_jellyfin_parity.py` renders the vendored role template
(`tests/parity/ansible/jellyfin_deploy__jellyfin-traefik.yml.j2`, checked
against ops-library main `540ede2b`, 2.56.0) the way Ansible does and
requires a **byte-identical** route for several configs; the template the
deploy ships is the same file. With `OPS_LIBRARY_PATH` it also compares the
defaults, the repository line and key URL, the ffmpeg pick and the task
layout with the roles. `tests/parity/ops_library_roles.json` records
`jellyfin_deploy` and `jellyfin_shared`.

Differences:

- The role downloads the key on every run (`get_url force: true`) and
  dearmors it when the download changed; here the key is fetched only while
  the keyring is missing or armored, so a converged plan makes no network
  request. A key rotated upstream is not picked up by this deploy; the
  role's run (both write the same dearmored keyring) or removing the keyring
  does.
- The role refreshes the apt cache on every run (`update_cache: true`); here
  only before an install or after a repository change.
- The role downloads the key with `get_url` (Python on the host) and needs
  `gpg`; here `curl` and `gpg` must be installed when the key is
  (re)installed. They are checked, not installed: installing them would need
  an apt refresh, which fails while the Jellyfin source has no valid key.
- The role's `apt_repository` leaves an existing list file alone when the
  line is already present (in that file or any other source); here the list
  file must hold exactly the one line and is rewritten otherwise.
- Repository settings are fixed and checked, not derived from facts (above).
- The role runs `systemctl daemon-reload` on every run and reloads Traefik
  after a route change (restarting it when the reload fails); here neither.
- The ffmpeg pick. Current `jellyfin` packages depend on `jellyfin-ffmpeg7`
  (10.10, 10.11) or `jellyfin-ffmpeg8` (12.x), which conflict with the
  role's candidates (`jellyfin-ffmpeg6`, `-5`, plain `jellyfin-ffmpeg`):
  installing one of those would remove `jellyfin` and its ffmpeg. Here an
  installed `jellyfin-ffmpeg*` satisfies the pick and no install may remove
  a package (`--no-remove`). The role itself installs no candidate under
  ansible-core 2.19 and later: its pick regex sits in a folded YAML scalar,
  where the new templating keeps `\\s` as two characters, so it never
  matches and the role always reports "No jellyfin-ffmpeg package
  available" (seen on an Ubuntu 24.04 VM with ansible-core 2.21.5). Both
  therefore leave the `jellyfin-ffmpeg` that `jellyfin` depends on.
- `mounts_required` is an addition (empty by default).
- The bcrypt hash is computed on the controller; `apache2-utils` is still
  installed (it is one of the role's base packages).

Confirmed [removal](media-removal.md) is available through `JellyfinRemoveConfig`
and `deploy_jellyfin_remove`, preserving the original four-package purge and
independent keep flags. Media directories are outside its declared targets.
