# Confirmed media removal

The public removal APIs port the original `navidrome_remove`, `metube_remove`
and `jellyfin_remove` roles. Each requires `confirm=True`; confirmation is
checked before host queries or effects. These are destructive operations.

```python
from ops_deploy.services.metube import MetubeRemoveConfig, deploy_metube_remove

deploy_metube_remove(MetubeRemoveConfig(confirm=True, remove_downloads=False))
```

All three expose `user`, `group`, `service_name`, `service_unit`,
`traefik_config_path`, `remove_user` and `remove_traefik_config`. Every literal
resource path may contain spaces. A finite set of named system, shared-media and
Traefik parent roots (listed by `PROTECTED` in the removal module), parent traversal,
root accounts and uid/gid zero are refused. Only selected path lstat, named unit
state and the named account/group metadata are collected. No password verifier,
configuration or media body is read for the removal plan. Metadata/tool failures
refuse before planned effects; genuine account/group and package removal errors
propagate. Route removal uses the existing Traefik transaction-lock guard;
a held transaction lock refuses route deletion, and earlier removal steps may
already have completed. The original service stop/disable and MeTube Traefik reload failures
remain tolerated.

| API | Original defaults and removal targets |
| --- | --- |
| `NavidromeRemoveConfig`, `deploy_navidrome_remove` | Stop/disable main service; remove main, rescan service and rescan timer unit paths, then reload systemd when a unit was present. Always remove `config_path` (`/etc/navidrome.toml`). `remove_data`, `remove_logs`, `remove_binary`, `remove_user`, `remove_traefik_config` each default true. Data/cache default `/var/lib/navidrome` and its `cache`; log `/var/log/navidrome`; installation `/opt/navidrome`, derived `bin_path` and `/usr/local/bin/navidrome` link. `rescan_service_unit` and `rescan_timer_unit` are independently configurable paths. No music-directory removal is declared. |
| `MetubeRemoveConfig`, `deploy_metube_remove` | Independent default true flags `remove_service`, `remove_env`, `remove_state`, `remove_install_dir`, `remove_user`, `remove_traefik_config` control unit, `/etc/metube`, `/var/lib/metube`, `/opt/metube` plus `ui_build_root` (`/var/cache/metube`), account and route. `remove_downloads` defaults **false**; only an explicit true removes `download_dir` (`/mnt/cryptdata/media/video/youtube`). Actual unit deletion schedules systemd reload at completion; actual route deletion schedules the original tolerated Traefik reload at completion. |
| `JellyfinRemoveConfig`, `deploy_jellyfin_remove` | Stop/disable main service; remove its distribution unit (`/lib/systemd/system/jellyfin.service`) and reload systemd when present. Default true flags `remove_packages`, `remove_config`, `remove_data`, `remove_logs`, `remove_user`, `remove_traefik_config`. Purge exactly `jellyfin`, `jellyfin-ffmpeg6`, `jellyfin-ffmpeg5`, `jellyfin-ffmpeg`, including residual config-files state. Config/data/log default `/etc/jellyfin`, `/var/lib/jellyfin`, `/var/log/jellyfin`. Media directories, repository/keyring and unrelated packages remain outside the declared targets. |

Default account and service names match the application. All route paths default
to `/etc/traefik/dynamic/<service>.yml`. The Navidrome default main/rescan units
live under `/etc/systemd/system`; the MeTube unit defaults there as well.
Overriding `service_name` does not implicitly change an independently configured
`service_unit`, matching the original shared variables.

`remove_user=True` preserves the original `userdel --remove` behavior: removing
the service user also removes its recorded home. A separate keep-data/download
flag cannot preserve content an operator placed inside that home. Use
`remove_user=False` as well when retaining such content. Group deletion follows
user deletion and rechecks existence because shadow-utils may already remove a
private group. Other accounts sharing the selected group can cause a genuine
failure; it is never silently treated as absence.

Absent resources converge to zero managed operations. Navidrome/Jellyfin's
unconditional original daemon reload is deliberately gated to actual unit-file
removal; package maintainer-script effects remain part of a genuine apt purge.
MeTube retains both original change-triggered handlers. A pyinfra `--dry` plan
may contain destructive proposals; planned changes are not executed or labelled
as successful removals. No live inventory destructive demonstration or deployment
count follows from owned fixtures. Backup/restore remain separate lifecycle work.
