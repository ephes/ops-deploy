# Nikon archive synchronization components

`services.daybook_photos_archive_sync` carries the original one-writer archive
installation. All 35 role defaults and both dormant templates are retained.
The declared inventory hostname must equal the expected writer, and SSH must
connect directly as the declared non-root service user. Inherited sudo, doas,
dzdo and su settings are cleared on the actual facts, commands and transfer.
The installer does not substitute a root connection or provision an identity.

```python
from ops_deploy.services.daybook_photos_archive_sync import (
    DaybookPhotosArchiveSyncConfig,
    install_daybook_photos_archive_sync,
)

install_daybook_photos_archive_sync(
    DaybookPhotosArchiveSyncConfig(
        inventory_hostname="archive-writer",
        daybook_photos_archive_sync_enabled=True,
        daybook_photos_archive_sync_service_user="example",
        daybook_photos_archive_sync_repo_ref=source.commit,
        daybook_photos_archive_sync_repo_bundle_src=str(bundle),
        daybook_photos_archive_sync_expected_smb_server="nas.example.invalid",
        daybook_photos_archive_sync_expected_writer_host="archive-writer",
    ),
    source,
    bundle,
)
```

The controller must bind one exact Main revision and a local bundle advertising
only that revision as `refs/heads/main`. The original controller Main resolver
and derived canonical bundle lifetime can be reused by a private binding.
No mutable target fetch, alternate source selector or force-checkout option is
introduced. The installed owner-private bundle is checked against its actual
digest before Git changes. An indexed dirty checkout is refused; an interrupted
original `--no-checkout` clone with no index resumes without replacing its Git
directory. Existing source and environment continuity remain observable.

The exact configured uv-managed Python patch and frozen dependencies are
installed as the connecting owner. A nonstarting virtual environment is rebuilt.
Pure source/environment observations never run an archive command. The original
`daybook --help` smoke runs application code as an explicit managed operation on
every converge, including a current repeat. It is never labelled read-only or
zero managed work. Git/build/sync/help actions retain the original unbounded
managed command lifetime; bounded metadata probes are separate.

`enabled: false` remains an inert no-op, not an uninstall or emergency disable.
General installation uses `launchd_enabled: false`: it disables and unloads only
the declared label before writes and verifies that state afterward. The original
plist has `RunAtLoad: true` and no `Disabled` key; its persistent launchctl
disabled override is therefore essential. A separately authorized activation
may select `launchd_enabled: true`; the original enable/bootstrap/verification
and failed-activation disable/bootout behavior are retained. This public option
does not establish real activation qualification or change an operator's
existing confirmation/attendance policy.

The generated launcher contains the original bounded Photos SQL privacy
preflight, exact SMB identity and one-way archival execution. Installation never
runs that launcher, opens the Photos database, lists the camera working folder,
mounts/authenticates a share, initializes a ledger or reads a folder map/log
body. Data declarations remain outside its source/resource operations. It
changes neither TCC permissions nor the Full Disk Access policy required for a
later explicit background run.

Source tests compare the original defaults/templates, actual SDK operation
ordering and all inherited privilege switches. Owned Git tests cover clean and
dirty trees, interrupted clone continuity, nonstarting environment recovery and
data-body refusal. The disposable hosted-native fixture uses only an inert
package, owned paths, a loopback user SSH server, synthetic state and a separate
keeper. Native execution and real inventory first/repeat are distinct gates;
source tests alone establish neither. An offline writer is not qualified by a
cached online status.

The fixture first constructs a normally validated original declaration, then
deliberately uses pydantic `model_copy` to substitute its private temporary paths
and unique labels. Those substitutions are not revalidated against production
`/Users/` and `/Volumes/` constraints. The receipt makes that bypass explicit:
it qualifies the mechanism under owned paths. Source tests separately exercise
the original writer/path/schedule validation; this is not a claim of native
validation of a real inventory declaration.
