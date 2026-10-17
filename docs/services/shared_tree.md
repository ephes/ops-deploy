# shared_tree

A directory tree that every member of one group may write: root owns it, the
group can write, and setgid directories keep new entries in the group.
Daemons that write there run with the group as their (P)GID and `UMASK=002`,
so imports can hardlink or move within one filesystem (the Servarr/TRaSH
layout). Port of ops-control's `playbooks/media/storage.yml` (the shared media
tree on macmini, `media_storage`).

```python
from ops_deploy.services.shared_tree import SharedTreeConfig, deploy_shared_tree

cfg = SharedTreeConfig(
    root="/srv/crypt/media",
    group="media",
    mode="2775",
    directories=("/srv/crypt/media", "/srv/crypt/media/video", "/srv/crypt/media/downloads"),
    foreign=("/srv/crypt/media/video/youtube",),
    mounts_required=("/srv/crypt",),
)
deploy_shared_tree(cfg)
```

The run:

1. `findmnt --mountpoint` for every entry of `mounts_required` (read-only;
   the run stops before any change without the mount);
2. the group (a system group);
3. every directory, `root:<group>` with `mode`;
4. the repair of what was copied in before the group model: entries without
   the group get it (`chgrp -h`), directories without group `rwx` and setgid
   get them, files without group `rw` get them. Each is found while planning
   (`find ... -print -quit`, read-only) and gets an operation only when
   something was found, so a converged tree changes nothing. `foreign`
   subtrees (owned by another deploy) are pruned.
