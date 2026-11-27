# Root writes in service homes

> **Planning record.** This design was written after Ansible was removed
> from ops-control on 2026-11-16 and ops-library was archived on 2026-11-18.

Status: design, 2026-11-24. Nothing here is rolled out. Step 0 and the code of
step 1 (chesslab) are merged; the evidence listed under "Evidence the pilot
change must bring" is recorded in `docs/services/chesslab.md` and the tests it
names. Every rollout step below is a class-B live change and needs its own
window and its own plan review.

## Problem

A deploy connects as root. Several shared building blocks then write, as root
and by path, into directories that belong to the service user:

| Building block | What root does | How a service user can redirect it |
|---|---|---|
| `sync_tree(user=...)` | the remote rsync runs as root with `--delete` and `--chown` into `<home>/site` | `site` itself replaced by a symlink: the destination argument is resolved by name, so root mirrors the source into the link's target, deletes what is not in the source and hands the files to the service user. (Recent rsync receivers refuse a destination symlink owned by another user; the hosts' versions are not all that recent, and the deploy must not depend on it.) A symlink *inside* the tree at a place where the source has a directory is replaced, not followed, with the flags in use (`-rl`, no `--keep-dirlinks`); what remains inside the tree is the receiver's path-based handling under a concurrent swap, which rsync has had to fix more than once |
| `files.put`, `files.template`, `record_source`, wrapper scripts | with the direct root connection, pyinfra writes the final path over SFTP and then runs `chown`/`chmod` by path (through `sudo` it would stage in a temp file and `mv`) | a symlink planted at the destination: the SFTP write itself follows it and root overwrites the link's target. Or a swap between the write and `chown`: root changes owner and mode of the link's target |
| `system_user(directories=...)`, `files.directory` | `mkdir -p`, `chown`, `chmod` by path below the home | the same swap; the plan-time fact only refuses a link that exists while planning |
| `chown -R` / `chmod -R` repairs | recursive walk as root | a hard link to a root-owned file inside the tree (only where `fs.protected_hardlinks=0`), or a directory swapped during the walk |

`secret_file` is much better and still not sufficient in a directory the
service can write. Its host program opens every path component with
`O_NOFOLLOW`, stages in a private directory and sets owner and mode on a
descriptor, so a symlink cannot redirect it. But not following symlinks does
not make a name trustworthy when the service can rename entries in the
directory:

- it recognises leftovers of a killed run by name prefix plus "directory,
  owned by the installer's user, without group or other permission bits" and
  empties them; the service can give that name to another such directory;
- it creates its staging directory and then opens it by name; the service can
  put another root-owned private directory there in between;
- the walk accepts any real directory; below a service-writable ancestor the
  service can substitute a real directory it cannot write itself, and root
  then replaces or removes entries in it.

The first two need a root-owned private directory within the service's reach,
which no deploy creates on purpose. The third needs less: any real directory
the service can move into place but not write itself, for example one owned
by another account, or a root-owned one with mode 0755, on the same file
system. The design nevertheless does not build on a
stronger installer; it stops pointing the installer at such directories
(section 3).

Affected deploys with these patterns today: opaq_app, django_site, work_app,
chesslab, fastdeploy, nyxmon, archive (named in the finding), and by the same
helpers haushalt, homelab, echoport, graphyard, logyard, mailgun_relay,
voxhelm, opsgate, static_site, weeknotes_home, daybook_operations_api, toy and
toyweb. The same pattern exists outside `home`/`site_path` and outside the
deploy entry points: metube removes a file below its service-owned site as
root, minecraft_java manages descendants of its service-owned tree as root,
and work_app's restore runs a recursive root `chown`. The scope of "closed" is
defined under "Closing the finding".

## Threat model

**Attacker.** Code execution as one service user, for example through a
vulnerability in the web application. The attacker stays for days, can prepare
the service's home at leisure, can watch for a deploy (inotify, process list)
and can swap paths while it runs.

**Goal.** Root on the host, or write access to another service's files, at the
next deploy.

**What the attacker already has, and this design does not take away.** Every
file the service user owns: its code, its virtual environment, its `.env`, its
database. A compromised service can already change its own code and keep the
compromise across restarts. Only the alternative "root-owned releases" below
addresses that.

**In scope.**

- Writes, deletes, owner and mode changes that root performs by path below a
  directory the service user can write.
- Races between a plan-time fact and the command that acts on it.
- Hard links inside a tree that root later walks.

**Out of scope.**

- An attacker who is already root, or who controls the controller.
- Root *reading* through a planted symlink where the result goes only to the
  controller (facts such as `stat` or `sha256sum`). A probe whose output a
  later root command trusts is in scope and is listed in the per-service
  audit.
- Kernel bugs.

**In scope, although not a root write by a deploy command.**

- *Root programs that write as a side effect of reading.* chesslab's user
  probe runs `sqlite3 -readonly` as root on the database in the service's
  `data` directory; a read-only connection to a WAL database can create or
  update the `-shm`/`-wal` files next to it. Such probes run as the service
  user (section 2).
- *Root entering a service directory before dropping privileges.*
  `cd <site> && runuser ...` resolves `site` as root and hands the directory
  to the unprivileged program as its working directory, also when the service
  user could not have reached it. The `cd` moves inside the unprivileged
  command (section 2).
- *Privileged reads whose result reaches the service.* A unit's
  `EnvironmentFile=<site>/.env` is read by systemd as root at every start and
  its content is given to the service. With `.env` in a directory the service
  can write, a link to another service's environment file discloses that
  service's secrets. This is a read, not a write, but it crosses the boundary
  this design defends; section 4 moves environment files out of
  service-writable directories.
- *Root executing a file from a service-writable directory.* No shared helper
  does it. fastdeploy keeps the scripts it runs through `sudo` in
  `/usr/local/libexec/fastdeploy`, outside the service's reach; that boundary
  stays. The per-service audit records any other case as its own finding.

**New surface the design adds.** With the sync running as the service user, the
remote rsync process belongs to that user, and the controller's rsync parses
what it sends. On a host with `kernel.yama.ptrace_scope=0` the attacker could
take over that process; with any setting it may influence it through the files
it reads. The controller is the sender. The known attack of this kind
(CVE-2024-12086, a server reading arbitrary client files) is fixed in rsync
3.4.0, but one fixed CVE is not a proof: the residual risk is a compromised
service attacking the controller's rsync through a parser bug not yet known.
Before, that needed root on the host. Mitigations: the controller runs a
supported, security-patched rsync (checked and recorded per rollout, at least
3.4.0), the host has `ptrace_scope >= 1` (the Ubuntu default), and the sync
source on the controller is a clean checkout, not a directory with other
material in it. The alternative that avoids this surface (root-owned staging)
is kept as the fallback.

**What `runuser` gives, and what it does not.** The command runs with the
service user's UID, primary GID and supplementary groups, outside the unit's
systemd sandbox: `ProtectSystem`, `ReadWritePaths` and the like do not apply to
it. The boundary of a deploy command is therefore the user's file permissions,
not the unit's hardening. Each rollout records `id` as run through the exact
`runuser` invocation.

## Invariant

> Root does not write below a directory a service user can write. There, a
> deploy changes the file system as that service user; what root must own
> lives where every ancestor is root's.

For authors this gives two cases, and no third:

1. What belongs to the service inside its directories is written as the
   service user. A redirected write then reaches only what that user could
   write anyway.
2. What root must own (units, routes, root-only configuration, environment
   files systemd reads, stamps) lives outside service-writable directories:
   `/etc/systemd`, `/etc/traefik`, `/etc/<service>`,
   `/var/lib/ops-deploy/<service>`.

An installer that refuses symlinks was the first idea for a third case, "root
writes carefully inside the service's directory". The review of this design
showed why that does not hold (see `secret_file` under "Problem"): a careful
walk can pin the inode it acts on, but below a service-writable directory it
cannot know that the name still means what the deploy meant.

## Design

### 1. Code sync as the service user

`sync_tree` gets `run_as` (implemented for the pilot as the separate
operation `sync_tree_as_user`, see open decision 5). The controller still
connects as root, but the
remote side of both the dry run and the real run is

```
cd / && runuser -u <user> -- sh -c 'test -d <dest> && test ! -L <dest> && exec rsync "$@"' rsync --server ...
```

set through `--rsync-path`. `--chown` is dropped: the files belong to the user
because the user creates them. `run_as` excludes `user=` and `group=` and needs
`ssh_user` root. Every `runuser` invocation of a deploy has this one form,
without `-g`: the process gets the account's primary group and its
supplementary groups from the user database, as the unit's `User=` does. (With
`-g`, util-linux sets an explicit group list instead, so two forms would mean
two sets of credentials to verify.) A service whose files need a group other
than the user's primary group is not converted before its account is fixed;
the deploy checks this read-only. `runuser` executes the program directly, so a `nologin` shell
does not matter, and it is the mechanism `uv_sync` and `django_manage` already
use. The `cd /` keeps root's working directory out of the unprivileged
process. The guard runs as the service user at the moment of the transfer, as
the existing `prepared_by` path does for its transfers. It is a correctness
check, not the security boundary: it stops rsync from creating a missing last
component and refuses a destination that is a symlink when it looks. It checks
by name, so a swap between the check and rsync's own resolution, or a
symlinked ancestor, gets past it. The boundary is the process's UID: whatever
path rsync ends up in, it can only change what the service user may change.

First deploy. `sync_tree` runs its dry run while pyinfra plans, before any
queued operation has created the account or the destination. With `run_as`,
when the user or the destination directory does not exist yet at plan time,
there is no dry run: the operation counts as a change and runs the real
transfer at its place in the order, after `system_user`. If the account or
directory is still missing then, `runuser` or the guard fails and the deploy
stops. Unit tests cover both failures; the smoke test covers a missing
destination.

Consequences:

- A symlinked `site` leads the rsync only to places the service user may
  write. Against a target the user may not write it fails with "Permission
  denied" and the deploy stops; root changed nothing.
- A file in the tree that the service user does not own is *not* protected by
  rsync: the owner of the directory can replace or delete it, so the sync
  replaces it with a service-owned copy. Root-owned files that are meant to
  stay root-owned must not live in a service-writable directory at all
  (section 4). The ownership audit in the migration finds such files; it is a
  check of expectations, not something rsync enforces. A foreign-owned
  *directory* without write permission for the user does make the sync fail.
- Linux only for now. The macOS path (`rsync_path`, `prepared_by`) keeps its
  behaviour; combining it with `run_as` is rejected. macOS services run in the
  owner's account and are not part of this finding.

### 2. Directories and commands below the home as the service user

`system_user` keeps creating the home itself as root. That is only safe when
no ancestor of the home can be replaced by anyone but root. From the first
opt-in (`directories_as_user=True`) the deploy therefore checks, read-only and
before any change, that every ancestor of the home from `/` down is a real
directory (no symlink) owned by root and not writable by group or others, and
that an existing home is a real directory owned by the service user. A host
that fails the check is not converted until its layout is fixed; there is no
warning-only mode. The home keeps being created by root, by path, under that verified chain,
also after step 3.

Directories below the home are created by the service user
(`runuser -u <user> -- mkdir -p -m <mode>`). An existing directory
with the wanted owner, group and mode is a no-op; a wrong mode is corrected by
the user itself; a wrong owner, a symlink or a non-directory fails the deploy
with a pointer to the migration step, and root does not repair it by path.

Commands that run as the service user enter their directory as that user:

```
cd / && runuser -u <user> -- env HOME=<home> ... sh -c 'cd "$1" && shift && exec "$@"' sh <dir> <argv...>
```

instead of `cd <dir> && runuser ...`. `uv_sync` and `django_manage` get this
form behind a parameter, so unconverted services keep their exact commands;
a converted service uses it for every command, including read-only probes
that open application data (chesslab's `sqlite3 -readonly` user probe and its
migration check).

### 3. Files: as the service user inside, by the installer only outside

**Inside service-writable directories** every file operation runs as the
service user, in the command form of section 2, with the content on standard
input (never in an argument, so the same operation carries secrets):

| Operation | Replaces | How |
|---|---|---|
| `user_file(path, content, run_as, mode)` | `files.put`, `files.template`, `secret_file` and `record_source` in service directories | the user writes a temporary file next to the destination and renames it over it |
| `user_directory`, `user_link`, `user_remove` | `files.directory`, `files.link`, `files.file(present=False)` in service directories | `mkdir`, `ln -s`, `rm` as the user |

Whatever the service does to these paths while the deploy runs, the write has
the service's own rights. Step 3 specifies these operations in their own
reviewed change.

**Outside**, `secret_file` and its host program stay as they are, with one
addition that turns the invariant into a check: `trusted_parents=True`
requires every directory from `/` to the destination directory to be a real
directory owned by root and not writable by group or others. The operation
checks this read-only while planning, before it decides that nothing needs to
be written, so a converged call fails as well. Directories that do not exist
yet while planning (a fresh `/etc/<service>/` queued in the same deploy) are
allowed there: the plan-time check covers the ancestors that exist. The
installer checks the complete chain again on the descriptors it walks, before
it writes, and by then every directory must exist. In a directory only root can
change, the weaknesses listed under "Problem" have no attacker.

The parameter stays opt-in. The lint test of "Closing the finding" requires it
for every `secret_file` call in a converted service's modules. Callers outside
the service conversions keep today's behaviour, notably
`ssh_authorized_key_entries`, which writes into account-owned `.ssh`
directories on Linux and macOS. That is the same class of problem for login
accounts instead of service accounts; it is not part of this finding and is
recorded for an audit of its own.

There is no operation that hands existing inodes to the service user
(`chown -R` done safely), and none that deletes a tree as root below a
service-writable directory. Foreign-owned entries are migrated by copy, see
"Migration".

### 4. Nothing root reads for a service, or keeps root-owned, in a service-writable directory

- Environment files named in a unit's `EnvironmentFile=` move to
  `/etc/<service>/` (`root:<group> 0640`, directory `root:root 0755`), written
  by `secret_file`. The service can read its own file and cannot replace it.
  Applications that read `.env` from their working directory themselves get
  the path through the unit instead. This is a layout change per service and
  is rolled out with the service's conversion; where an application insists on
  `<site>/.env`, the file is written by `user_file` and the unit does not
  name it.
- Root-owned stamps and markers (`.ops-deploy-users`, `.ops-deploy-source`)
  move to `/var/lib/ops-deploy/<service>/`. In a service-writable directory
  the service can delete or replace them whatever their owner.
- A root-owned subdirectory inside a service-writable directory is *not* a
  safe place: the service can rename it away and put its own in its place.

### Closing the finding

"Closed" covers every entry point ops-deploy ships for a service (deploy,
remove, backup, restore, lifecycle actions and the host scripts they install)
and every path a service user can write, not only `home` and `site_path`:
data directories, media, caches, runtime directories.

1. A per-service audit lists the service-writable paths and every privileged
   operation on them, including indirect ones through helpers and host
   scripts. Known today beyond the deploys named above: metube (root
   `files.file` below the site), minecraft_java (root-managed descendants of
   the service tree), work_app restore (recursive root `chown`).
2. A lint test forbids `files.put`, `files.template`, `files.directory`,
   `files.link`, `files.file`, `sync_tree(user=...)` and `chown`/`chmod` shell
   commands in the modules of a converted service, with an explicit allow-list
   per call site that states why the path is not service-writable. The lint
   catches the direct patterns; the audit, kept in the service's documentation,
   is what covers the rest. An empty list of unconverted services plus the
   audits closes the finding; the lint alone does not.

### What stays as it is

- `secret_stdin`, and `secret_file` outside service-writable directories.
- Everything else outside service-writable directories.

## Alternatives

| Alternative | Why not (now) |
|---|---|
| **Root-owned releases**: code in `/opt/<service>/releases/<commit>`, owned by root and not writable by the service; state in a separate service-owned directory | The strongest answer: it also stops a compromised service from changing its own code. It changes the layout of every service (virtual environment built by root or a build user, `__pycache__`, apps that write into the site: SQLite files, media, collected static files), every backup target and every restore procedure. Worth its own decision by the owner; the invariant above is a precondition for it either way, because state directories stay service-owned. |
| Sync into a root-owned staging directory outside the home, then copy from there as the service user | Keeps the network-facing rsync root-owned (no new surface towards the controller), at the price of a second full copy per deploy. Kept as the fallback if `run_as` shows problems in the pilot. |
| A root installer that refuses symlinks, used inside service directories | The first idea, and what `secret_file` does today. Not sufficient where the service can rename entries, see "Problem" and "Invariant". |
| rsync as root with `--no-implied-dirs`, `--safe-links`, `--munge-links` | These govern links *in the transfer*, not links already on the receiver; the destination argument itself is still followed. rsync's receiver works by path and has had race fixes in this area more than once. |
| Stop the service and lock the account during a deploy | Does not help: the attacker prepares the links before the deploy. |
| `chattr +i` or mount options on the home | Breaks the applications that write there; does not cover the swap of a parent directory. |
| Deploy over SSH as the service user | Needs a login shell and a key per service user, which widens every service account. `runuser` gives the same effect without it. |
| Leave it, rely on `fs.protected_symlinks` | That sysctl only covers sticky world-writable directories such as `/tmp`, not a home. |

## Migration

Services fall into three classes. The class is established per service by a
read-only audit recorded in the rollout plan of that service.

1. **Tree already owned by the service user throughout** (the sync has always
   used `--chown`, nothing else is written by root): chesslab, archive. The
   conversion is a code change. A read-only audit before the window
   (`find <site> -xdev \( ! -user <user> -o ! -group <group> -o -type d -perm -2000 \)`)
   must print nothing: without `--chown`, new files take the group of a
   setgid directory, so group inheritance in the tree is part of the audit.
2. **Tree service-owned, with some root-written files** (`files.put` of
   wrapper scripts, `record_source`, a recursive `chown` that keeps it that
   way): opaq_app, haushalt, work_app, django_site, nyxmon, homelab, echoport
   and the smaller ones. Those writes move to `run_as`, `user_file` or out of the directory, and
   the recursive `chown` is removed, since nothing creates foreign-owned files
   any more. What is foreign-owned at that point is listed by the audit and
   replaced *by copy, as the service user*. The normal sync does not do this:
   it compares checksums and skips an unchanged file whoever owns it. A
   one-time step copies each listed regular file to a new inode and renames
   it over the old one (the user needs to read the file and write the
   directory, which gives it nothing it did not have). The audit `find` must
   print nothing afterwards. Foreign-owned directories and data trees too
   large to copy are not handled by a helper: the service is not converted
   until a plan of its own has dealt with them.
3. **Root-owned files inside a service-writable directory on purpose**
   (fastdeploy's site metadata with its `chown root` repair): the root-owned
   part moves out of the service-writable directory. The scripts fastdeploy
   runs through `sudo` already live in `/usr/local/libexec/fastdeploy` and
   stay there. This needs a layout change and is planned separately.

Order, least critical first; each line is one class-B change with its own plan
review:

| Step | Service(s) | Host | Notes |
|---|---|---|---|
| 0 | the building blocks of sections 1 and 2 (`ops_deploy.services._service_home`: `sync_tree_as_user`, `user_directories`, `as_user`) | none | merged with the pilot's code; no other deploy uses them until its service converts |
| 1 | chesslab: sync, directories, probes | macmini | pilot, class 1; separate code change, then its window |
| 2 | archive: the same | macmini | class 1 |
| 3 | `user_file` and its siblings, the installer's ancestor check, the copy step, lint test; environment files and stamps out of the homes (section 4), first for chesslab and archive | none, then macmini | code, then one class-B change per service because the unit changes and the service restarts |
| 4 | toy, toyweb, static_site, opaq_app, haushalt | smoke VM, macmini | class 2 |
| 5 | django_site on staging, then production sites one by one | staging, production | class 2; homepage and python_podcast last |
| 6 | work_app, weeknotes_home, homelab, voxhelm, opsgate, graphyard, logyard, mailgun_relay, daybook_operations_api | macmini and others | class 2 |
| 7 | nyxmon, echoport | macmini | class 2; monitoring and backup, after the pattern has run elsewhere for a week |
| 8 | fastdeploy | macmini | class 3, own layout plan |
| 9 | remove, backup, restore and lifecycle entry points; metube, minecraft_java | per service | from the audits |
| 10 | no unconverted service left, audits recorded, `sync_tree(user=...)` to a service home rejected | none | closes the finding |

## Rollout plan for the pilot (chesslab, class B)

The pilot has two stages. Stage A queues no operation that changes the host
(its only effects are the permitted physical SQLite changes defined below);
stage B is the first routine deploy with the converted code.

- **Stage A, verify only.** The pilot change adds `verify_only` to chesslab's
  configuration. With it set, the deploy function queues nothing that can
  change the host: no account or directory step, no packages, no dependency
  sync, no `.env`, no migrations, no unit, no restart, no Traefik route, no
  Echoport or Nyxmon wiring, no stamp. It runs the read-only checks (ancestors of the
  home, the ownership and group audit, `id` through `runuser`), the sync's
  dry run as `chesslab`, and the deploy's own convergence predicates as
  `chesslab`, the same code stage B uses to decide: the virtual
  environment's interpreter is executable, the migrations are current, and
  the application users need no update (database rows *and* the
  `.ops-deploy-users` stamp against the configured secrets). The stamp is
  `root:root 0600` in the home and is read by root in both stages; the result
  goes only to the controller, where it is compared with an HMAC. Because
  `chesslab` controls the directory and could put a FIFO or a symlink there,
  the pilot replaces today's `cat` by a bounded read: opened with
  `O_NOFOLLOW | O_NONBLOCK`, accepted only if the descriptor is a regular
  file owned by root with mode 0600 and at most a few hundred bytes; anything
  else counts as "no stamp", which is pending work and fails stage A.
  Everything else runs as `chesslab`. The unit test uses the production owner
  and mode. It fails if the
  dry run itemizes a change or a predicate reports pending work, so drift that
  would make stage B sync dependencies, migrate, update users or restart is
  found here, without acting on it.

  Stage A writes nothing as root in the service's directories and queues no
  mutating operation. The converted deploy's planning probes open the
  database as `chesslab` and read-only, in both stages: the user probe with
  `sqlite3 -readonly -init /dev/null` (as `chesslab` the shell would otherwise
  run that account's `.sqliterc`, which could write files or change the
  output; a unit test and the smoke run have one present), and the migration check by running Django's
  `migrate --check` with the connection switched to the SQLite URI
  `file:<db>?mode=ro`. A read-only connection cannot checkpoint and cannot
  roll back a hot rollback journal; a database that needs that fails the
  probe, which is a stop. In WAL mode it can still create or touch the
  `-shm`/`-wal` sidecars (including rebuilding a missing shared-memory
  index), as the running application does all the time. These are the
  *permitted physical SQLite changes*; wherever this plan says that nothing
  on the host changed, it means: nothing apart from them and, once stage B
  has planned, the permitted neighbour effects described below. The Python probes run with
  `PYTHONDONTWRITEBYTECODE=1`, so they write no bytecode.

  A probe that fails (as opposed to one that reports pending work) aborts
  planning in the converted deploy, in both stages: today `probe()` returns
  nothing on failure and the callers then schedule the migration, the user
  update or the Echoport/Nyxmon upsert and probe again, which would turn an
  unreadable database or an unreachable neighbour into a write. The pilot
  change keeps "failed" and "pending" apart for all of chesslab's probes, the
  two database probes and the two wiring probes, and has tests that stage B
  executes no operation after an error of each.

  The read-only rule and the permitted changes are about chesslab's own
  directories and database. The Echoport and Nyxmon wiring probes are not run
  in stage A at all. In stage B they run the same queries as in every routine
  chesslab deploy, as those services' users with those services' normal
  database connections, while pyinfra plans. Whatever a query on such a
  connection does physically to the neighbour's database (sidecars, a
  checkpoint, recovery of a hot journal), and whatever bytecode Python writes
  into the neighbour's `__pycache__` directories while importing, it does
  today at every deploy;
  these are the *permitted neighbour effects*, and the chesslab baseline does
  not see them. The pilot changes two things about the wiring: its check and
  apply commands enter the neighbour's site as that service's user (the
  command form of section 2, not `cd` as root), and an error of a probe
  aborts instead of scheduling an upsert.

  These limits describe an account that is not compromised. Programs run as
  `chesslab` use that account's own configuration and code; what a
  compromised account makes them do, it does with its own rights, which is
  the point of the design. The stop rules do not depend on it.

  Two operations of stage B open the database for writing, and only when
  they execute: `migrate` (migrations pending, or the source or the
  dependencies changed) and `ensure_admin` (a user or profile differs, or the
  stamp does not match the secrets). Stage A rules their triggers out
  beforehand, but stage B plans again.

  The listing of precondition 4 records path, owner, group, mode, type and
  link target of every entry of the home on its own file system (`-xdev`:
  nothing mounted below it is covered; precondition 1 shows that nothing is),
  without `.venv`, `__pycache__` directories and the two sidecars. The
  virtual environment is left out because routine checks may write bytecode
  there as `chesslab` (the trust check imports packages with `python -I`,
  which ignores `PYTHONDONTWRITEBYTECODE`); that is permitted. That its
  packages did not change is covered by the execution record (the dependency
  sync did not run), not by the listing. It does not record
  the database's size, times or content, and it cannot: the running
  application writes to it. That the deploy did not write to the database is
  established by the execution record instead: neither `migrate` nor
  `ensure_admin` ran. An incomplete record is a stop.
- **Stage B, routine deploy.** `verify_only` is removed and chesslab is
  deployed normally. pyinfra plans again and decides conditional steps while
  it executes, so nothing can promise that this run is a no-op, and the plan
  does not claim it. Its risk is that of any chesslab deploy today: the
  operations on Traefik, Echoport and Nyxmon are the unchanged code every
  routine deploy already runs, and they only act when their inputs differ.
  The expectation, with fixed inputs, is no change and no restart; it is
  checked afterwards, and a deviation is investigated before the pilot counts
  as verified.

What the pilot changes on the host: who runs the remote rsync, who creates
`site` and `data`, and who runs the commands and probes in them. It does not
move `.env` or the stamp: after the pilot `secret_file` still writes both as
root into chesslab's directories, with the weaknesses listed under "Problem",
until step 3. Expected effect on macmini: none. The tree is already
service-owned and identical, so stage B is expected to be a no-op without a
restart.

### Evidence the pilot change must bring (before any window)

- Unit tests for the new parameters, for chesslab's commands and for
  `verify_only` (no mutating operation is queued, on a converged host and on
  one with pending changes; a dry run that itemizes a change fails the run).
- A smoke run on the lima VM (Ubuntu 24.04) with three cases:
  1. *Normal deploy with a changed source.* The real transfer runs; the logged
     remote command is the `runuser` form without `--chown`, and the new file
     on the VM belongs to `chesslab`. Without `--chown` a root receiver would
     leave it root-owned, so the owner proves the real receiver's effective
     UID. A repeat deploy is a no-op. `runuser -u chesslab -- id` is recorded.
  2. *Missing destination.* With `site` removed and the account, `data` and
     the database in place (the fixture provides the database, which the
     deploy never creates and still checks first), one deploy recreates the
     tree as `chesslab` and ends healthy. A host without the database stops at
     the database check before the sync, as today.
  3. *Redirected site, whole deploy.* `/home/chesslab/site` is replaced by a
     symlink to a directory outside the home; the source gets a changed file;
     the deploy runs again. Required: the deploy fails.
  4. *Redirected destination, `sync_tree(run_as=...)` alone*, without the
     directory guard of case 3 in front of it, for the dry run and for a
     forced real run, against two targets: the root-owned one (the receiver
     must not be able to change it even if the guard were absent), and a
     directory `chesslab` owns (the guard must refuse a stable symlink; that
     target is unchanged too).

  The root-owned target of cases 3 and 4 is `root:root 0755` with a few files
  and a subdirectory, none of it writable by `chesslab`. For every target a
  recursive listing with owner, group, mode, type, link target and content
  hash is taken before and after each attempt and must be identical, whatever
  the exit status.

### Preconditions, checked read-only on macmini before and again inside the window

1. `find /home/chesslab/site /home/chesslab/data -xdev \( ! -user chesslab -o ! -group chesslab -o -type d -perm -2000 \)`
   prints nothing (no foreign owner or group, no setgid directory that would
   give new files another group); `stat` shows `/home/chesslab`, `site` and `data` as real
   directories owned by `chesslab:chesslab`, and `/` and `/home` as real
   directories owned by root without group or other write permission;
   the list of mount targets (`findmnt -rn -o TARGET`) contains none equal to
   `/home/chesslab` or below `/home/chesslab/`.
2. `sysctl kernel.yama.ptrace_scope` is at least 1; the controller's rsync is a
   supported release, at least 3.4.0; `runuser` exists on the host;
   `runuser -u chesslab -- id` (the one form every command of the
   pilot uses) shows only the expected UID, GID and groups, and `chesslab` is
   the account's primary group.
3. Pinned inputs: the chesslab source commit and the effective configuration
   are the ones currently live (compared on the controller: the deployed
   commit, and the rendered unit, route and `.env` hash against the host's
   files), so the only difference to the live state is the ops-deploy pin. The
   rendered Traefik route and the basic-auth verifier are part of that
   comparison: the window permits no change to a shared service, and a route
   change would restart `traefik.service`. Check and deploy run back to back
   from the same checkout with the same decrypted secrets, without a fetch in
   between. The
   *old* pin is not run against the host for a baseline: its plan contains the
   root `sqlite3` probe this change removes.
4. A listing for comparison: `find /home/chesslab -xdev -printf '%p %u %g %m %y %l\n'`
   without `.venv`, `__pycache__` and SQLite's `-wal`/`-shm` sidecars;
   `ActiveEnterTimestamp` and `NRestarts` of `chesslab.service` and of
   `traefik.service`; modification time and SHA-256 of the unit file, the
   Traefik route file and `.env`. All of it is recorded before stage A.

Every check command must succeed; a failing or empty-when-it-should-not-be
check stops the window before the pin changes.

### Steps

1. Stage A. From a fresh ops-control checkout: pin the ops-deploy commit and
   set `verify_only` for chesslab; `just pyinfra-check`, then
   `just deploy-one chesslab`. Both must succeed. The output shows the remote
   command of the dry run,
   `runuser -u chesslab -- sh -c 'test -d /home/chesslab/site && ...' rsync`,
   and no itemized change. Afterwards the complete baseline of precondition
   4 is compared and must be identical (listing, both services' counters,
   modification time and hash of the three files); stage B does not start
   otherwise. Any failure is handled by the ordered rules under "If
   something goes wrong".
2. Stage B. Remove `verify_only` (a second ops-control commit, same pin);
   `just pyinfra-check`, then `just deploy-one chesslab`, back to back.
   pyinfra's report is read like this, for this check and for the follow-up
   check in step 3 alike. Chesslab's read-only checks always count as
   "changed" because they are shell commands: the port preflight, the
   database check, the trust verification, the health check and the probes;
   the unit test `test_second_run_changes_nothing_mutating` pins that list
   (`READ_ONLY`), extended by the new read-only checks of the pilot. The
   operations with a condition decided during execution are listed as
   conditional changes: the dependency sync, the migrations, the daemon
   reload and the restarts (the same unit-test fixture shows the full list
   for a converged host; the pilot change records it in chesslab's
   documentation). During the deploy pyinfra prints "No changes" for each of
   them when its condition is false. Any operation outside these two lists
   that the check reports as changing stops the window before the deploy.
3. Verify. The report alone does not establish that nothing mutating ran; the
   host does:
   - in the deploy output, the operations that ran commands are exactly the
     read-only list, and every conditional one reports "No changes"; in
     particular neither the migration nor the user operations ran;
   - `ActiveEnterTimestamp` and `NRestarts` of `chesslab.service` and of
     `traefik.service` are as before; the unit file, the route file and
     `.env` have their old modification time and hash;
   - the complete baseline of precondition 4 is identical;
   - `curl` on the host against `http://127.0.0.1:10019/healthz` returns 200
     with `{"ok": true}` (the deploy's own health check does the same), and
     the public route answers with authentication as before;
   - the receiver identity: `sync_tree` logs the remote command of each rsync
     run (added in the pilot change, because the runner captures output and
     logs nothing on success), and the deploy output shows the guarded
     `runuser -u chesslab -- sh -c ...` command for the dry run. A no-op
     deploy runs no real transfer; that the real transfer uses the same remote
     command is shown by the smoke evidence and by unit tests, and on macmini
     by the next chesslab deploy that carries a code change (owner of the new
     files, and the logged command);
   - a second `just pyinfra-check` shows no change.

### If something goes wrong

One rule decides, in this order:

1. **Stop** whenever the host may not be what the plan assumed: "Permission
   denied" from the sync, a path that changed unexpectedly, a symlink where a
   directory is expected, a failing audit or ancestor check, a dry run in
   stage A that itemizes a change, a stage B that was not a no-op, a restart
   of chesslab or Traefik, a listing that differs in any entry, or any failure
   whose cause is not identified. Stopping means: no further deploy of any
   version in this window, no retry, no repair by path as root. In particular
   the previous version is not deployed: its root rsync is exactly what must
   not run over a destination that cannot be trusted. The service keeps
   running as it is; the paths and outputs are recorded and the owner decides.
   A later recovery works as the service user (`runuser`) only. A transfer
   that was interrupted leaves only service-owned files behind and waits for
   that decision like everything else.
2. **Revert the controller** only when rule 1 does not apply and there is
   affirmative evidence that no mutating operation started: the failure
   happened in stage A (which has none), or in stage B while pyinfra was still
   planning, before it executed the first operation; its cause is identified
   and lies in the new code or its requirements (for example `runuser`
   missing on the host, a bug in `verify_only`); and the complete baseline of
   precondition 4 compares as identical. A failure after stage B began to
   execute, or an incomplete execution record, is rule 1: the baseline does
   not cover the database, installed packages or the Echoport and Nyxmon
   wiring. Reverting means reverting the ops-control commits of this window
   together, the pin and the `verify_only` setting (the previous ops-deploy
   does not know that field). No deploy is needed after the revert: nothing on
   the host changed. An identical baseline and an empty execution record
   establish exactly this: no operation ran, and chesslab's directories are
   as before. They do not exclude the permitted physical SQLite changes nor,
   if stage B had started planning, the permitted neighbour effects, both of
   which every routine deploy has today. The next routine chesslab deploy then runs with the
   previous code, as it would have without the pilot.

## Open decisions for the owner

1. Window for the chesslab pilot (step 1), then archive (step 2).
2. Environment files in `/etc/<service>/` and stamps in
   `/var/lib/ops-deploy/<service>/` (section 4). This changes the layout of
   every converted service and restarts it once. Without it a compromised
   service can read another service's environment file through systemd at its
   next restart.
3. Whether "root-owned releases" should become the target layout later. It
   does not change steps 0 to 7; it would replace steps 8 and 9 and add a
   layout migration per service.
4. Whether macOS services are to be covered by the same invariant. They run
   in the owner's account, so a compromised service there already has the
   owner's rights; the proposal is to leave them out.
5. The size cap of the shared layer. Sections 1 and 2 describe the sync and
   the directories as parameters of `sync_tree` and `system_user`. The shared
   layer is at 1,699 of 1,700 code lines, so the pilot implements them as
   separate functions in `ops_deploy.services._service_home` (about 110 code
   lines), with the same behaviour. Moving them into `sync_tree` and
   `system_user`, as written above, needs the cap raised by about that much;
   leaving them where they are needs no decision.
