# Operations

Custom pyinfra operations in `ops_deploy.ops`. Call them with keyword
arguments and a `name=`.

## `sync_tree`

Makes a remote directory mirror a controller directory with rsync over the
system OpenSSH (so `~/.ssh/config`, the agent and `ControlMaster` apply).
Replaces `ansible.posix.synchronize` and pyinfra's alpha `files.rsync`.

```python
from ops_deploy.ops import sync_tree

changed = sync_tree(
    name="Sync source",
    src=cfg.source_path,  # local directory; its contents are synced
    dest=cfg.site_path / "app",  # absolute remote directory
    user=cfg.user,  # optional: --chown=user:group (needs root)
    group=cfg.user,  # optional, defaults to user
    excludes=("data/", "*.sqlite3"),
    delete=True,  # default
    runner=rsync,  # injectable RsyncRunner
)
```

- **Change detection.** While planning, it runs
  `rsync --dry-run --itemize-changes`. No itemized lines means no change and
  nothing runs; otherwise a `FunctionCommand` runs the real rsync, so
  `changed.did_change()` is accurate for restart gating.
- **One dry run.** pyinfra runs an operation body at plan time and again while
  executing. The dry-run result is cached per host and operation, so rsync is
  asked once and execution acts on exactly what was planned.
- **Ownership is never preserved** (`--no-owner --no-group`). With `user` the
  files get `--chown=user:group`; without it they belong to the SSH user.
- **Content decides, not times** (`-rl --checksum`, no `-t`). Files are
  compared by checksum and their times are not synced, so a fresh clone of
  unchanged code (every file with a new mtime) is a no-op, and a time-only
  difference produces no itemized line. Directory times are left alone too
  (`--omit-dir-times`): the app writing into a synced directory (a
  `__pycache__`, a database) would otherwise show up as a change. The checksum
  costs nothing measurable on the nyxmon tree (118 files, three syncs): 0.65 s
  for the dry runs against macmini over LAN versus 0.69 s comparing times, and
  0.30 s versus 0.32 s on the smoke VM. Ansible's `synchronize` compares times,
  so the first Ansible run from another clone resyncs (and restarts) once.
- **Excludes.** `MANDATORY_EXCLUDES` (`.git`, `.venv`, `__pycache__`,
  `.ops-deploy-*`, `.pyinfra-*`) always apply, followed by `excludes`.
  Excluded paths on the host are not deleted by `--delete`, which is how state
  markers and data directories survive a sync.
- **Target.** `user@host` comes from host data `ssh_user` (default `root`) and
  `ssh_hostname` (default the inventory name); `ssh_port` adds `-p`,
  `ssh_key` adds `-i <key> -o IdentitiesOnly=yes`, and `ssh_known_hosts_file`
  and `ssh_strict_host_key_checking` add the matching `-o` options (the keys
  pyinfra's ssh connector reads).
- A failed dry run raises `RsyncError` while planning, before anything
  changes. A failed real run fails the operation.

## `secret_file`

Installs secret content at a path without it appearing in a command line,
pyinfra's output or a shared temp directory.

```python
from ops_deploy.core import SecretContent
from ops_deploy.ops import secret_file

secret_file(
    name="Write secrets",
    path="/home/app/site/.env",  # absolute; the directory must exist
    content=SecretContent(rendered_env),
    user="app",  # optional; chown needs root
    group="app",  # optional
    mode="0600",  # default
)
```

The content goes base64-encoded over the command's stdin to a small Python
program (`ops_deploy/ops/_secret_install.py`, run on the host as
`python3 -I -c <source> <dir> <name> <tag> <size> <mode> <user> <group>`; the
command line carries no secret material). It:

1. opens the destination directory one component at a time from `/` with
   `O_NOFOLLOW`, so a symlink anywhere on the path is refused, and does every
   later step relative to that descriptor;
2. reads the whole stream and checks the decoded length before creating
   anything, so an interrupted upload never touches the directory;
3. removes staging directories (`.ops-secret.<tag>.*`) that a killed earlier
   run left, after checking on the opened descriptor that each is the same
   private directory of the connecting user it saw in the listing;
4. creates a private 0700 staging directory `.ops-secret.<tag>.<random>` next
   to the destination, opens it with `O_NOFOLLOW` and checks the descriptor
   (a directory owned by the connecting user, no group or other permissions,
   empty), so other users who may write the destination directory cannot
   swap it or its contents;
5. creates `content` in it with `O_CREAT | O_EXCL | O_NOFOLLOW` and mode 0600,
   writes it, applies owner and mode with `fchown`/`fchmod`, `fsync`s it and
   renames it over the destination.

`<tag>` is a hash of the file name, so the leftover pattern never contains
glob characters. A failing step or `SIGHUP`/`SIGINT`/`SIGTERM` before the
rename removes the staging directory and leaves the destination as it was.
The rename is the commit point: the directory `fsync` and staging cleanup
after it are best effort and never turn an installed file into a failure.
`SIGKILL` cannot be handled; the next run removes the leftover (it runs even
when the content is already up to date if a leftover exists). Because nothing
is reopened by a path another user controls, a destination directory owned by
the service user is safe to write into as root.

The command always runs with `_get_pty=False` (a pty would echo stdin into the
output) and `_shell_executable="sh"`, whatever the deploy sets. The host needs
`python3` 3.8 or newer.

The operation reports no change when the file exists with the wanted mode,
owner (where given) and SHA-256 of the content, and no leftovers exist. A
destination that exists but is not a regular file (a directory or a symlink)
is an error; the installer would replace a symlink rather than follow it, but
the operation refuses it first.

Never use `files.put`/`files.template` or `_sudo` for secrets: pyinfra stages
`_sudo` uploads as plaintext in a temp directory. Connect as a user that may
write the destination instead.

`tests/test_secret_file_script.py` runs the installer as shipped and injects
faults: truncated streams, `SIGHUP`/`SIGINT`/`SIGTERM`/`SIGKILL` mid-stream, a
dropped connection, failing `write`, `fchmod`, `fsync` and `rename`, failing
post-commit steps, leftovers (including ones owned by the target user inside
and a symlinked one), a swapped staging directory, symlinked directories and a
symlinked destination.
