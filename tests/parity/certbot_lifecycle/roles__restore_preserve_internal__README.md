# restore_preserve_internal

Internal task library for quiesced restore targets. Callers include `tasks/main.yml`
with `restore_preserve_path` and `restore_preserve_empty` (default `true`).
Requires Linux `findmnt`, `cp`, `rsync` and Python 3 on the managed host.

Ordinary directories are atomically renamed into a reserved timestamped sibling.
Mount points and `restore_preserve_empty: false` use an independent `cp -a` copy,
verified with a checksum and metadata rsync dry run before any live content is
cleared. Space checks reserve 10% or 16 MiB extra, whichever is larger.
Nested mounts and symlink targets are refused. Callers must stop all writers;
this helper does not synchronize concurrent restores or application writes.

Copies use `<live-directory>.pre-restore-<UTC timestamp>-<random suffix>`.
No success, failure or subsequent restore removes these copies. The owner
inspects and prunes them by hand. Read-only `tasks/preflight.yml` checks mounts and copy space before writers stop;
preservation repeats those checks on quiesced state. `tasks/validate.yml`
refuses overlapping live/staging/source paths and mutation of retained copies.
The helper prints a marked JSON record containing the copy path and original apparent
size in bytes (collected before any rename) before clearing and exposes `restore_preserve_report` for the
caller's final report. A failed copy can leave an incomplete sibling for manual
inspection, but leaves live data untouched. Check mode initializes a placeholder report and does not preserve or clear.

## Replacing directories from an archive

`tasks/replace_from_archive.yml` restores whole directories from a tar archive
whose members are stored by directory name (`letsencrypt/...`, `postfix/...`),
as `community.general.archive` writes them. Inputs: `restore_archive_src`
(archive path on the managed host), `restore_archive_root` (the parent, for
example `/etc`) and `restore_archive_allowed_tops` (directory names allowed
below it). The tasks:

1. run `files/archive_members.py`, which fails unless every member is a
   relative path below an allowed name, without `..`, present only once, and a regular file,
   directory, symlink or hardlink whose target, resolved through every
   symlink in the archive, stays inside its own directory, with no hardlink
   to a symlink (directly or through other hardlinks), no member stored below
   a symlink and every top-level entry a directory. Nothing has
   changed at this point;
2. extract into a `.restore-staging-*` directory inside `restore_archive_root`
   and check that every staged top-level entry is a directory;
3. for each directory present in the archive, preserve the live directory as
   described above and move the staged contents into the emptied directory,
   which gets the owner and mode of its pre-restore copy (of the staged
   directory when there was no live directory);
4. remove the staging directory, also after a failure.

`restore_archive_reports` lists one preservation report per directory. A
failure after preservation leaves the live directory empty or partly filled;
the retained copy is then the way back. Callers that stop services can run
`files/archive_members.py` themselves before stopping them, as `mail_restore`
does.
