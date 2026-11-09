# Linux apps native fixture: encrypted_volume

`.github/workflows/linux-apps-integration.yml` qualifies
`ops_deploy.infra.encrypted_volume` on one
disposable GitHub-hosted Ubuntu 24.04 x86_64 VM. It runs on a push of the
feature branch that touches these files, or by `workflow_dispatch` with an
exact implementation commit. `run.sh` refuses anything but an owned
GitHub-hosted runner (root, systemd, x86_64, Ubuntu 24.04, the selected
commits checked out, no existing `/mnt/cryptdata`, `cryptdata` mapper,
keyfile or `cryptdata` line). It never reaches an inventory host.

The controller is the locked environment with ops-deploy reinstalled from
`git+https://github.com/ephes/ops-deploy.git@<sha>` (not editable,
`OPS_DEPLOY_PATH` unset); `run.sh` proves the installed package holds exactly
the files of that commit, byte for byte (`installed-artifact.json`).

Everything is synthetic and generated on the VM: a 512 MiB LUKS2 loop file
with an ext4 filesystem and a marker file, a second LUKS loop file (another
UUID), a plain ext4 loop file and the passphrase. `cryptsetup` is removed after the images are made, so
the first deploy installs it.

## Phases

Each deploy runs through pyinfra's API on `@local`. Repeats and refusals
(`zero`) run every command under `strace` and fail on any write syscall
(open for write, create, rename, unlink, chmod/chown, mount/umount, ...),
an upload, a mutating operation or a changed file/mount state.

encrypted_volume: fresh (installs cryptsetup, writes the keyfile, opens,
records the crypttab line next to an unrelated one, adds the fstab entry,
mounts) and repeat; closed mapper reopened and mounted without touching the
recorded lines; lost crypttab/fstab lines restored without a remount; changed
fstab options rewritten and applied with `mount -o remount` only (same mount
ID, no umount); keyfile drift rewritten; refusals for a wrong LUKS UUID, a
non-LUKS device, a missing device, a read-only mount, a duplicate fstab entry (mounted and with the mapper closed),
the mapper name open on another device, the device mapped under another name
and a foreign mount at the mount point; recovery and final repeat; then the
`encrypted_volume_prepare` role of ops-library `cf3a0c74` (Ansible 14.5.0)
on the converged volume must report `changed=0` and leave every file and the
mount as they are, followed by a pyinfra repeat.

The open_webui phases (fresh install, updates, route rotation, faults and
repairs) were removed with `ops_deploy.services.open_webui` when Open WebUI
was retired on 2026-11-09; they are in the git history.

Evidence (uploaded as `linux-apps-<run id>`): `summary.json`, one JSON per
phase, the strace files of traced runs, Ansible summaries, the installed
artifact proof, platform versions (kernel, cryptsetup, systemd) and the
tail of the boot journal.
