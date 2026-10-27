# Linux apps native fixture: encrypted_volume and open_webui

`.github/workflows/linux-apps-integration.yml` qualifies
`ops_deploy.infra.encrypted_volume` and `ops_deploy.services.open_webui` on one
disposable GitHub-hosted Ubuntu 24.04 x86_64 VM. It runs on a push of the
feature branch that touches these files, or by `workflow_dispatch` with an
exact implementation commit. `run.sh` refuses anything but an owned
GitHub-hosted runner (root, systemd, x86_64, Ubuntu 24.04, the selected
commits checked out, no existing `openwebui` account, `/mnt/cryptdata`,
`/opt/open-webui`, `cryptdata` line or listener on port 3000). It never
reaches an inventory host.

The controller is the locked environment with ops-deploy reinstalled from
`git+https://github.com/ephes/ops-deploy.git@<sha>` (not editable,
`OPS_DEPLOY_PATH` unset); `run.sh` proves the installed package holds exactly
the files of that commit, byte for byte (`installed-artifact.json`).

Everything is synthetic and generated on the VM: a 512 MiB LUKS2 loop file
with an ext4 filesystem and a marker file, a second LUKS loop file (another
UUID), a plain ext4 loop file, the passphrase, the basic auth passwords and
the Open WebUI admin. `cryptsetup` is removed after the images are made, so
the first deploy installs it.

## Phases

Each deploy runs through pyinfra's API on `@local`. Repeats and refusals
(`zero`) run every command under `strace` and fail on any write syscall
(open for write, create, rename, unlink, chmod/chown, mount/umount, ...),
an upload, a mutating operation, a changed file/mount state or a changed
Open WebUI PID.

encrypted_volume: fresh (installs cryptsetup, writes the keyfile, opens,
records the crypttab line next to an unrelated one, adds the fstab entry,
mounts) and repeat; closed mapper reopened and mounted without touching the
recorded lines; lost crypttab/fstab lines restored without a remount; changed
fstab options rewritten and applied with `mount -o remount` only (same mount
ID, no umount); keyfile drift rewritten; refusals for a wrong LUKS UUID, a
non-LUKS device, a missing device, a read-only mount, a duplicate fstab entry,
the mapper name open on another device, the device mapped under another name
and a foreign mount at the mount point; recovery and final repeat; then the
`encrypted_volume_prepare` role of ops-library `cf3a0c74` (Ansible 14.5.0)
on the converged volume must report `changed=0` and leave every file and the
mount as they are, followed by a pyinfra repeat.

open_webui (data on the encrypted volume, `mounts_required`): fresh install of
open-webui 0.7.2 on uv-managed CPython 3.11.14 with the shipped constraints
(the installed distributions must all carry the constraint versions); a
synthetic admin signs up through the API; repeat; an environment change
(one restart, session still valid, secret key file and database kept) and a
basic auth rotation (route only, no restart), each with a repeat; the role's
`traefik` task file (as `rotate-traefik-basic-auth.yml` runs it) must leave
the pyinfra route byte for byte; a foreign listener on port 3000 and an
unmounted volume are refused before any change and recovered; a broken
interpreter link, a venv on another Python and a missing package are
repaired (recreate or reinstall from uv's cache) with the session, the
secret key file and the database kept, each followed by a repeat; final
repeats of both deploys.

Evidence (uploaded as `linux-apps-<run id>`): `summary.json`, one JSON per
phase, the strace files of traced runs, Ansible summaries, the installed
artifact proof, platform versions (kernel, cryptsetup, systemd) and the
Open WebUI journal.
