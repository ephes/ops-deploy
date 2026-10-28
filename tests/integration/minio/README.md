# Owned MinIO native qualification

Prepared harness; no native success is claimed before a completed receipt.
A private read-only-token workflow downloads only the two SHA-bound pinned
executables, then anonymously checks out an exact public implementation SHA.
Public scripts build a fresh Ubuntu24 systemd guest on an owned x86 GitHub VM.
The guest shares the VM kernel; this is native executable execution, not QEMU.
No inventory, credential, source or Docker-socket bind mounts are used. Only
public source/tooling and verified artifacts are copied; an explicit environment
allowlist excludes GitHub/Actions credentials. No production lifecycle job runs.

Ansible runs in a separate virtualenv, preserving the locked pyinfra dependency set.
The guest verifies every actually installed package resource against Git and
its noneditable direct_url, plus both executable hashes/versions. It exercises
fresh service/buckets, the declared four synthetic identities/five policies,
healthy bash/fish repeats, original Ansible-role observation, top-level data-mode
repair, root-credential/missing-client/stopped-service admission refusals,
disabled/immutable/extra-attachment refusals, synthetic credential
rotation, retained enabled versioning and superseded policy cleanup. Each real
pyinfra phase records actual operations/uploads, before/after owned files,
IAM and synthetic object bytes/metadata, service PID/state, accounts and packages.
Healthy repeats require zero managed operations, zero uploads and strict scoped
snapshot equality. atime is excluded because reading can update it. MinIO's
other internal temporary/background paths are outside this bounded receipt;
there is no global-I/O claim. Expected faults and original Ansible recursive
chmod/alias/bootstrap writes remain separately classified with raw evidence.

The local ARM/QEMU CLI and helper probes are earlier mechanism research only.
They neither replace this native receipt nor qualify inventory deployment.
