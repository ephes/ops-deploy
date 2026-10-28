# Prepared offline KVM fixture

This alternate transport is prepared, not executed or qualified. The private
GitHub run40651848171 failed before allocation because of an account billing
annotation. No token or billing setting is changed by this alternative.

The reviewed private wrapper transports only the selected public runner and two
SHA-bound licensed executables over existing root SSH, and supervises an owned
tmux session. All bootstrap, checks, VM logic and evidence handling are public in
this directory. No private inventory/configuration is copied into either guest.

The host needs existing Docker and writable `/dev/kvm`; no host apt, kernel,
firewall, authentication, sudoers, binfmt or service setting is changed. Image
build prepares a clean Ubuntu24 root filesystem, kernel/initrd and exact public
controller/dependencies anonymously. It never starts MinIO or runs its tests.
The actual tooling container has no network, host ports, host filesystem or
socket mounts, capabilities or privileged flag. Its only host device is
`/dev/kvm`. The real guest also has no network device. A read-only ISO transports
only `mc` and `minio`; the guest generates every credential and data object.
No guest SSH key or new transport protocol is needed.

QEMU uses `accel=kvm` with no software-emulation fallback, and QMP must report
both KVM present and enabled. The guest separately proves x86_64, systemd PID1,
KVM virtualization, its fresh per-run marker/machine identity, no non-loopback
network interfaces, and the full actual installed Git resource set, bytes and
noneditable direct_url. This is native CPU virtualization, not physical-device
attestation. GitHub-hosted environment variables are explicitly refused in this
mode; the receipt identifies an independent KVM guest kernel.

Bounds: guest2vCPU/4GiB and an8GiB regular disk image; tooling2CPU/5GiB with swap
limited to the same ceiling,256PIDs; image build2CPU/5GiB and40minutes, guest45minutes,
16MiB each serial/QEMU log and256MiB total evidence. Guest receipt extraction
first admits at most1024 flat regular files totalling192MiB from debugfs metadata;
symlinks, nested directories and unsafe names are refused before copy-out. Docker runtime logging is capped at
20MiB. At least32GiB on Docker's actual data-root filesystem,512MiB on the owned
transport filesystem and6GiB available memory are required
before build. Image layers/root filesystem and writable disk can consume more
than the8GiB guest-visible capacity; the preparation uses fixed package/source
sets, and the run keeps no unbounded guest storage source.

The classic Docker builder is selected so this fixture's labelled intermediate
images can be removed without pruning shared BuildKit caches. If that builder is
unavailable, the run fails before VM launch; it must not silently switch builders.
Cleanup selects only the fresh owned label/nonce, removes that run's containers
and images, verifies absence, and removes copied source/binaries/Docker config.
Small private evidence and the failure exit remain in the owned host directory
for retrieval. Shared pre-existing Ubuntu layers and peer resources are retained.
Failure evidence includes the original build/guest logs, actual exits, image and
container metadata, QMP result, and bounded extracted guest receipts.

No build, download or VM launch on an inventory host is authorized by this file.
Use the exact reviewed immutable source under the coordinator's execution GO.

Guest evidence is admitted from debugfs metadata before body extraction (flat regular files, at most 1024 files and 192 MiB). Docker copy-out independently rejects links/special files/path escapes and stops before any body that would exceed 256 MiB. This also applies during failed-run cleanup; bounded partial evidence is retained.
