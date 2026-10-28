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

The first owned attempt stopped before guest boot: Docker's default build resolver
could not resolve the public Ubuntu mirrors. A bounded disposable probe showed
public HTTP egress working and public DNS at `1.1.1.1` resolving both mirror names.
Each networked build step now selects that resolver only in its ephemeral
container resolver mount; failed apt index retrieval is fatal. This changes no
host DNS, Docker daemon, firewall or routing setting. The final tooling container
and real guest remain offline. The failed receipt is retained separately and
provides no native service qualification.

The DNS probe covered only the two public Ubuntu mirror names and public Ubuntu
HTTP egress. GitHub, PyPI, Python download hosts and redirect/CDN destinations
were not separately preflighted. Their real bootstrap fetches remain fallible
build steps whose complete result must be preserved; the resolver correction
is not evidence that every dependency endpoint is reachable. The guest receipt
records its actual Ubuntu release, machine ID, run identity and kernel.

The second attempt built the image but Docker rejected tooling-container startup:
its local logging driver does not allow compression with `max-file=1`. The runner
explicitly disables compression for this container while retaining `max-size=20m`
and `max-file=1`, as supported by the [Docker local logging options](https://docs.docker.com/engine/logging/drivers/local/#options).
No guest or MinIO process started in that attempt; its failure and successful
owned-resource cleanup remain separate evidence.

The third attempt started tooling but its five-second QMP socket read timed out
after the greeting, before enabled-KVM admission completed. Empty serial/QEMU
logs did not establish guest boot or the cause of the delay. The query now has
one 60-second total admission budget and a timestamped request/reply transcript;
it still requires an identified response with KVM both present and enabled.
This does not extend the overall 45-minute guest limit or permit emulation.
The failed attempt remains separate from any later native proof.

The fourth attempt recorded KVM present and enabled, booted the independent
Ubuntu guest, and completed fresh MinIO/IAM deployment plus healthy bash/fish
repeats with zero managed operations and uploads. The original Ansible comparison
then failed because its apt module tried to install missing `python3-apt` in the
offline guest. That dependency is now installed during image bootstrap alongside
`apache2-utils`; the actual guest still has no network interface. The failed
original-role observation (including its earlier change) remains separate from
successful pyinfra phases. Recovery and remaining fault cases were not reached,
so this partial run does not qualify the complete service migration.

The fifth attempt reached all 28 healthy/recovery/refusal phases, including 13
strict zero-change repeats, but failed its final foreign-alias assertion. The
fixture had mutated the expected alias to the newly rotated root credential;
the unrelated alias was originally imported with the old credential. Original
Ansible normal/missing-client/stopped-service observations succeeded; its root
rotation failed after changing the environment, and pyinfra safely refused that
untouched half-applied state before writes. Those raw results remain retained.
File-level snapshots and the runtime preservation guard do not substitute for
an independent per-phase semantic alias proof. The fixture now keeps a separate
immutable baseline and records equality plus differing field names, never
credential values, before and after every pyinfra/original-role phase. A negative
local test changes the actual foreign alias and proves the comparison rejects it.
The failed run remains incomplete qualification; no runtime resource changed.

After the MinIO matrix writes its own successful summary, a separately scoped S4
component runs the checksum-bound, unmodified `20b721bb` lag probe and its owned
driver against the same loopback synthetic server and exact mc binary. Current
fixture credentials travel only in-memory through stdin. The driver owns two new
synthetic buckets and `/srv/s4-owned-lag-20b` state, testing six healthy/failure/
recovery calls; its status and marker writes are expected managed effects. Its
separate receipt and any post-MinIO error do not overwrite the MinIO summary.
This proves neither the typed S4 deployment nor composite, hardware or inventory
behavior. Both copied fixture inputs are hash-checked before execution; no server
configuration, admin action, external network or production data is involved.
