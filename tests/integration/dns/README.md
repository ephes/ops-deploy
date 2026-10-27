# Owned DNS Linux qualification

Manual `DNS routine integration` runs only on a fresh GitHub-hosted Ubuntu24.04
systemd x86_64 VM. `implementation_sha` must be a full immutable Git SHA; the
workflow records the separately selected harness SHA. `run.sh` verifies both
checkouts, refuses existing DNS paths and creates an exclusive machine/run marker.
It does not accept an inventory host or credentials.

The production API installs Unbound, replaces an owned fixture resolver symlink
and is repeated. It then seeds all six exact obsolete DNAT rules across IPv4/IPv6,
plus unrelated NAT rules/chains and persistent files, first verifies an invalid candidate retains the legacy forwarding, then verifies selective removal
and metadata preservation, and repeats with no writes. The harness then adds an
unrelated nested absolute/glob include, exercises configuration change/repeat,
invalid candidate refusal with unchanged live files/PID, and a real one-shot
systemd restart failure with exact owned-file restoration. It installs DDNS
against a private network-namespace BIND primary with a dummy TSIG key, verifies
restricted A/AAAA updates/readback, authenticated endpoint output and no extra
updater execution on repeat. Immutable ops-library source56495f7 is rendered by
Ansible core2.21.5 to seed existing role files and independently generated bcrypt
credentials; the first deployment over that state and its repeat must be no-ops.
Every repeat traces the connector commands and rejects file/helper upload or
filesystem mutation syscalls, including temporary files later removed. It switches the endpoint to the existing pinned
Rust release, repeats, repairs deliberately drifted owned root metadata/staging
without binary replacement or process restart, repeats again, and returns to Python/repeats. No public DNS UPDATE occurs.

Phase JSON records all operations, managed mutations and protected file metadata.
Existing upstream blocklist/DNSSEC warnings are not silently repaired. The local
HTTP fixture supplies a small blocklist and test WAN addresses. Natural timer
activity must be distinguished from deploy-triggered writes; production timer
state must not be frozen for qualification. Native results remain pending until
an actual successful immutable run is linked in the deployment receipt.

The no-write scanner distinguishes dig naming its own short-lived threads via
`/proc/self/task/<tid>/comm` from persistent filesystem mutation: only successful
O_RDWR opens by a PID observed executing `/usr/bin/dig` are admitted. Other proc
paths, other processes, creates and ordinary file writes remain failures. The
fixture listener observer writes evidence only and never controls listeners.

Firewall evidence retains raw expected/actual iptables-save text. Policies, chain
and rule order, arguments and comments remain exact apart from generated/completed
timestamps. Packet/byte counters may advance, never reset: production removes
individual rules with `-D` and does not use restore or reload.

Explicit queries prove both source-address split views, generated blocklist
NXDOMAIN, an outside-ACL client REFUSED from the owned primary namespace, and
the unrelated nested include after a configuration replacement. Responses are
retained separately from deployment operation counts.

The owned VM retains its original non-loopback upstream DNS addresses in an
unrelated root-forward include after first recording the default localhost resolver
result for the actual release and discovered redirect hosts. This avoids
assuming the runner permits direct recursive DNS egress. The receipt records the
original uplink source/addresses and bounded system getaddrinfo before/after
and immediately before the Rust fetch. The fixture alone restarts Unbound to
activate this prerequisite include; subsequent deployment repeats preserve it.
It does not claim default-recursion success when that diagnostic fails. Loopback-only,
link-local/scoped, or malformed uplinks refuse before DNS fixture changes. No public inventory
resolver policy changes, and no unknown port-53 process is terminated.


Qualified run: [40508758685](https://github.com/ephes/ops-deploy/actions/runs/40508758685),
implementation `77e470f4761b4a22c00fb99af0ae46611e02813e`, harness
`e0376e5631960a6273a84ffdf6e8043f865b9822`:20 phases,10 no-write runs,
1,256 checked syscall traces. Default-recursive resolution also succeeded on
that VM; the prior Errno-5 failure is retained without an asserted cause. The
explicit fixture upstream activation and its PID change have a separate receipt.
