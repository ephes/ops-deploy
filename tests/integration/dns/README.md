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
Rust release, repeats, and returns to Python/repeats. No public DNS UPDATE occurs.

Phase JSON records all operations, managed mutations and protected file metadata.
Existing upstream blocklist/DNSSEC warnings are not silently repaired. The local
HTTP fixture supplies a small blocklist and test WAN addresses. Natural timer
activity must be distinguished from deploy-triggered writes; production timer
state must not be frozen for qualification. Native results remain pending until
an actual successful immutable run is linked in the deployment receipt.
