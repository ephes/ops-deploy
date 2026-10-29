# DNS resolver and DDNS

`ops_deploy.services.dns` ports the ordinary Unbound deployment, including its
blocklist updater/timer, RFC2136 DDNS updater/timer and optional authenticated
status endpoint. The private adapter adds the existing conditional Nyxmon check.
This is separate from authoritative BIND, router/DHCP configuration ; removal is a separate confirmed lifecycle operation below. The ordinary private adapter applies to macmini. Native Ubuntu 24.04
qualification covers installation, changes, recovery and no-write convergence;
inventory rollout records belong in the private operator repository.

`DnsConfig` supplies explicit split networks, views, forwarders, local records,
cache settings and DDNS inputs. LAN address, Tailscale address and CPU count come
from the target unless explicitly provided. Packages use present-only convergence;
there is no latest-version resolver or incidental package upgrade. Installed
DNSSEC anchors, generated blocklists, DDNS history and unrelated includes remain
owned by their existing services. The allowlist deliberately follows the actual
role's `dns_whitelist_domains` template behavior, including its static entries;
it does not reinterpret the historically unused `dns_allowlist` default.

Configuration comparison runs in memory with request data on stdin. A converged
call stages nothing. A changed candidate copies the complete existing Unbound
configuration tree and generated blocklist tree, rewrites include paths into that
candidate (including nested non-`.conf` and external absolute includes) and runs `unbound-checkconf` before changing owned files. Only five
owned snippets/allowlist files can be replaced. Failed restart or split-view
verification restores their original bytes, modes and owners. Unrelated files
are never rollback targets. A real configuration change restarts Unbound, which
can disrupt in-flight queries and lose cache; a no-op preserves the process and
cache. No cache/query content is exported as proof.

Periodic jobs are not deployment hooks on a converged host. Initial empty
blocklist state is populated once; existing lists are retained. A changed DDNS
updater/configuration is run once, accounting for the timer’s `Requires=` start,
and its normal timer continues. Restarting a changed timer may itself run its
required service; that is counted as part of the changed deployment. A bounded
read-only wait observes the already queued service job and requires terminal
success, without starting a duplicate invocation. The TSIG key is
passed through protected secret-file transport, never process arguments; an
existing verifying htpasswd file retains its bytes. Endpoint Python/Rust choice
uses the existing pinned metrics-httpd implementation helpers. Native tests use
only a dummy isolated RFC2136 primary; they never update public DNS.

The endpoint opts into `_metrics_httpd.select(check_when=...,
transient_check_is_mutation=True)`: a sandbox validation runs after actual input
changes, new/repaired binary installation or a Rust drop-in/runtime switch, and
counts as a mutation. Converged DNS repeats skip transient unit creation. Other
callers retain the helper's historical default behavior; this is not a claim that
all metrics endpoints have adopted this stronger no-write contract.

See `tests/integration/dns/README.md` for the owned native fixture. A successful
fixture does not itself claim inventory deployment. Actual immutable artifact
and standard dispatcher first/repeat receipts are required for that claim.

Legacy firewall cleanup admits both IPv4/IPv6 runtime and persistent rules before
mutation. It selects only the role's six obsolete port53-to5335 DNAT rules; all
other rules/chains remain untouched. Missing tools or an explicitly absent NAT
table are distinguished from unknown read failures, which refuse deployment. A
converged host performs no firewall write or temporary staging.


## Qualification

[Native run40508758685](https://github.com/ephes/ops-deploy/actions/runs/40508758685)
passed20 phases using implementation `77e470f4761b4a22c00fb99af0ae46611e02813e`
and harness `e0376e5631960a6273a84ffdf6e8043f865b9822`. Ten no-write runs
(including role-seeded first deployment) preserved files/PIDs and passed1,256
actual syscall traces. The fixture also verifies selective legacy firewall
cleanup, configuration refusal/rollback, authenticated DDNS, Python/Rust switches,
and owned Rust layout repair followed by a no-write repeat. Its explicit upstream
activation is fixture setup, separate from deployment/no-op accounting. Historical
failed runs are retained; an earlier release-host resolution failure has no
claimed root cause. See the fixture README for the evidence boundaries.


## Confirmed removal

`DnsRemoveConfig(confirm=True)` and `deploy_dns_remove` preserve the original
Unbound/DDNS removal route. It stops/disables the six named services/timers,
removes the declared DDNS resources and account/home, purges Unbound including
residual package configuration, deletes its named cache/state leftovers, removes
only the five original UFW allow rules and three named Ansible root cron entries,
and cleans the declared Pi-hole leftovers. Unrelated cron/rules remain intact.
The original stopped/disabled blocklist unit files are retained; their mere
presence does not trigger repeated daemon reloads. Removal creates no backup.

`restore_systemd_resolved=True` retains the original enable/start, tolerated local
listener wait and stub symlink policy; a missing distribution unit uses the fixed
public fallback resolver. False leaves resolver configuration alone. Custom role
paths remain supported, and a DDNS state path is removed only when its basename
contains `ddns` and the original literal nested-absolute-path regex matches.
The raw state-variable spelling is retained: trailing `/` or `/.` and root-level
literal `/ddns` remain original skips. The predicate is spelling-sensitive:
`/./ddns`, `///ddns` and `/.//ddns` match the original raw expression and select
that same root-level directory for removal. No canonical-path equivalence is
assumed by this legacy condition; account/home removal remains independent.
The confirmation and bounded path checks precede mutation.
Account existence uses `pwd.getpwnam` metadata, without a broad user/shadow fact.
Required package/path metadata errors refuse; optional unit/firewall/account/cron
cleanup keeps the source's explicit tolerance and does not label unknown state
absent. A repeat with known absent resources performs no managed changes; the
optional resolved listener wait remains a read-only TCP connection, not a DNS query.
Owned package/account/cron/UFW/systemd tests establish component behavior only;
no destructive inventory removal has been performed or qualified by them.

Lifecycle custom paths accept ordinary spaces while retaining absolute-path,
parent-traversal and bounded-resource checks. Shell metacharacter/control-character
admission remains unchanged; the shared deploy/backup path policy is unchanged.
