# DNS resolver and DDNS

`ops_deploy.services.dns` ports the ordinary Unbound deployment, including its
blocklist updater/timer, RFC2136 DDNS updater/timer and optional authenticated
status endpoint. The private adapter adds the existing conditional Nyxmon check.
This is separate from authoritative BIND, router/DHCP configuration and DNS
removal. Current inventory applicability is macmini; implementation/native and
live qualification are pending while this candidate is developed.

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
