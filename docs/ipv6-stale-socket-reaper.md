# IPv6 stale socket reaper

`infra.ipv6_stale_socket_reaper` installs a small daemon that closes TCP
connections stuck on a withdrawn global IPv6 address, so applications reconnect
over the new prefix within seconds instead of hanging for about 16 minutes.

## The problem

When the home router (here a FRITZ!Box) reconnects to the ISP, it gets a new
delegated IPv6 prefix. It announces the new prefix and the old one with
lifetime 0. Linux follows RFC 4862: the old address becomes *deprecated* and
stays configured for two more hours. New connections choose the new address,
but established TCP connections keep the old one as their source. The ISP
drops those packets without an answer, so the connection only fails when TCP
gives up retransmitting (`net.ipv4.tcp_retries2 = 15`, about 15–16 minutes,
also for IPv6).

tailscaled's long-poll connection to the coordination server is such a
connection. Observed on fractal and macmini (2026-11-10 and 2026-11-11): the
prefix changed at 03:05:40 UTC, tailscaled logged `LinkChange: major,
rebinding` and reconnected DERP (IPv4) at once, but the control connection on
the old IPv6 address only failed at 03:21:43 with `read: connection timed
out`. In between `tailscale status --json` reported `Self.Online = false`, and
Nyxmon's `Tailscale key expiry (fractal)` check (`$.summary.self_online`)
turned red every night.

## What the daemon does

`ipv6-stale-socket-reaper.service` runs `/usr/local/sbin/ipv6-stale-socket-reaper`
(Python, stdlib only). It follows `ip -6 monitor address`, waits two seconds for
a burst of updates to settle, and then checks the connected TCP sockets. It
also checks every five minutes in case it missed an event. It closes a single
connection with `ss -K` (matched by local and peer address and port) only when
its local address is a global unicast IPv6 address (`2000::/3`), its peer is a
global address outside every /64 of the host (so traffic goes through the
uplink), and one of these is true:

- the address is no longer configured on the host, or
- the address is deprecated **and** another preferred global address in a
  different /64 exists, which means a replacement prefix is in place.

What it leaves alone:

- LAN connections: a peer in one of the host's own /64s (old or new prefix)
  is reached on-link and still works while the old address is deprecated.
- Deprecated privacy (temporary) addresses. They share the /64 of a preferred
  address.
- A prefix that is deprecated without a replacement, for example while the
  uplink is down. Those connections may still recover.
- Unique local (ULA), link-local, and IPv4 traffic.

Each closure is logged once per address, with syslog tag
`ipv6-stale-socket-reaper`:

```text
closed 1 TCP connection(s) stuck on withdrawn IPv6 address 2a02:…
```

`ipv6-stale-socket-reaper --dry-run` prints the connections it would close now,
and `--once` runs a single pass.

The unit runs as root, with `CAP_NET_ADMIN` as its only capability (needed for
`SOCK_DESTROY`) and netlink/unix sockets only. It also needs
`CONFIG_INET_DIAG_DESTROY=y`, which Ubuntu kernels have.

## Usage

```python
from ops_deploy.infra import Ipv6StaleSocketReaperConfig, deploy_ipv6_stale_socket_reaper

deploy_ipv6_stale_socket_reaper(cfg=Ipv6StaleSocketReaperConfig())
# remove again:
deploy_ipv6_stale_socket_reaper(cfg=Ipv6StaleSocketReaperConfig(state="absent"))
```

| Field   | Default     | Meaning                                                        |
|---------|-------------|----------------------------------------------------------------|
| `state` | `"present"` | `"absent"` stops and disables the unit and removes both files. |

A changed script restarts the service. A changed unit reloads systemd and
restarts it. A converged host runs nothing.

## Verifying

```bash
systemctl status ipv6-stale-socket-reaper
journalctl -t ipv6-stale-socket-reaper
journalctl -u tailscaled | grep -E 'LinkChange|not-in-map-poll'
```

After a prefix change, tailscaled should show no `not-in-map-poll` warning, or
only a short one, instead of a 16-minute gap.
