#!/usr/bin/python3 -I
"""Close TCP connections that are stuck on a withdrawn global IPv6 address.

When the router reconnects with a new delegated prefix, it announces the old
prefix with lifetime 0. Linux keeps the old address "deprecated" for two more
hours (RFC 4862 two-hour rule). New connections use the new address, but
established ones keep the old source address, whose packets the ISP now drops.
They hang until TCP gives up (tcp_retries2, about 16 minutes). This daemon
closes them right away so the application reconnects over the new prefix.

A connection is closed only when its local address is a global unicast IPv6
address (2000::/3), its peer is a global address outside every /64 of this
host (so it is routed via the uplink, not on-link), and either
  - the local address is no longer configured on this host, or
  - the local address is deprecated, AND another preferred global address
    exists in a different /64 (a replacement prefix is in place).
Deprecated privacy addresses share the /64 of a preferred address and are
never touched. A prefix that is only deprecated without a replacement (for
example while the uplink is down) is left alone, so those connections can
still recover. LAN connections on the old prefix keep working while it is
deprecated and are left alone too.
"""

from __future__ import annotations

import ipaddress
import json
import re
import selectors
import subprocess
import sys
import syslog
import time

GLOBAL_UNICAST = ipaddress.ip_network("2000::/3")
# ss -n prints IPv6 endpoints as [addr]:port, or [addr]%ifname:port when bound to a device.
SOCKET_ADDR = re.compile(r"^\[([0-9A-Fa-f:.]+)\](?:%[^\s:]+)?:(\d+|\*)$")
DEBOUNCE_SEC = 2.0
PERIODIC_SEC = 300.0


def log(message: str) -> None:
    syslog.syslog(syslog.LOG_INFO, message)


def run(args: list[str]) -> str:
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=30).stdout


Endpoint = tuple[ipaddress.IPv6Address, int]


def connected_sockets() -> list[tuple[Endpoint, Endpoint]]:
    """(local, peer) of connected TCP sockets with a global local address."""
    result: list[tuple[Endpoint, Endpoint]] = []
    for line in run(["ss", "-H", "-t", "-n", "-6", "state", "connected"]).splitlines():
        endpoints = [m for m in (SOCKET_ADDR.match(token) for token in line.split()) if m]
        if len(endpoints) < 2 or "*" in (endpoints[0].group(2), endpoints[1].group(2)):
            continue
        try:
            local = ipaddress.IPv6Address(endpoints[0].group(1))
            peer = ipaddress.IPv6Address(endpoints[1].group(1))
        except ValueError:
            continue
        if local in GLOBAL_UNICAST:
            result.append(((local, int(endpoints[0].group(2))), (peer, int(endpoints[1].group(2)))))
    return result


Addresses = tuple[
    set[ipaddress.IPv6Address], set[ipaddress.IPv6Address], set[ipaddress.IPv6Network], set[ipaddress.IPv6Network]
]


def host_addresses() -> Addresses:
    """Configured addresses, deprecated global ones, preferred-/64s, and all local global /64s."""
    configured: set[ipaddress.IPv6Address] = set()
    local64: set[ipaddress.IPv6Network] = set()
    deprecated: set[ipaddress.IPv6Address] = set()
    preferred64: set[ipaddress.IPv6Network] = set()
    for link in json.loads(run(["ip", "-j", "-6", "addr", "show"]) or "[]"):
        for info in link.get("addr_info", []):
            if info.get("family") != "inet6":
                continue
            try:
                address = ipaddress.IPv6Address(info["local"])
            except (KeyError, ValueError):
                continue
            configured.add(address)
            if address not in GLOBAL_UNICAST:
                continue
            local64.add(ipaddress.IPv6Network((address, 64), strict=False))
            if info.get("tentative") or info.get("dadfailed"):
                continue
            if info.get("deprecated") or info.get("preferred_life_time") == 0:
                deprecated.add(address)
            else:
                preferred64.add(ipaddress.IPv6Network((address, 64), strict=False))
    return configured, deprecated, preferred64, local64


def stale_sockets() -> list[tuple[Endpoint, Endpoint]]:
    # Sockets first: an address added after this listing cannot be mistaken
    # for a missing one.
    sockets = connected_sockets()
    if not sockets:
        return []
    configured, deprecated, preferred64, local64 = host_addresses()
    stale: list[tuple[Endpoint, Endpoint]] = []
    for local, peer in sockets:
        address = local[0]
        if peer[0] not in GLOBAL_UNICAST or ipaddress.IPv6Network((peer[0], 64), strict=False) in local64:
            continue  # on-link or local peer: unaffected by the uplink prefix change
        if address not in configured or (
            address in deprecated
            and preferred64
            and ipaddress.IPv6Network((address, 64), strict=False) not in preferred64
        ):
            stale.append((local, peer))
    return stale


def reap() -> int:
    closed: dict[ipaddress.IPv6Address, int] = {}
    for (address, port), (peer, peer_port) in stale_sockets():
        selector = ["state", "connected", "src", f"[{address}]:{port}", "dst", f"[{peer}]:{peer_port}"]
        if not run(["ss", "-H", "-t", "-n", "-6", *selector]).strip():
            continue
        subprocess.run(["ss", "-K", "-H", "-t", "-n", "-6", *selector], check=True, capture_output=True, timeout=30)
        closed[address] = closed.get(address, 0) + 1
    for address, count in sorted(closed.items()):
        log(f"closed {count} TCP connection(s) stuck on withdrawn IPv6 address {address}")
    return sum(closed.values())


def reap_logged() -> None:
    try:
        reap()
    except (subprocess.SubprocessError, OSError, ValueError) as error:
        log(f"reap failed: {error}")


def watch() -> int:
    monitor = subprocess.Popen(
        ["ip", "-6", "monitor", "address"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1
    )
    assert monitor.stdout is not None
    selector = selectors.DefaultSelector()
    selector.register(monitor.stdout, selectors.EVENT_READ)
    log("watching IPv6 address changes")
    reap_logged()
    next_periodic = time.monotonic() + PERIODIC_SEC
    while True:
        timeout = max(0.0, next_periodic - time.monotonic())
        if selector.select(timeout):
            if not monitor.stdout.readline():
                log("ip monitor exited; restarting via systemd")
                return 1
            # Let a burst of address/route updates settle, then drain it.
            deadline = time.monotonic() + DEBOUNCE_SEC
            while (remaining := deadline - time.monotonic()) > 0:
                if selector.select(remaining) and not monitor.stdout.readline():
                    log("ip monitor exited; restarting via systemd")
                    return 1
        reap_logged()
        next_periodic = time.monotonic() + PERIODIC_SEC


def main(argv: list[str]) -> int:
    syslog.openlog("ipv6-stale-socket-reaper")
    if argv[1:] == ["--once"]:
        return 0 if reap() >= 0 else 1
    if argv[1:] == ["--dry-run"]:
        for (address, port), (peer, peer_port) in stale_sockets():
            print(f"[{address}]:{port} -> [{peer}]:{peer_port}")
        return 0
    if argv[1:]:
        print("usage: ipv6-stale-socket-reaper [--once|--dry-run]", file=sys.stderr)
        return 2
    return watch()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
