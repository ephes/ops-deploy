"""Checks of the ``metrics_httpd_switch`` role (rust/metrics-httpd/PLAN.md 7.2).

The role writes a consumer role's metrics-httpd command line into a systemd
drop-in (``ExecStart=``) and passes it to ``systemd-run`` for
``--check-config``; after the switch it probes the endpoint from the host.
The decisions that keep that safe live here as plain functions, so they are
unit-tested directly (``tests/test_metrics_httpd_switch.py``):

- ``metrics_httpd_argv_problems``: what makes a command line unsafe to write
  into ``ExecStart=`` (systemd specifiers, environment expansion, quoting and
  escapes, control characters) or not a metrics-httpd command line;
- ``metrics_httpd_sandbox_problems``: the ``systemd-run --property`` list;
- ``metrics_httpd_probe_host`` and ``metrics_httpd_probe_covered``: the
  address the host probes and whether the unit's ``IPAddressAllow=`` lets that
  probe in (its source address is the bind address itself).

The drop-in template quotes with plain Jinja2 only (no filter of this file),
so ops-deploy can render it byte-identically (PLAN.md 7.4).
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

MODES = ("json-file", "script", "apt-state", "logyard-health", "static")
# Characters systemd interprets inside ExecStart= even in quotes: "%"
# (specifiers), "$" (environment expansion), '"' and "\\" (quoting and
# escapes). Control characters (newline, tab, ...) would end or split the line.
FORBIDDEN = frozenset('%$"\\')
PROPERTY_RE = re.compile(r"^[A-Z][A-Za-z]*=")

# systemd.resource-control(5): the symbolic names IPAddressAllow= accepts.
SYMBOLIC_NETWORKS = {
    "any": ("0.0.0.0/0", "::/0"),
    "localhost": ("127.0.0.0/8", "::1/128"),
    "link-local": ("169.254.0.0/16", "fe80::/64"),
    "multicast": ("224.0.0.0/4", "ff00::/8"),
}


def _bad_char(text: str) -> str | None:
    for char in text:
        if char in FORBIDDEN or ord(char) < 0x20 or ord(char) == 0x7F:
            return char
    return None


def metrics_httpd_argv_problems(argv: Any) -> list[str]:
    """Problems of a metrics-httpd command line (empty when it is safe).

    ``argv`` is the list after the binary, e.g. ``["json-file", "--bind",
    ...]``. Elements are strings or integers (a port); the role appends
    ``--check-config`` itself, so the list must not contain it.
    """

    if not isinstance(argv, (list, tuple)) or not argv:
        return ["argv must be a non-empty list"]
    problems = []
    for index, value in enumerate(argv):
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            problems.append(f"argv[{index}] is not a string or an integer: {value!r}")
            continue
        text = str(value)
        if text == "":
            problems.append(f"argv[{index}] is empty")
            continue
        char = _bad_char(text)
        if char is not None:
            problems.append(f"argv[{index}] contains {char!r}, which systemd would interpret: {text!r}")
        if text == "--check-config":
            problems.append(f"argv[{index}] is --check-config, which the role adds itself")
    if str(argv[0]) not in MODES:
        problems.append(f"argv[0] must be a metrics-httpd mode ({', '.join(MODES)}), got {argv[0]!r}")
    return problems


def metrics_httpd_sandbox_problems(properties: Any) -> list[str]:
    """Problems of the ``systemd-run --property`` list mirroring the unit."""

    if not isinstance(properties, (list, tuple)):
        return ["unit_sandbox must be a list of Key=Value strings"]
    problems = []
    for index, value in enumerate(properties):
        if not isinstance(value, str) or PROPERTY_RE.match(value) is None:
            problems.append(f"unit_sandbox[{index}] is not a Key=Value property: {value!r}")
            continue
        if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
            problems.append(f"unit_sandbox[{index}] contains a control character: {value!r}")
        if value.split("=", 1)[0] in ("User", "Group"):
            problems.append(f"unit_sandbox[{index}] sets {value.split('=', 1)[0]}; use validate_user/validate_group")
    return problems


def _address(value: Any) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if not isinstance(value, str):
        raise ValueError(f"not an IP address: {value!r}")
    return ipaddress.ip_address(value)


def metrics_httpd_probe_address(bind: Any) -> str:
    """The address the host connects to (and from): the bind address, or the
    loopback address of its family when the unit binds every address."""

    address = _address(bind)
    if address.is_unspecified:
        return "127.0.0.1" if address.version == 4 else "::1"
    return str(address)


def metrics_httpd_probe_host(bind: Any) -> str:
    """The host part of the probe URL (IPv6 in brackets)."""

    address = metrics_httpd_probe_address(bind)
    return f"[{address}]" if ":" in address else address


def _networks(entry: Any) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network] | None:
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    if not isinstance(entry, str):
        return None
    for token in entry.split():
        if token in SYMBOLIC_NETWORKS:
            networks.extend(ipaddress.ip_network(net) for net in SYMBOLIC_NETWORKS[token])
            continue
        try:
            networks.append(ipaddress.ip_network(token, strict=False))
        except ValueError:
            return None
    return networks


def metrics_httpd_probe_covered(bind: Any, allow: Any) -> bool:
    """True when a probe from the host to ``bind`` passes the unit's IP filter.

    ``allow`` is the unit's list of ``IPAddressAllow=`` values (the units all
    set ``IPAddressDeny=any``; a unit without an IP filter passes ``["any"]``).
    A connection from the host to one of its own addresses has that address as
    its source, so the probe passes iff the probed address is allowed. An entry
    this function cannot read counts as not covering (the probe is skipped,
    never run against a filter that drops it).
    """

    try:
        address = ipaddress.ip_address(metrics_httpd_probe_address(bind))
    except ValueError:
        return False
    if not isinstance(allow, (list, tuple)):
        return False
    for entry in allow:
        networks = _networks(entry)
        if networks is None:
            continue
        if any(address.version == net.version and address in net for net in networks):
            return True
    return False


class FilterModule:
    """Expose the metrics_httpd_switch checks to Ansible."""

    def filters(self) -> dict[str, Any]:
        return {
            "metrics_httpd_argv_problems": metrics_httpd_argv_problems,
            "metrics_httpd_sandbox_problems": metrics_httpd_sandbox_problems,
            "metrics_httpd_probe_host": metrics_httpd_probe_host,
            "metrics_httpd_probe_covered": metrics_httpd_probe_covered,
        }
