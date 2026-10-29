"""Original gathered default IPv4 input for normal inventory composition.

The kernel route lookup sends no packet. Ansible's Linux network collector uses
8.8.8.8, takes only the first matching route line, and has no address when the
command is unavailable or returns no matching line. This helper preserves that
absence; it never substitutes the SSH/Tailscale address or edits networking.
"""

from __future__ import annotations

from pyinfra import host
from pyinfra.facts.server import Command

from .deploy_config import HomeAssistantDeployConfig

ROUTE_COMMAND = "ip -4 route get 8.8.8.8 2>/dev/null || true"


def route_address(output: str) -> str | None:
    lines = output.splitlines()
    words = lines[0].split() if lines else []
    if not words or words[0] != "8.8.8.8":
        return None
    address = None
    for index in range(len(words) - 1):
        if words[index] == "src":
            address = words[index + 1]
    return address


def resolve_target_network(cfg: HomeAssistantDeployConfig) -> HomeAssistantDeployConfig:
    """Fill only omitted API/ingress facts; keep every explicit caller value.

    Call before deploy_homeassistant at the original gather-facts boundary. A
    failed/no-route query is an absent original fact, not evidence of a working
    API. The later unchanged role readiness/configuration checks still apply.
    """
    missing = [name for name in ("api", "ingress") if "default_ipv4" not in getattr(cfg, name).model_fields_set]
    if not missing:
        return cfg
    address = route_address(str(host.get_fact(Command, command=ROUTE_COMMAND) or ""))
    if address is None:
        return cfg
    # These fields are strings supplied by the original kernel fact. Updating
    # only those leaves preserves every other explicit/default field boundary.
    return cfg.model_copy(
        update={name: getattr(cfg, name).model_copy(update={"default_ipv4": address}) for name in missing}
    )
