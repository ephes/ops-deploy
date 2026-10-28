"""Public, nonsecret target payload; no inventory or credentials are embedded."""

from __future__ import annotations

from typing import Any

from .config import NetplanConfig
from .render import render


def payload(cfg: NetplanConfig) -> dict[str, Any]:
    result: dict[str, Any] = cfg.model_dump(mode="json", exclude_none=True, by_alias=True)
    result["resources"] = {"/etc/netplan/99-ops-library.yaml": {"content": render(cfg, "netplan.yaml"), "mode": "0600"}}
    if cfg.route_guard.enabled:
        base = "/etc/systemd/system/" + cfg.route_guard.service_name
        for name, path, mode in (
            ("netplan-route-guard.sh", cfg.route_guard.script_path, "0755"),
            ("netplan-route-guard.service", base + ".service", "0644"),
            ("netplan-route-guard.timer", base + ".timer", "0644"),
        ):
            result["resources"][path] = {"content": render(cfg, name), "mode": mode}
    return result
