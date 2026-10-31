"""Owned synthetic HTTP baseline confirmation; never production deployment logic."""

from __future__ import annotations

import asyncio
import hashlib
import importlib
import importlib.metadata
import ipaddress
import json
from datetime import datetime
from pathlib import Path
from typing import Any


def project(value: Any) -> dict[str, Any]:
    """Discard configuration bodies; only finite enums and booleans leave RAM."""
    if not isinstance(value, dict) or set(value) != {"stable", "pending", "revert_at", "active_config_type", "default"}:
        raise ValueError("invalid owned HTTP status response")
    active = value["active_config_type"]
    if not isinstance(active, str) or active not in {"stable", "pending", "default", "default_legacy_port"}:
        raise ValueError("invalid owned HTTP active slot")
    deadline = value["revert_at"]
    if deadline is not None:
        try:
            if not isinstance(deadline, str) or datetime.fromisoformat(deadline).tzinfo is None:
                raise ValueError
        except ValueError:
            raise ValueError("invalid owned HTTP revert deadline") from None
    slots: dict[str, dict[str, bool] | None] = {}
    for name in ("stable", "pending", "default"):
        slot = value[name]
        if slot is None and name == "pending":
            slots[name] = None
            continue
        if not isinstance(slot, dict) or type(slot.get("server_port")) is not int:
            raise ValueError("invalid owned HTTP config slot")
        port = slot["server_port"]
        if not 1 <= port <= 65535:
            raise ValueError("invalid owned HTTP port")
        slots[name] = {"port_is_fixture10020": port == 10020, "port_is_builtin8123": port == 8123}
    error = value["pending"].get("error") if value["pending"] is not None else None
    if error is not None and (not isinstance(error, str) or error not in {"apply_failed", "not_promoted"}):
        raise ValueError("invalid owned HTTP pending error")
    return {
        "active_slot": active,
        "pending_present": value["pending"] is not None,
        "pending_error": error,
        "revert_scheduled": deadline is not None,
        "slots": slots,
    }


def original_expected(ipv4: str) -> tuple[Any, dict[str, Any], dict[str, Any]]:
    """Validate the actual immutable original schema before any confirmation."""
    address = ipaddress.ip_address(ipv4)
    if address.version != 4 or str(address) != ipv4:
        raise ValueError("invalid owned guest address")
    if importlib.metadata.version("homeassistant") not in {"2026.10.1", "2026.10.2"}:
        raise ValueError("unqualified original HTTP version")
    original = importlib.import_module("homeassistant.components.http.config")
    for name, expected_hash in {
        "config": "6f8efb3384428563a2ed00535a8a038b86bbe5639f8115eab59b04bcea0e0f60",
        "websocket_api": "66e76b5bea8af6ac3259620148f80cbf602f777b5adfd098081bf89ff4eeaaba",
    }.items():
        module = importlib.import_module("homeassistant.components.http." + name)
        if not isinstance(module.__file__, str):
            raise ValueError("unqualified original HTTP source path")
        if hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest() != expected_hash:
            raise ValueError("unqualified original HTTP source")
    default = dict(original.HTTP_STORAGE_SCHEMA({}))
    if default.get("server_port") != 8123:
        raise ValueError("unexpected owned HTTP default")
    expected = dict(
        original.HTTP_STORAGE_SCHEMA(
            {
                "server_host": "0.0.0.0",
                "server_port": 10020,
                "use_x_forwarded_for": True,
                "trusted_proxies": ["127.0.0.1", ipv4],
            }
        )
    )
    return original, expected, default


def exact_slot(original: Any, slot: Any, expected: dict[str, Any]) -> bool:
    if not isinstance(slot, dict) or set(slot) != set(expected) | set(original._META_KEYS):
        return False
    if slot.get("error") is not None or slot.get("error_message") is not None:
        return False
    created = slot.get("created_at")
    if not isinstance(created, str):
        return False
    try:
        if datetime.fromisoformat(created).tzinfo is None:
            return False
    except ValueError:
        return False
    # JSON equality also distinguishes booleans/integers/floats. Never persist
    # either body or a digest; both known synthetic configurations stay in RAM.
    return json.dumps(original._strip_meta(slot), sort_keys=True, allow_nan=False) == json.dumps(
        expected, sort_keys=True, allow_nan=False
    )


async def complete(websocket: Any, ipv4: str) -> dict[str, Any]:
    """Confirm only this known synthetic, authenticated and reachable trial.

    Return bounded effect accounting on refusal/failure. The original API write
    is explicit fixture onboarding, not part of typed/original deployment logic.
    """
    result: dict[str, Any] = {
        "confirmed": False,
        "confirmation_attempted": False,
        "confirmation_response_success": False,
        "scope": "owned synthetic existing-host HTTP baseline only",
    }
    try:
        async with asyncio.timeout(100):
            original, expected, default = original_expected(ipv4)
            before = await websocket({"type": "http/config"})
            projection = project(before)
            result["before"] = projection
            if (
                projection["active_slot"] != "pending"
                or not projection["revert_scheduled"]
                or not exact_slot(original, before["pending"], expected)
                or not exact_slot(original, before["stable"], default)
                or not exact_slot(original, before["default"], default)
            ):
                raise ValueError("unexpected owned HTTP baseline")
            result["confirmation_attempted"] = True
            response = await websocket({"type": "http/config/promote"})
            result["confirmation_response_success"] = True
            if response is not None:
                raise ValueError("unexpected owned HTTP confirmation response")
            after = await websocket({"type": "http/config"})
            projection = project(after)
            result["after"] = projection
            if (
                projection["active_slot"] != "stable"
                or projection["pending_present"]
                or projection["revert_scheduled"]
                or not exact_slot(original, after["stable"], expected)
                or not exact_slot(original, after["default"], default)
            ):
                raise ValueError("owned HTTP baseline was not confirmed")
            result["confirmed"] = True
    except Exception as error:
        # No response/body/message/metadata digest survives an error.
        result["error_type"] = type(error).__name__
    return result
