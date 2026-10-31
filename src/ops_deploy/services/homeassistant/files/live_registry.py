"""Read-only live Assist registry projection; input/output remain protected RAM."""

import asyncio
import json
import sys
from urllib.parse import urlparse, urlunparse

import aiohttp


def websocket_url(api_url):
    parsed = urlparse(api_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("invalid API URL")
    return urlunparse(
        (
            "wss" if parsed.scheme == "https" else "ws",
            parsed.netloc,
            parsed.path.rstrip("/") + "/api/websocket",
            "",
            "",
            "",
        )
    )


async def registry(payload):
    """Return only enabled engine identifiers, never entry data or options."""
    async with asyncio.timeout(payload["timeout"]):
        async with aiohttp.ClientSession() as session:
            async with session.ws_connect(
                websocket_url(payload["url"]), ssl=payload.get("validate_certs", True)
            ) as ws:
                if (await ws.receive_json()).get("type") != "auth_required":
                    raise ValueError("unexpected authentication greeting")
                await ws.send_json({"type": "auth", "access_token": payload["token"]})
                if (await ws.receive_json()).get("type") != "auth_ok":
                    raise ValueError("authentication failed")
                await ws.send_json({"id": 1, "type": "config/entity_registry/list"})
                while True:
                    response = await ws.receive_json()
                    if response.get("id") == 1:
                        break
                if response.get("success") is not True or not isinstance(
                    response.get("result"), list
                ):
                    raise ValueError("registry query failed")
                entities = []
                for entry in response["result"]:
                    if not isinstance(entry, dict) or not isinstance(
                        entry.get("entity_id"), str
                    ):
                        raise ValueError("invalid registry entry")
                    if entry.get("disabled_by") is not None:
                        continue
                    if not entry["entity_id"].startswith(("stt.", "tts.")):
                        continue
                    entities.append(
                        {
                            key: entry.get(key)
                            for key in (
                                "entity_id",
                                "platform",
                                "config_entry_id",
                            )
                        }
                    )
                return entities


def selection_ready(entities, payload):
    selected = payload.get("entry_id")
    kinds = payload.get("kinds", [])
    # An unknown identity retains the original unresolved-selection failure;
    # retries cannot invent an endpoint mapping absent from the supported API.
    if not selected:
        return True
    return all(
        any(
            entry["platform"] == "wyoming"
            and entry["config_entry_id"] == selected
            and entry["entity_id"].startswith(kind + ".")
            for entry in entities
        )
        for kind in kinds
    )


async def query(payload):
    retries = max(0, payload.get("retries", 0))
    for attempt in range(retries + 1):
        try:
            entities = await registry(payload)
        except Exception:
            if attempt == retries and "entity_id" not in payload:
                raise
            entities = None
        if entities is not None:
            if "entity_id" in payload:
                if any(
                    entry["entity_id"] == payload["entity_id"] for entry in entities
                ):
                    return {"success": True, "ready": True, "attempts": attempt + 1}
            elif selection_ready(entities, payload) or attempt == retries:
                # Missing engines still fail the original desired-state assert.
                return {"success": True, "entities": entities}
        if attempt < retries:
            await asyncio.sleep(max(0, payload["delay"]))
    return {"success": True, "ready": False, "attempts": retries + 1}


def main():
    try:
        result = asyncio.run(query(json.load(sys.stdin)))
    except Exception:
        # Authentication/protocol errors can contain private response values.
        print(json.dumps({"success": False}))
        return 1
    print(json.dumps(result))
    return 0 if result.get("ready", True) else 1


if __name__ == "__main__":
    raise SystemExit(main())
