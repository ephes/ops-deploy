"""One bounded Describe/Info using the actual installed Wyoming client; no audio."""

from __future__ import annotations

import asyncio
import hashlib
import importlib
import importlib.metadata
import json
from pathlib import Path
from typing import Any


async def probe() -> dict[str, Any]:
    client_module = importlib.import_module("wyoming.client")
    event_module = importlib.import_module("wyoming.event")
    info_module = importlib.import_module("wyoming.info")
    AsyncTcpClient, Describe, Info = client_module.AsyncTcpClient, info_module.Describe, info_module.Info
    modules = (client_module, event_module, info_module)
    if any(module.__file__ is None for module in modules):
        raise ValueError("installed Wyoming source unavailable")
    async with asyncio.timeout(10), AsyncTcpClient("127.0.0.1", 10300) as client:
        await client.write_event(Describe().event())
        event = await client.read_event()
        if event is None or not Info.is_type(event.type):
            raise ValueError("owned Wyoming Info unavailable")
        info = Info.from_event(event)
    return {
        "version": importlib.metadata.version("wyoming"),
        "source_sha256": {
            module.__name__: hashlib.sha256(Path(str(module.__file__)).read_bytes()).hexdigest() for module in modules
        },
        "asr": [
            {
                "name": service.name,
                "installed": service.installed,
                "models": [
                    {"name": item.name, "installed": item.installed, "languages": item.languages}
                    for item in service.models
                ],
            }
            for service in info.asr
        ],
        "tts": [
            {
                "name": service.name,
                "installed": service.installed,
                "voices": [{"name": item.name, "languages": item.languages} for item in service.voices],
            }
            for service in info.tts
        ],
        "satellite": info.satellite is not None,
    }


if __name__ == "__main__":
    try:
        result = asyncio.run(probe())
    except Exception as error:
        print(json.dumps({"collection_failed": True, "error_type": type(error).__name__}))
        raise SystemExit(1) from None
    print(json.dumps(result))
