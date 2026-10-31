"""Read only named synthetic Wyoming metadata in an already admitted owned guest."""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .fixture import write
from .harness import CONFIG, HOME, api
from .matter_ready import PROPERTIES, bounded_command

REGISTRY_LIMIT = 4 * 1024 * 1024


def entries(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > 4096 or any(not isinstance(item, dict) for item in value):
        raise ValueError("invalid owned config entry metadata")
    return [
        {
            **{key: item.get(key) for key in ("entry_id", "domain", "state", "disabled_by")},
            "matches_fixture_endpoint": (
                item["data"].get("host") == "127.0.0.1" and item["data"].get("port") == 10300
                if isinstance(item.get("data"), dict)
                else None
            ),
        }
        for item in value
        if item.get("domain") == "wyoming"
    ]


def entities(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > 4096 or any(not isinstance(item, dict) for item in value):
        raise ValueError("invalid owned entity metadata")
    return [
        {key: item.get(key) for key in ("entity_id", "platform", "config_entry_id", "disabled_by")}
        for item in value
        if item.get("platform") == "wyoming"
    ]


def disk(path: Path, key: str, project: Callable[[Any], list[dict[str, Any]]]) -> dict[str, Any]:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > REGISTRY_LIMIT:
            raise ValueError("owned registry exceeds bounds")
        body = stream.read(REGISTRY_LIMIT + 1)
        if len(body) > REGISTRY_LIMIT:
            raise ValueError("owned registry grew beyond bound")
    parsed = json.loads(body)
    return {"size": metadata.st_size, "mtime_ns": metadata.st_mtime_ns, "selected": project(parsed["data"][key])}


def capture(label: str, token: str) -> dict[str, Any]:
    """No config-entry data/options, registry user bodies, token or model/audio."""
    if label not in {"before-original-selected", "after-original-selected"}:
        raise ValueError("unexpected owned Wyoming diagnostic stage")
    collectors: dict[str, Callable[[], Any]] = {
        "live_entries": lambda: entries(api("ws", token=token, command_value={"type": "config_entries/get"})["result"]),
        "live_entities": lambda: entities(
            api("ws", token=token, command_value={"type": "config/entity_registry/list"})["result"]
        ),
        "disk_entries": lambda: disk(CONFIG / ".storage/core.config_entries", "entries", entries),
        "disk_entities": lambda: disk(CONFIG / ".storage/core.entity_registry", "entities", entities),
        "protocol": lambda: bounded_command(
            [str(HOME / ".venv/bin/python"), "-I", "-B", str(Path(__file__).with_name("wyoming_protocol_probe.py"))],
            timeout=20,
        ),
        "unit": lambda: bounded_command(
            ["systemctl", "show", "homeassistant.service", "--property=" + PROPERTIES], timeout=5
        ),
        "journal": lambda: bounded_command(
            [
                "journalctl",
                "--no-pager",
                "--unit=homeassistant.service",
                "--lines=200",
                "--output=short-iso",
                "--grep=wyoming|Wyoming|speech.to.text|text.to.speech",
            ],
            timeout=10,
        ),
    }
    result = {}
    for name, collect in collectors.items():
        try:
            result[name] = collect()
        except Exception as error:
            # A collector failure must not hide other evidence or the original failure.
            result[name] = {"collection_failed": True, "error_type": type(error).__name__}
    write("wyoming-" + label + ".json", result)
    return result
