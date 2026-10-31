"""Original HA optional dependency initialization for the declared existing host.

Executed only with the selected owned application's interpreter. This loads
manifests/requirements, never starts Home Assistant or an integration.
"""

from __future__ import annotations

import asyncio
import hashlib
import importlib
import importlib.metadata
import json
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any

VERSIONS = frozenset({"2026.10.1", "2026.10.2"})
SOURCE_HASHES = {
    "requirements.py": "ec9a8434fe5d883d77d4b76ce013aed79878e0597e2ca774bf1dd89142951843",
    "loader.py": "89d892bdb0fe6e8448683c17a329821c4f96a5dab6a83d4985d050e6c79ebade",
    "components/matter/manifest.json": "ecd06230a8e1cb4a8b8bba21255347b37549c0eba50635f0ef318b666079479f",
    "components/hassio/manifest.json": "a3e1fa8020d61f9f128195da0836cc6193cac4285ef3cf61dfef628a62413e12",
}


def original_environment(selected: str) -> dict[str, Any]:
    """The unchanged role's pip/legacy checks, with status-only evidence."""

    def status(*args: str) -> int:
        return subprocess.run([sys.executable, "-m", "pip", *args], capture_output=True, timeout=30).returncode

    return {
        "python_exists": Path(sys.executable).exists(),
        "python_stdout": "Python " + platform.python_version(),
        "pip_status": status("--version"),
        "legacy_matter_status": status("show", "python-matter-server"),
        "application_exists": (Path(sys.prefix) / "bin/hass").exists(),
        "installed_version": selected,
    }


async def initialize(config_path: Path, selected: str) -> dict[str, Any]:
    if selected not in VERSIONS or importlib.metadata.version("homeassistant") != selected:
        raise RuntimeError("owned Home Assistant baseline version mismatch")
    if platform.python_version() != "3.14.8":
        raise RuntimeError("owned Home Assistant baseline interpreter mismatch")
    package = importlib.import_module("homeassistant")
    if package.__file__ is None:
        raise RuntimeError("owned Home Assistant package source unavailable")
    root = Path(package.__file__).resolve().parent
    actual = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in SOURCE_HASHES}
    if actual != SOURCE_HASHES:
        raise RuntimeError("unqualified original Home Assistant dependency loader")
    core = importlib.import_module("homeassistant.core")
    loader = importlib.import_module("homeassistant.loader")
    requirements = importlib.import_module("homeassistant.requirements")
    hass = core.HomeAssistant(str(config_path))
    try:
        loader.async_setup(hass)
        integration = await requirements.async_get_integration_with_requirements(hass, "matter")
        if integration.domain != "matter":
            raise RuntimeError("unexpected original integration dependency result")
        importlib.import_module("homeassistant.components.matter.config_flow")
        manager = requirements._async_get_manager(hass)
        closure = {name: list(value.requirements) for name, value in manager.integrations_with_reqs.items()}
        return {
            "homeassistant_version": selected,
            "python": platform.python_version(),
            "source_sha256": actual,
            "requirements": closure,
            "matter_config_flow_import": True,
            "application_started": False,
            "original_environment": original_environment(selected),
        }
    finally:
        await hass.async_stop(force=True)


def main() -> None:
    if len(sys.argv) != 3:
        raise RuntimeError("owned dependency seed requires config path and selected version")
    config_path = Path(sys.argv[1])
    if not config_path.is_absolute() or not config_path.is_dir():
        raise RuntimeError("owned dependency seed requires an existing absolute config path")
    print(json.dumps(asyncio.run(initialize(config_path, sys.argv[2])), sort_keys=True))


if __name__ == "__main__":
    main()
