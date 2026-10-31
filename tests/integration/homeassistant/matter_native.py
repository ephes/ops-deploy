"""Original installed CHIP loader oracle, only for the owned synthetic guest."""

from __future__ import annotations

import ctypes
import hashlib
import importlib
import importlib.metadata
import json
from pathlib import Path
from typing import Any

VERSIONS = {"python-matter-server": "8.1.2", "home-assistant-chip-core": "2025.7.0"}
# Official PyPI manylinux_2_31_x86_64 wheel, SHA256 afde5db4...8ac1bbec.
# Compare the actual installed resources before executing its original resolver.
HASHES = {
    "chip/__init__.py": "840100f7e36dcc6540ff99224693d45dad3457788d173bdfa9f4592aecd408a7",
    "chip/exceptions/__init__.py": "af394d93a848126c52e6668d956fff37c1068f20351111c140cc63ea4f2d0377",
    "chip/_ChipDeviceCtrl.so": "213d6bf20fc2a2b946d3b197f871b683c82c65f3efeab0fbdf3916985109cab1",
    "chip/native/__init__.py": "761fb5ff68f912f0822854551b49b9be387d63758e12f11434f64123e2ec0f65",
    "home_assistant_chip_core-2025.7.0.dist-info/METADATA": (
        "43f01476e339079eb10319ed4d9038bb06e2baa4b9c570cf254cce273570e5ac"
    ),
}
MARKER = "OWNED_MATTER_NATIVE_JSON="
VENV = Path("/home/homeassistant/site/.venv-matter-server")


def inspect_native() -> dict[str, Any]:
    """Resolve and dlopen the exact original controller; do not initialize CHIP."""
    versions = {name: importlib.metadata.version(name) for name in VERSIONS}
    if versions != VERSIONS:
        raise RuntimeError("unqualified owned Matter distribution")
    distribution = importlib.metadata.distribution("home-assistant-chip-core")
    resources = {
        name: hashlib.sha256(Path(str(distribution.locate_file(name))).read_bytes()).hexdigest() for name in HASHES
    }
    if resources != HASHES:
        raise RuntimeError("unqualified owned CHIP resource")
    native = importlib.import_module("chip.native")
    selected = Path(native.FindNativeLibraryPath(native.Library.CONTROLLER)).resolve()
    expected = Path(str(distribution.locate_file("chip/_ChipDeviceCtrl.so"))).resolve()
    if selected != expected:
        raise RuntimeError("original CHIP resolver selected another library")
    # Exact original _GetLibraryHandle loading expression, without chip.native.Init
    # or creating another Matter stack, storage file, radio or service instance.
    ctypes.CDLL(str(selected))
    return {"versions": versions, "resources": resources, "library": str(selected), "dlopen": True}


def verify_native_dependencies() -> None:
    """Bounded metadata and actual service-account loader proof after bootstrap."""
    from .fixture import write
    from .matter_ready import bounded_command

    commands = {
        "distro": [
            "dpkg-query",
            "-W",
            "-f=${binary:Package}\t${Version}\t${Status}\n",
            "libnl-route-3-200",
            "libnl-3-200",
        ],
        "dynamic": ["readelf", "--dynamic", str(VENV / "lib/python3.14/site-packages/chip/_ChipDeviceCtrl.so")],
        "loader": [
            "runuser",
            "-u",
            "homeassistant",
            "--",
            str(VENV / "bin/python"),
            "-I",
            "-B",
            str(Path(__file__).resolve()),
        ],
    }
    results = {name: bounded_command(argv, timeout=15) for name, argv in commands.items()}
    write("matter-native-dependencies.json", results)
    if any(result["exit"] != 0 or result["truncated"] or result["timed_out"] for result in results.values()):
        raise RuntimeError("owned Matter native dependency proof failed")
    markers = [
        line.removeprefix(MARKER) for line in results["loader"]["output"].splitlines() if line.startswith(MARKER)
    ]
    try:
        proof = json.loads(markers[0]) if len(markers) == 1 else None
    except ValueError:
        proof = None
    if not isinstance(proof, dict) or proof.get("dlopen") is not True:
        raise RuntimeError("owned Matter native loader proof missing")


if __name__ == "__main__":
    print(MARKER + json.dumps(inspect_native(), sort_keys=True))
