"""Real owned uv --check proof; no inventory, package network or app imports."""

from __future__ import annotations

import os
import pwd
import runpy
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from tests.test_daybook_runtime_observer import SCRIPT


def metadata(root: Path) -> dict[str, tuple[int, ...]]:
    result: dict[str, tuple[int, ...]] = {}
    for path in (root, *root.rglob("*")):
        info = path.lstat()
        result[str(path.relative_to(root))] = (
            info.st_dev,
            info.st_ino,
            info.st_uid,
            info.st_gid,
            info.st_mode,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
        )
    return result


@pytest.mark.parametrize("editable", [False, True])
def test_actual_uv_check_is_offline_no_sync_and_preserves_environment_metadata(tmp_path: Path, editable: bool) -> None:
    root = tmp_path.resolve()
    uv = shutil.which("uv")
    assert uv is not None
    (root / "pyproject.toml").write_text(
        '[project]\nname="owned-runtime-env"\nversion="0.0.0"\nrequires-python=">=3.12"\n'
    )
    if editable:
        with (root / "pyproject.toml").open("a") as handle:
            handle.write('\n[build-system]\nrequires=[]\nbuild-backend="_owned_backend"\nbackend-path=["."]\n')
        (root / "src/owned_runtime_env").mkdir(parents=True)
        (root / "src/owned_runtime_env/__init__.py").write_text(
            "raise RuntimeError('fixture package must never be imported')\n"
        )
        (root / "_owned_backend.py").write_text("""import pathlib, zipfile

def get_requires_for_build_editable(config_settings=None):
    return []

def build_editable(wheel_directory, config_settings=None, metadata_directory=None):
    name = 'owned_runtime_env-0.0.0-py3-none-any.whl'
    prefix = 'owned_runtime_env-0.0.0.dist-info/'
    with zipfile.ZipFile(pathlib.Path(wheel_directory) / name, 'w') as wheel:
        wheel.writestr(prefix + 'METADATA', 'Metadata-Version: 2.1\\nName: owned-runtime-env\\nVersion: 0.0.0\\n')
        wheel.writestr(prefix + 'WHEEL', 'Wheel-Version: 1.0\\nGenerator: owned-fixture\\n'
                       'Root-Is-Purelib: true\\nTag: py3-none-any\\n')
        wheel.writestr('owned_runtime_env.pth', str(pathlib.Path.cwd() / 'src') + '\\n')
        wheel.writestr(prefix + 'RECORD', '')
    return name
""")
    # Initial owned fixture setup only. The observer never runs this sync.
    subprocess.run(
        [
            uv,
            "--directory",
            str(root),
            "sync",
            "--offline",
            "--no-python-downloads",
            *([] if editable else ["--no-build"]),
            "--no-dev",
            "--python",
            sys.executable,
        ],
        capture_output=True,
        check=True,
        timeout=30,
    )
    if editable:
        assert list((root / ".venv").rglob("owned_runtime_env-0.0.0.dist-info"))
        assert list((root / ".venv").rglob("owned_runtime_env.pth"))
    module = runpy.run_path(str(SCRIPT))
    user = pwd.getpwuid(os.geteuid()).pw_name
    data = {
        "user": user,
        "python": str(root / ".venv/bin/python"),
        "python_version": ".".join(map(str, sys.version_info[:3])),
        "uv_bin": uv,
        "checkout": str(root),
    }
    probe = module["NativeProbes"](data)
    before = metadata(root)
    managed = "/uv/python/cpython-" + data["python_version"] + "-" in sys.base_prefix
    if os.environ.get("GITHUB_ACTIONS") == "true" and sys.version_info[:2] == (3, 13):
        assert managed, "CI 3.13 must retain the combined managed-interpreter positive case"
    # Linux CI 3.12 may run Ubuntu's system Python. The production guard must
    # still reject that interpreter; independently prove the actual offline uv
    # lock/editable-package check, without faking a managed interpreter or skip.
    assert probe.runtime_current() is managed
    assert probe.locked_environment_current() is True
    assert probe.locked_environment_current() is True
    assert metadata(root) == before
    # A missing environment stays missing; verification cannot repair it.
    (root / ".venv/pyvenv.cfg").unlink()
    broken = metadata(root)
    assert probe.runtime_current() is False
    assert probe.locked_environment_current() is False
    assert metadata(root) == broken
