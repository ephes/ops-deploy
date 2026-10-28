"""Real offline uv check of an installed sdist, with executable-backend tripwire."""

from __future__ import annotations

import grp
import os
import pwd
import runpy
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path
from typing import Any

import pytest

from tests.test_daybook_runtime_observer import SCRIPT
from tests.test_daybook_sessions_source import MODULE as SESSIONS_MODULE
from tests.test_daybook_sessions_source import snapshot


@pytest.mark.parametrize("kind", ["runtime", "sessions"])
def test_sdist_check_detects_drift_without_build_install_or_app_import(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    root = tmp_path.resolve()
    uv = os.environ.get("S8_UV_CHECK_BIN") or shutil.which("uv")
    assert uv is not None
    source = root / "owned_sdist-0.0.0"
    source.mkdir()
    marker = root / "backend-called"
    (source / "pyproject.toml").write_text(
        '[project]\nname="owned-sdist"\nversion="0.0.0"\n'
        '[build-system]\nrequires=[]\nbuild-backend="_backend"\nbackend-path=["."]\n'
    )
    (source / "_backend.py").write_text(f"""import pathlib, zipfile
pathlib.Path({str(marker)!r}).write_text('backend imported')
def get_requires_for_build_wheel(config_settings=None): return []
def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    name = 'owned_sdist-0.0.0-py3-none-any.whl'
    with zipfile.ZipFile(pathlib.Path(wheel_directory) / name, 'w') as wheel:
        prefix = 'owned_sdist-0.0.0.dist-info/'
        wheel.writestr(prefix + 'METADATA', 'Metadata-Version: 2.1\\nName: owned-sdist\\nVersion: 0.0.0\\n')
        wheel.writestr(prefix + 'WHEEL', 'Wheel-Version: 1.0\\nRoot-Is-Purelib: true\\nTag: py3-none-any\\n')
        wheel.writestr('owned_sdist.py', "raise RuntimeError('fixture app must never be imported')\\n")
        wheel.writestr(prefix + 'RECORD', '')
    return name
""")
    archive = root / "owned_sdist-0.0.0.tar.gz"
    with tarfile.open(archive, "w:gz") as stream:
        stream.add(source, arcname=source.name)
    project = root / "project"
    project.mkdir()
    (project / "pyproject.toml").write_text(
        '[project]\nname="owned-check"\nversion="0.0.0"\nrequires-python=">=3.12"\n'
        'dependencies=["owned-sdist"]\n[tool.uv.sources]\n'
        'owned-sdist={path="../owned_sdist-0.0.0.tar.gz"}\n'
    )
    monkeypatch.setenv("UV_CACHE_DIR", str(root / "cache"))
    monkeypatch.setenv("UV_PROJECT_ENVIRONMENT", str(project / ".venv"))
    # Explicit owned setup only; its real backend marker is the positive control.
    subprocess.run(
        [uv, "--directory", str(project), "sync", "--offline", "--no-python-downloads",
         "--no-dev", "--python", sys.executable],
        capture_output=True, check=True, timeout=30,
    )
    assert marker.read_text() == "backend imported"
    marker.unlink()
    data: dict[str, Any] = {
        "user": pwd.getpwuid(os.geteuid()).pw_name,
        "group": grp.getgrgid(os.getegid()).gr_name,
        "uv_bin": uv,
        "checkout": str(project),
        "python": str(project / ".venv/bin/python"),
        "python_version": ".".join(map(str, sys.version_info[:3])),
        "sync_args": ["sync", "--frozen", "--no-dev", "--python", sys.executable],
    }
    module = runpy.run_path(str(SCRIPT)) if kind == "runtime" else SESSIONS_MODULE
    probe = module["NativeProbes" if kind == "runtime" else "SourceProbes"](data)
    before = snapshot(project)
    assert probe.locked_environment_current() is True
    assert probe.locked_environment_current() is True
    assert snapshot(project) == before
    assert not marker.exists(), "--check must not import or invoke the build backend"
    dist = next((project / ".venv/lib").glob("python*/site-packages/owned_sdist-0.0.0.dist-info"))
    saved = root / "saved-dist-info"
    dist.rename(saved)  # Deliberate owned negative setup, outside the checker.
    try:
        missing = snapshot(project)
        assert probe.locked_environment_current() is False
        assert snapshot(project) == missing, "check must not repair a missing installed distribution"
        assert not marker.exists()
    finally:
        saved.rename(dist)
    assert probe.locked_environment_current() is True
    assert not marker.exists()
