"""The Rust workspace under rust/ (moved from ops-library, rust/HISTORY.md).

These checks run in the default gate without a Rust toolchain: the package
never ships rust/, the frozen Python guard the Rust port is tested against is
still the guard ops-deploy installs, and the record of the eight releases
built in ops-library stays consistent.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import tarfile
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
RUST = ROOT / "rust"
LIVE_GUARD = ROOT / "src/ops_deploy/base/files/echoport_remote_command_guard.py.txt"
ORACLE_GUARD = RUST / "oracle/roles/echoport_remote_command_guard/files/echoport-remote-command-guard.py"
GUARD_FIXTURES = RUST / "echoport-command-guard/fixtures"
TARGET = "x86_64-unknown-linux-gnu"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_wheel_and_sdist_hold_nothing_from_rust(tmp_path: Path) -> None:
    uv = shutil.which("uv")
    assert uv is not None, "uv builds the package"
    subprocess.run(
        [uv, "build", "--offline", "--quiet", "--wheel", "--sdist", "-o", str(tmp_path), str(ROOT)],
        check=True,
        capture_output=True,
        timeout=300,
    )
    (wheel,) = tmp_path.glob("*.whl")
    (sdist,) = tmp_path.glob("*.tar.gz")
    names = zipfile.ZipFile(wheel).namelist()
    assert "ops_deploy/__init__.py" in names
    assert not [name for name in names if name.split("/", 1)[0] == "rust"]
    with tarfile.open(sdist) as archive:
        members = [name.split("/", 1)[1] for name in archive.getnames() if "/" in name]
    assert "src/ops_deploy/__init__.py" in members
    assert not [name for name in members if name.split("/", 1)[0] == "rust"]


def test_frozen_guard_oracle_is_the_installed_guard() -> None:
    """The Rust guard's fixtures are decisions of the frozen oracle. A change
    to the live Python guard fails here until the oracle, the fixtures
    (`gen_fixtures.py`) and the port follow (rust/HISTORY.md)."""
    live = sha256(LIVE_GUARD)
    assert sha256(ORACLE_GUARD) == live
    assert (GUARD_FIXTURES / "GUARD_SHA256").read_text(encoding="utf-8").strip() == live
    manifest = json.loads((GUARD_FIXTURES / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["guard_sha256"] == live


def test_releases_json_records_the_eight_ops_library_releases() -> None:
    data = json.loads((RUST / "releases.json").read_text(encoding="utf-8"))
    assert data["source_repository"] == "ephes/ops-library"
    releases = data["releases"]
    assert [entry["tag"] for entry in releases] == [
        "echoport-command-guard-v0.1.0",
        "echoport-command-guard-v0.2.0",
        "echoport-command-guard-v0.3.0",
        "metrics-httpd-v0.1.0",
        "metrics-httpd-v0.1.1",
        "software-live-v0.1.0",
        "software-live-v0.1.1",
        "software-live-v0.1.2",
    ]
    for entry in releases:
        assert entry["tag"] == f"{entry['crate']}-v{entry['version']}"
        assert entry["title"] == f"{entry['crate']} {entry['version']}"
        assert re.fullmatch(r"[0-9a-f]{40}", entry["commit"])
        assert re.fullmatch(r"[0-9a-f]{40}", entry["ops_library_commit"])
        assets = {asset["name"]: asset for asset in entry["assets"]}
        archives = sorted(name for name in assets if name.endswith(".tar.gz"))
        assert sorted(assets) == sorted(archives + [f"{name}.sha256" for name in archives])
        variants = [""] if entry["crate"] != "software-live" else ["-debian13", "-ubuntu24.04"]
        assert archives == [f"{entry['crate']}-{entry['version']}-{TARGET}{variant}.tar.gz" for variant in variants]
        for asset in assets.values():
            assert re.fullmatch(r"[0-9a-f]{64}", asset["sha256"])
            assert asset["size"] > 0


@pytest.mark.parametrize(
    "path",
    [
        "rust/echoport-command-guard/parity/oracle.py",
        "rust/metrics-httpd/fixtures/generate.py",
        "rust/metrics-httpd/parity/static_site.py",
        "rust/software-live/fixtures/generate.py",
        "rust/software-live/parity/run_parity.py",
        "rust/software-live/parity/shadow_compare.py",
    ],
)
def test_harnesses_read_the_frozen_oracles(path: str) -> None:
    """Each harness resolves the ops-library files under rust/oracle/."""
    assert '"oracle"' in (ROOT / path).read_text(encoding="utf-8")


def test_oracle_holds_the_26_frozen_ops_library_files() -> None:
    files = sorted(
        str(path.relative_to(RUST / "oracle"))
        for path in (RUST / "oracle").rglob("*")
        if path.is_file() and "__pycache__" not in path.parts
    )
    assert len(files) == 26
    assert all(name.startswith("roles/") for name in files)
    assert "roles/software_live/files/software_live.py" in files
    assert "roles/echoport_remote_command_guard/files/echoport-remote-command-guard.py" in files
