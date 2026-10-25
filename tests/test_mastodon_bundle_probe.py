"""Real Bundler checks must not manufacture file-based restart debt."""

from __future__ import annotations

import datetime
import hashlib
import importlib.util
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from tests.test_mastodon_release_source import host_module, release_config


def test_actual_bundle_probe_preserves_lock_and_restart_debt(tmp_path: Path) -> None:
    executable = shutil.which("bundle")
    if executable is None:
        pytest.skip("real Bundler unavailable; mandatory caller also runs with exact Bundler 4.0.13")
    env = {k: v for k, v in os.environ.items() if not k.startswith("BUNDLE")}
    home = tmp_path / "home"
    home.mkdir()
    env["HOME"] = str(home)
    site = tmp_path / "app"
    site.mkdir()
    (site / "Gemfile").write_text('source "https://rubygems.org"\n')

    def bundle(*args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run([executable, *args], cwd=site, env=env, capture_output=True, text=True)

    version = bundle("--version")
    assert version.returncode == 0, version.stderr
    bundler_version = re.search(r"\d+\.\d+\.\d+", version.stdout)
    assert bundler_version is not None
    assert bundle("lock", "--local").returncode == 0
    lock = site / "Gemfile.lock"
    original = lock.read_bytes()
    old_ns = 1_700_000_000_000_000_000
    os.utime(lock, ns=(old_ns, old_ns))
    restart_file = Path(__file__).parents[1] / "src/ops_deploy/services/gotosocial/files/restart_host.py"
    spec = importlib.util.spec_from_file_location("mastodon_bundle_restart_probe", restart_file)
    assert spec is not None
    assert spec.loader is not None
    restart = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(restart)
    started = datetime.datetime.now(datetime.UTC)
    timestamp = started.strftime("%a %Y-%m-%d %H:%M:%S.%f UTC")
    assert bundle("check").returncode == 0
    assert lock.read_bytes() == original
    assert lock.stat().st_mtime_ns != old_ns
    assert restart.decide("active", timestamp, [lock.stat().st_mtime_ns]) == "owed"

    module = host_module(tmp_path)
    cfg = release_config(yarn_install=False, precompile_assets=False).model_dump()
    cfg["source_files"]["Gemfile.lock"] = hashlib.sha256(original).hexdigest()
    module.state_write("bundle", module.bundle_key(cfg))

    def user(_cfg: Any, argv: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        return bundle(*argv[1:])

    module.user = user
    os.utime(lock, ns=(old_ns, old_ns))
    result = module.dependencies_state(cfg, {"ruby": False, "node": False})
    assert result["bundle"] is False
    assert lock.read_bytes() == original
    assert lock.stat().st_mtime_ns == old_ns
    assert restart.decide("active", timestamp, [lock.stat().st_mtime_ns]) == "current"
    # Retain full precision: a genuine after-start write still requires rollout.
    epoch = datetime.datetime(1970, 1, 1, tzinfo=datetime.UTC)
    start_ns = ((started - epoch) // datetime.timedelta(microseconds=1)) * 1000
    os.utime(lock, ns=(start_ns + 1, start_ns + 1))
    assert restart.decide("active", timestamp, [lock.stat().st_mtime_ns]) == "owed"

    (site / "Gemfile").write_text('source "https://rubygems.org"\ngem "ops_deploy_missing_fixture", "99.0.0"\n')
    lock.write_text(
        "GEM\n  remote: https://rubygems.org/\n  specs:\n    ops_deploy_missing_fixture (99.0.0)\n\n"
        "PLATFORMS\n  ruby\n\nDEPENDENCIES\n  ops_deploy_missing_fixture (= 99.0.0)\n\n"
        "BUNDLED WITH\n   " + bundler_version.group() + "\n"
    )
    missing = lock.read_bytes()
    cfg["source_files"]["Gemfile.lock"] = hashlib.sha256(missing).hexdigest()
    module.state_write("bundle", module.bundle_key(cfg))
    os.utime(lock, ns=(old_ns, old_ns))
    assert module.dependencies_state(cfg, {"ruby": False, "node": False})["bundle"] is True
    assert lock.read_bytes() == missing
    assert lock.stat().st_mtime_ns == old_ns
