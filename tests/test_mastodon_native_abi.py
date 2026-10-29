"""Native gem rebuild after an OS/ABI change, never on a healthy existing bundle.

A fake ``ldd`` on PATH resolves each extension's needed sonames against a fake
library directory; an "OS upgrade" replaces that directory's ICU soname and the
fake os-release, exactly what a release upgrade does to a vendored bundle.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.services.mastodon import deploy_mastodon
from ops_deploy.testing import run_deploy_fake
from tests.test_mastodon import secrets
from tests.test_mastodon_release import inspection, responses
from tests.test_mastodon_release_source import host_module, release_config

FAKE_LDD = """
import os, sys
libs = os.environ["FAKE_LIB_DIR"]
files = sys.argv[1:]
status = 0
for path in files:
    if len(files) > 1:
        print(path + ":")
    needed = [line for line in open(path).read().splitlines() if line]
    if not needed:
        print("\\tnot a dynamic executable")
        status = 1
        continue
    print("\\tlinux-vdso.so.1 (0x00007ffd)")
    for soname in needed:
        target = os.path.join(libs, soname)
        print("\\t" + soname + " => " + (target + " (0x00007f00)" if os.path.exists(target) else "not found"))
sys.exit(status)
"""

LOCK = """GEM
  remote: https://rubygems.org/
  specs:
    charlock_holmes (0.7.9)
    ffi (1.17.4)
    json (2.19.9)
    websocket-driver (0.8.2)
      websocket-extensions (>= 0.1.0)

PLATFORMS
  ruby

DEPENDENCIES
  charlock_holmes (~> 0.7.7)
  json (~> 2.3)

CHECKSUMS
  json (2.19.9) sha256=00

BUNDLED WITH
   4.0.13
"""

ICU = ["libicudata.so.{0}", "libicui18n.so.{0}", "libicuuc.so.{0}"]


class Host:
    """A fake installed bundle on a fake OS."""

    def __init__(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self.tmp = tmp_path
        self.lib = tmp_path / "lib"
        self.lib.mkdir()
        self.os_release = tmp_path / "os-release"
        self.site = tmp_path / "live"
        self.site.mkdir()
        (self.site / "Gemfile.lock").write_text(LOCK)
        self.base = self.site / "vendor/bundle/ruby/4.0.0"
        tools = tmp_path / "bin"
        tools.mkdir()
        ldd = tools / "ldd"
        ldd.write_text("#!" + sys.executable + "\n" + FAKE_LDD)
        ldd.chmod(0o755)
        monkeypatch.setenv("PATH", str(tools) + ":" + "/usr/bin:/bin")
        monkeypatch.setenv("FAKE_LIB_DIR", str(self.lib))
        self.os("24.04", "74")
        self.module = host_module(tmp_path)
        self.calls: list[list[str]] = []
        self.pristine_fixes = True
        local = self.module.user

        def user(cfg: Any, argv: list[str], **kwargs: Any) -> Any:
            self.calls.append(list(argv))
            if argv[0] == "bundle":
                if argv[1] == "pristine" and self.pristine_fixes:
                    for name in argv[2:]:
                        self.rebuild(name)
                return subprocess.CompletedProcess(argv, 0, "", "")
            return local(cfg, argv, **kwargs)

        self.module.user = user
        self.module.verify_source = lambda _cfg: None
        self.cfg = release_config(yarn_install=False, precompile_assets=False).model_dump()
        self.cfg.update(site_path=str(self.site), bundle_path=str(self.site / "vendor/bundle"), ruby_version="4.0.5")
        for name in ("libjemalloc.so.2", "libffi.so.8", "libruby.so.4.0"):
            (self.lib / name).touch()

    def os(self, version: str, icu: str) -> None:
        """Install the fake OS release: os-release and the ICU soname it ships."""
        self.os_release.write_text('ID=ubuntu\nVERSION_ID="' + version + '"\n')
        for old in self.lib.glob("libicu*"):
            old.unlink()
        for name in ICU:
            (self.lib / name.format(icu)).touch()
        self.icu = icu

    def extension(self, relative: str, *sonames: str) -> Path:
        path = self.site / "vendor/bundle" / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(sonames) + "\n")
        return path

    def charlock(self, icu: str) -> None:
        sonames = [name.format(icu) for name in ICU] + ["libjemalloc.so.2"]
        self.extension("ruby/4.0.0/gems/charlock_holmes-0.7.9/lib/charlock_holmes/charlock_holmes.so", *sonames)
        self.extension(
            "ruby/4.0.0/extensions/x86_64-linux/4.0.0/charlock_holmes-0.7.9/charlock_holmes/charlock_holmes.so",
            *sonames,
        )

    def rebuild(self, name: str) -> None:
        assert name == "charlock_holmes"
        self.charlock(self.icu)

    def installed(self) -> None:
        """A typical installed bundle, built on the current fake OS."""
        self.charlock(self.icu)
        self.extension("ruby/4.0.0/gems/ffi-1.17.4-x86_64-linux-gnu/lib/ffi_c.so", "libffi.so.8")
        self.extension("ruby/4.0.0/gems/json-2.19.9/lib/json/ext/parser.so", "libjemalloc.so.2", "libruby.so.4.0")
        self.extension("ruby/4.0.0/gems/websocket-driver-0.8.2/lib/websocket_mask.so", "libjemalloc.so.2")

    def current_marker(self) -> None:
        self.module.state_write("bundle", self.module.bundle_key(self.cfg))

    def ldd_calls(self) -> list[list[str]]:
        return [call for call in self.calls if call[0] == "ldd"]


@pytest.fixture
def host(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Host:
    return Host(tmp_path, monkeypatch)


def test_bundle_key_inputs_are_unchanged_so_existing_markers_stay_current(host: Host) -> None:
    keys = [
        "source_commit",
        "source_files",
        "ruby_version",
        "bundle_path",
        "bundle_without",
        "bundle_jobs",
        "bundle_retry",
        "bundle_deployment",
    ]
    expected = hashlib.sha256(json.dumps({k: host.cfg[k] for k in keys}, sort_keys=True).encode()).hexdigest()
    assert host.module.bundle_key(host.cfg) == expected


def test_healthy_bundle_is_current_and_not_rebuilt(host: Host) -> None:
    host.installed()
    host.current_marker()
    before = sorted(p.name for p in host.module.STATE.iterdir())
    result = host.module.dependencies_state(host.cfg, {"ruby": False, "node": False})
    assert result["bundle"] is False
    assert result["native_rebuild"] == []
    assert len(host.ldd_calls()) == 1  # one batched, read-only ldd pass
    assert len(host.ldd_calls()[0]) == 1 + 5
    assert not any(call[:2] == ["bundle", "pristine"] for call in host.calls)
    assert sorted(p.name for p in host.module.STATE.iterdir()) == before


def test_os_upgrade_with_icu_soname_bump_triggers_targeted_rebuild(host: Host) -> None:
    host.installed()
    host.current_marker()
    host.os("26.04", "78")  # release upgrade: libicu74 replaced by libicu78
    assert host.module.bundle_key(host.cfg) == json.loads((host.module.STATE / "bundle").read_text())
    result = host.module.dependencies_state(host.cfg, {"ruby": False, "node": False})
    assert result["bundle"] is True
    assert result["native_rebuild"] == ["charlock_holmes"]

    host.calls.clear()
    host.module.bundle(host.cfg)
    bundler = [call[1:3] for call in host.calls if call[0] == "bundle"]
    install = bundler.index(["install", "--jobs"])
    assert bundler[install + 1] == ["pristine", "charlock_holmes"]
    assert bundler[install + 2] == ["check", "--dry-run"]
    assert host.module.native_broken(host.cfg) == []
    after = host.module.dependencies_state(host.cfg, {"ruby": False, "node": False})
    assert after == {**after, "bundle": False, "native_rebuild": []}


def test_rebuild_that_leaves_a_missing_library_fails_closed_without_marker(host: Host) -> None:
    host.installed()
    host.os("26.04", "78")
    host.pristine_fixes = False
    with pytest.raises(ValueError, match="still link missing libraries"):
        host.module.bundle(host.cfg)
    assert not (host.module.STATE / "bundle").exists()
    assert (host.module.STATE / "pending-rollout").exists()


def test_platform_gem_directory_maps_to_its_plain_lock_entry(host: Host) -> None:
    host.installed()
    host.current_marker()
    (host.lib / "libffi.so.8").unlink()
    assert host.module.native_broken(host.cfg) == ["ffi"]


def test_leftovers_of_earlier_bundles_and_ruby_abis_are_ignored(host: Host) -> None:
    host.installed()
    host.current_marker()
    host.extension("ruby/4.0.0/gems/json-2.19.8/lib/json/ext/parser.so", "libgone.so.1")
    host.extension("ruby/4.0.0/extensions/x86_64-linux/4.0.0/json-2.19.8/json/ext/parser.so", "libgone.so.1")
    host.extension("ruby/3.4.0/gems/charlock_holmes-0.7.9/lib/charlock_holmes/charlock_holmes.so", "libgone.so.1")
    result = host.module.dependencies_state(host.cfg, {"ruby": False, "node": False})
    assert result["bundle"] is False
    assert result["native_rebuild"] == []


def test_missing_libruby_is_not_an_abi_break(host: Host) -> None:
    host.installed()
    (host.lib / "libruby.so.4.0").unlink()
    assert host.module.native_broken(host.cfg) == []


def test_single_extension_output_without_header_is_attributed(host: Host) -> None:
    host.extension("ruby/4.0.0/gems/charlock_holmes-0.7.9/lib/charlock_holmes/charlock_holmes.so", "libicuuc.so.74")
    host.os("26.04", "78")
    assert host.module.native_broken(host.cfg) == ["charlock_holmes"]


def test_unattributable_missing_library_fails_closed(host: Host) -> None:
    host.installed()
    host.extension("ruby/4.0.0/bundler/gems/fixture-0123456789ab/lib/fixture.so", "libgone.so.1")
    with pytest.raises(ValueError, match="outside locked registry gems"):
        host.module.native_broken(host.cfg)


@pytest.mark.parametrize("status", [2, 126, 127])
def test_ldd_that_cannot_run_fails_closed(host: Host, status: int) -> None:
    host.installed()
    # The service-user shell answers 127 when ldd is absent, 126 when it cannot execute.
    (host.tmp / "bin/ldd").write_text("#!/bin/sh\nexit " + str(status) + "\n")
    with pytest.raises(ValueError, match="cannot inspect native extension links"):
        host.module.native_broken(host.cfg)


def test_non_dynamic_object_does_not_abort_the_pass(host: Host) -> None:
    host.installed()
    host.extension("ruby/4.0.0/gems/json-2.19.9/lib/json/static.so")
    host.os("26.04", "78")
    assert host.module.native_broken(host.cfg) == ["charlock_holmes"]


def test_no_abi_check_without_bundle_install_or_with_an_outdated_bundle(host: Host) -> None:
    host.installed()
    host.os("26.04", "78")
    host.cfg["bundle_install"] = False
    host.current_marker()
    assert host.module.dependencies_state(host.cfg, {"ruby": False, "node": False})["bundle"] is False
    host.cfg["bundle_install"] = True
    host.module.state_write("bundle", "outdated")
    assert host.module.dependencies_state(host.cfg, {"ruby": False, "node": False})["bundle"] is True
    assert host.ldd_calls() == []


def test_caller_rebuilds_and_rolls_out_when_native_gems_are_broken() -> None:
    cfg = release_config()
    observed = inspection(dependencies={"bundle": True, "yarn": False, "assets": False, "native_rebuild": ["x"]})
    run = run_deploy_fake(deploy_mastodon, cfg=cfg, secrets=secrets(), responses=responses(cfg, observed))
    assert run.succeeded, run.error
    joined = "\n".join(str(operation.name) for operation in run.ops)
    assert "Install and verify selected locked Ruby dependencies" in joined
    assert "Build and verify selected Mastodon production assets" in joined


def test_caller_with_healthy_native_gems_has_zero_mutations() -> None:
    cfg = release_config()
    observed = inspection(dependencies={"bundle": False, "yarn": False, "assets": False, "native_rebuild": []})
    run = run_deploy_fake(deploy_mastodon, cfg=cfg, secrets=secrets(), responses=responses(cfg, observed))
    assert run.succeeded, run.error
    assert run.mutating_changed_ops == []
