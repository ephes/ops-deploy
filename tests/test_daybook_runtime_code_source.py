"""Real Git source replacement with synthetic Python/launchd process boundaries."""

from __future__ import annotations

import importlib.resources
import subprocess
import sys
import types
from pathlib import Path
from typing import Any

import pytest

from tests.test_daybook_sessions_source import (
    MODULE as SESSION,
)
from tests.test_daybook_sessions_source import (
    Probes as SessionProbes,
)
from tests.test_daybook_sessions_source import (
    checkout,  # noqa: F401 - fixture
    git,
    snapshot,
    stage_transfer,
)


@pytest.fixture
def helper(monkeypatch: Any) -> Any:
    dependency = types.ModuleType("ops_runtime_code_source")
    dependency.__dict__.update(SESSION)
    monkeypatch.setitem(sys.modules, "ops_runtime_code_source", dependency)
    module = types.ModuleType("owned_real_git_runtime_code")
    body = (
        importlib.resources.files("ops_deploy.services.daybook_operations_runtime")
        .joinpath("files/runtime_code_guard.py")
        .read_bytes()
    )
    exec(compile(body, "<actual-runtime-code>", "exec"), module.__dict__)
    return module


class RuntimeProbes(SessionProbes):
    loaded = False
    serving = False
    pinned = "/owned/uv/python/cpython-3.14.7-owned/bin/python3.14"

    def run(self, argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        if argv[0] == "/bin/launchctl":
            return subprocess.CompletedProcess(argv, 0 if self.loaded else 113, b"", b"")
        if argv[0] == "/usr/bin/pgrep":
            return subprocess.CompletedProcess(argv, 0 if self.serving else 1, b"", b"")
        if argv[0] == self.data["uv_bin"]:
            return subprocess.CompletedProcess(argv, 0, self.pinned.encode() + b"\n", b"")
        return super().run(argv, **kwargs)

    def locked_environment_current(self) -> bool:
        return self.ready

    def managed(self, argv: list[str]) -> None:
        super().managed(argv)
        if argv[0] == self.data["uv_bin"]:
            # The actual UV/Python branch needs separate owned native proof.
            root = Path(self.data["checkout"])
            (root / ".git/info").mkdir(exist_ok=True)
            (root / ".git/info/exclude").write_text(".venv/\n")
            (root / ".venv").mkdir(exist_ok=True)
            (root / ".venv/bin").mkdir(exist_ok=True)
            (root / ".venv/bin/python").write_text("owned synthetic interpreter; never executed")
            (root / ".venv/bin/python").chmod(0o755)
            (root / ".venv/pyvenv.cfg").write_text("home = " + str(Path(self.pinned).parent) + "\n")


def prepared(checkout: Any) -> tuple[dict[str, Any], Path, Any]:  # noqa: F811
    data, bundle, source = checkout
    data.update(allow_create=True, owner="user", label="owned.never-real-runtime")
    return data, bundle, source


def test_original_different_revision_replacement_and_strict_repeat(
    helper: Any,
    checkout: Any,  # noqa: F811
) -> None:
    data, bundle, source = prepared(checkout)
    root = Path(data["checkout"])
    # Original runtime code.yml removes a readable different checkout; this
    # is deliberately distinct from checkout-only Sessions force:false.
    (root / "owned-old-untracked").write_text("owned synthetic source fixture")
    (root / "src/daybook/__init__.py").write_text("# owned dirty old revision\n")
    driver = RuntimeProbes(data)
    assert helper.inspect_code(data, driver)["replacing"] is True
    stage_transfer(data, bundle)
    helper.apply_code(data, driver)
    assert git(root, "rev-parse", "HEAD") == source.commit
    assert not (root / "owned-old-untracked").exists()
    assert git(root, "remote") == ""
    assert not Path(data["transfer_dir"]).exists()
    assert len(driver.syncs) == 1
    driver.loaded = driver.serving = True
    data["staged_bundle"] = False
    before = snapshot(root)
    helper.apply_code(data, driver)
    assert snapshot(root) == before
    assert len(driver.syncs) == 1


@pytest.mark.parametrize("running", ["loaded", "serving"])
def test_runtime_in_use_refuses_before_preparation_or_source_write(
    helper: Any,
    checkout: Any,  # noqa: F811
    running: str,
) -> None:
    data, _, _ = prepared(checkout)
    driver = RuntimeProbes(data)
    setattr(driver, running, True)
    before = snapshot(Path(data["checkout"]))
    with pytest.raises(helper.RuntimeCodeError, match="in_use"):
        helper.inspect_code(data, driver)
    assert snapshot(Path(data["checkout"])) == before
    assert not driver.syncs
    assert "transfer_dir" not in data


def test_failed_sync_keeps_failure_and_cleans_exact_private_transfer(
    helper: Any,
    checkout: Any,  # noqa: F811
) -> None:
    data, bundle, source = prepared(checkout)
    driver = RuntimeProbes(data)
    driver.fail_sync = True
    stage_transfer(data, bundle)
    with pytest.raises(SESSION["SourceError"], match="sessions_source_command_failed"):
        helper.apply_code(data, driver)
    assert git(Path(data["checkout"]), "rev-parse", "HEAD") == source.commit
    assert not Path(data["transfer_dir"]).exists()


def test_missing_environment_binary_with_matching_home_is_rebuilt(
    helper: Any,
    checkout: Any,  # noqa: F811
) -> None:
    data, bundle, _ = prepared(checkout)
    driver = RuntimeProbes(data)
    stage_transfer(data, bundle)
    helper.apply_code(data, driver)
    root = Path(data["checkout"])
    config_before = (root / ".venv/pyvenv.cfg").read_bytes()
    tracked_before = {name: (root / name).read_bytes() for name in ("src/daybook/__init__.py", "pyproject.toml")}
    stale = root / ".venv/owned-stale-marker"
    stale.write_text("must disappear only when the declared environment is removed")
    (root / ".venv/bin/python").unlink()
    driver.ready = False
    stage_transfer(data, bundle)
    helper.apply_code(data, driver)
    assert (root / ".venv/bin/python").is_file()
    assert not stale.exists()
    assert {name: (root / name).read_bytes() for name in tracked_before} == tracked_before
    assert (root / ".venv/pyvenv.cfg").read_bytes() == config_before
    assert len(driver.syncs) == 2
    assert not Path(data["transfer_dir"]).exists()
