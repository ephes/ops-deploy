"""Exercise the fixture wrapper with a Docker double, never a real daemon."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

SCRIPT = Path(__file__).parent / "integration/daybook_shared_notifier/run-container.sh"


@pytest.mark.parametrize(
    "case", ["success", "fixture_failure", "container_collision", "image_collision", "cleanup_failure"]
)
def test_owned_container_cleanup_and_collision_refusal(tmp_path: Path, case: str) -> None:
    binaries = tmp_path / "bin"
    binaries.mkdir()
    docker = binaries / "docker"
    docker.write_text(
        "#!/usr/bin/env python3\n"
        "import json,os,sys\nfrom pathlib import Path\n"
        "root=Path(os.environ['FAKE_DOCKER_ROOT']);args=sys.argv[1:];case=os.environ['FAKE_DOCKER_CASE']\n"
        "with (root/'calls').open('a') as f:f.write(json.dumps(args)+'\\n')\n"
        "if args[0] in ('container','image') and args[1]=='inspect':\n"
        " if '--format' in args: print('sha256:ownedimage');sys.exit(0)\n"
        " collision=(case=='container_collision' and args[0]=='container') or "
        "(case=='image_collision' and args[0]=='image')\n"
        " sys.exit(0 if collision or (root/args[0]).exists() else 1)\n"
        "if args[0]=='build': (root/'image').touch()\n"
        "if args[0]=='create': (root/'container').touch();print('ownedcontainer')\n"
        "if args[0]=='start': sys.exit(9 if case=='fixture_failure' else 0)\n"
        "if args[0] in ('container','image') and args[1]=='rm':\n"
        " if case=='cleanup_failure' and args[0]=='container':sys.exit(2)\n"
        " (root/args[0]).unlink()\n"
    )
    docker.chmod(0o755)
    uv = binaries / "uv"
    uv.write_text("#!/bin/sh\nexit 90\n")
    uv.chmod(0o755)
    env = dict(os.environ)
    env.update(
        PATH=str(binaries) + os.pathsep + env["PATH"],
        FAKE_DOCKER_ROOT=str(tmp_path),
        FAKE_DOCKER_CASE=case,
        GITHUB_ACTIONS="true",
        RUNNER_ENVIRONMENT="github-hosted",
        GITHUB_RUN_ID="123",
        GITHUB_RUN_ATTEMPT="1",
        IMPLEMENTATION_SHA="a" * 40,
        RUNNER_TEMP=str(tmp_path),
    )
    result = subprocess.run(["bash", str(SCRIPT.resolve())], env=env, capture_output=True, timeout=15)
    calls = [json.loads(line) for line in (tmp_path / "calls").read_text().splitlines()]
    receipt = tmp_path / "daybook-notifier-123-1/container-cleanup.json"
    if "collision" in case:
        assert result.returncode == 64
        assert all(call[1] == "inspect" for call in calls)
        assert not receipt.exists()
        return
    data = json.loads(receipt.read_text())
    assert result.returncode == {"success": 0, "fixture_failure": 9, "cleanup_failure": 1}[case]
    assert data["fixture_exit"] == (9 if case == "fixture_failure" else 0)
    assert data["owned_container_and_image_tag_removed"] is (case != "cleanup_failure")
    create = next(call for call in calls if call[0] == "create")
    mounts = [create[i + 1] for i, arg in enumerate(create) if arg == "--mount"]
    assert len(mounts) == 3
    assert sum(value.endswith(",readonly") for value in mounts) == 2
    assert all("/root/.ssh" not in value and "/etc/" not in value for value in mounts)
    assert ["container", "rm", "-f", "ownedcontainer"] in calls
    assert ["image", "rm", "daybook-notifier-123-1:fixture"] in calls


def test_real_owned_hardlink_and_cross_device_refusal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    spec = importlib.util.spec_from_file_location("notifier_owned_harness", SCRIPT.with_name("harness.py"))
    assert spec is not None
    assert spec.loader is not None
    harness = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(harness)
    source = tmp_path / "config.json"
    source.write_text("{}")
    destination = tmp_path / "config-link"
    harness.owned_hardlink(source, destination)
    assert source.stat().st_ino == destination.stat().st_ino
    assert source.stat().st_nlink == destination.stat().st_nlink == 2
    destination.unlink()
    other = tmp_path / "other-device"
    other.mkdir()
    actual_stat = Path.stat
    source_device = source.stat().st_dev

    def different_device(path: Path, *args: object, **kwargs: object) -> object:
        if path == other:
            return SimpleNamespace(st_dev=source_device + 1)
        return actual_stat(path, *args, **kwargs)  # type: ignore[arg-type]

    link = Mock()
    monkeypatch.setattr(Path, "stat", different_device)
    monkeypatch.setattr(harness.os, "link", link)
    with pytest.raises(AssertionError):
        harness.owned_hardlink(source, other / "config-link")
    link.assert_not_called()
