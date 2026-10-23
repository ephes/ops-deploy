"""Exercise the actual host admission script with an isolated local filesystem."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest

from ops_deploy.services.mastodon.deploy import PREFLIGHT
from tests.test_mastodon import config

SENTINEL = "mastodon-admission-fixture"


def host_fixture(tmp_path: Path) -> tuple[Any, dict[str, Any]]:
    path = tmp_path / "preflight.py"
    path.write_text(PREFLIGHT)
    spec = importlib.util.spec_from_file_location("mastodon_admission", path)
    assert spec is not None
    assert spec.loader is not None
    module: Any = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    home = tmp_path / "mastodon"
    site = home / "live"
    directories = [
        home,
        site,
        site / ".git",
        site / "public/system",
        site / "vendor/bundle",
        site / "node_modules",
        site / "public/assets",
        site / "public/packs",
        home / ".rbenv/versions/4.0.5/bin",
        home / ".nvm/versions/node/v24.17.0/bin",
    ]
    mapped = {
        name: tmp_path / name.lstrip("/")
        for name in ("/etc/mastodon", "/etc/traefik/dynamic", "/var/lib/mastodon-nginx/body", "/var/log/mastodon-nginx")
    }
    for directory in [*directories, *mapped.values()]:
        directory.mkdir(parents=True, exist_ok=True)
    for path in (
        site / "public/packs/manifest.json",
        site / "public/assets/.sprockets-manifest-fixture.json",
        home / ".rbenv/versions/4.0.5/bin/ruby",
        home / ".nvm/versions/node/v24.17.0/bin/node",
    ):
        path.touch()
    cfg = config(home_path=str(home), site_path=str(site), node_version="24.17").model_dump()
    for name in cfg["source_files"]:
        (site / name).write_text("locked\n")
    cfg["source_files"] = dict.fromkeys(cfg["source_files"], hashlib.sha256(b"locked\n").hexdigest())
    (site / ".env.production").write_text("fixture-secret-value\n")
    (site / ".env.production").chmod(0o600)
    if os.geteuid() == 0:
        os.chown(site / ".env.production", 501, -1)

    def mapped_path(value: str) -> Path:
        return tmp_path / value.lstrip("/") if value.startswith(("/etc/", "/var/")) else Path(value)

    for name in ("web", "sidekiq", "streaming", "nginx"):
        target = mapped_path(f"/etc/systemd/system/mastodon-{name}.service")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.touch()
    mapped_path("/etc/mastodon/nginx.conf").touch()
    mapped_path("/etc/traefik/dynamic/mastodon.yml").touch()
    module.Path = mapped_path
    module.pwd = SimpleNamespace(
        getpwnam=lambda _: SimpleNamespace(pw_dir=str(home), pw_uid=(site / ".env.production").stat().st_uid)
    )
    return module, {"config": cfg, "environment_b64": base64.b64encode(b"fixture-secret-value\n").decode()}


def test_actual_preflight_accepts_matching_existing_install(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    module, payload = host_fixture(tmp_path)

    def command(args: list[str], **kwargs: Any) -> Any:
        if args[0] == "runuser":
            assert args[:4] == ["runuser", "-u", "mastodon", "--"]
            return SimpleNamespace(
                returncode=0, stdout=payload["config"]["source_commit"] if "rev-parse" in args else ""
            )
        assert args[0] == "systemctl"
        if args[-1].startswith("mastodon_") or args[-1] == "mastodon-maintenance.service":
            return SimpleNamespace(returncode=3, stdout="")
        return SimpleNamespace(returncode=0, stdout="")

    with patch.object(module.subprocess, "run", side_effect=command):
        module.main(payload)
    assert capsys.readouterr().out == "24.17.0\n"


@pytest.mark.parametrize("failure", ["env", "lock", "media-link", "missing-build", "ambiguous-node", "untracked"])
def test_actual_preflight_refuses_immutable_drift(tmp_path: Path, failure: str) -> None:
    module, payload = host_fixture(tmp_path)
    site = Path(payload["config"]["site_path"])
    if failure == "env":
        payload["environment_b64"] = base64.b64encode(b"different-secret-value\n").decode()
    elif failure == "lock":
        (site / "Gemfile.lock").write_text("drift\n")
    elif failure == "media-link":
        (site / "public/system").rmdir()
        (site / "public/system").symlink_to(site / "node_modules", target_is_directory=True)
    elif failure == "missing-build":
        (site / "public/packs/manifest.json").unlink()
    elif failure == "ambiguous-node":
        node = Path(payload["config"]["home_path"]) / ".nvm/versions/node/v24.17.1/bin"
        node.mkdir(parents=True)
        (node / "node").touch()
    if failure == "untracked":

        def git_result(args: list[str], **kwargs: Any) -> Any:
            if args[0] == "systemctl":
                legacy = args[-1].startswith("mastodon_") or args[-1] == "mastodon-maintenance.service"
                return SimpleNamespace(stdout="", returncode=3 if legacy else 0)
            if "status" in args:
                return SimpleNamespace(stdout="?? config/initializers/leftover.rb", returncode=0)
            return SimpleNamespace(
                stdout=payload["config"]["source_commit"] if "rev-parse" in args else "", returncode=0
            )

        with patch.object(module.subprocess, "run", side_effect=git_result) as command:
            with pytest.raises(ValueError, match="existing-install contract"):
                module.main(payload)
            assert command.call_args_list[-1].args[0][-3:] == ["status", "--porcelain", "--untracked-files=normal"]
            assert all(call.args[0][0] != "systemctl" for call in command.call_args_list)
        return
    with patch.object(module.subprocess, "run") as command:
        with pytest.raises(ValueError, match="existing-install contract"):
            module.main(payload)
        command.assert_not_called()


def test_script_errors_never_echo_payload_secrets(tmp_path: Path) -> None:
    path = tmp_path / "preflight.py"
    path.write_text(PREFLIGHT)
    result = subprocess.run(
        [sys.executable, "-I", str(path)],
        input=json.dumps({"secret": SENTINEL}),
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr == "mastodon: existing-install admission refused\n"
