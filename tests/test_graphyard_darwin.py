"""Native role parity, credential transport and retained-state failure paths."""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import plistlib
import shlex
import sys
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.services.graphyard import GraphyardVectorConfig, GraphyardVectorDarwinConfig, deploy_graphyard_vector
from ops_deploy.services.graphyard.vector import fragment_text
from ops_deploy.services.graphyard.vector_darwin import host_command, native_payload
from ops_deploy.testing import run_deploy_fake
from tests.graphyard_fixtures import secrets_values
from tests.test_graphyard import assert_no_secret_leaks

ROOT = Path(__file__).parents[1]


def config(**overrides: Any) -> GraphyardVectorConfig:
    return GraphyardVectorConfig(
        host_id="studio",
        ingest_url="http://127.0.0.1:8051/v1/metrics",
        darwin=GraphyardVectorDarwinConfig(brew_user="runner"),
        **overrides,
    )


def host_script() -> Any:
    spec = importlib.util.spec_from_file_location(
        "graphyard_vector_host_test", ROOT / "src/ops_deploy/services/graphyard/files/graphyard_vector_host.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_native_defaults_and_literal_space_paths_are_role_compatible() -> None:
    cfg = config()
    assert cfg.filesystem_mountpoint_excludes == ()
    cfg = config(filesystem_mountpoint_excludes=("/Volumes/Backups of studio",))
    assert '"/Volumes/Backups of studio"' in fragment_text(cfg, secrets_values())
    assert GraphyardVectorConfig(
        host_id="linux", ingest_url="http://127.0.0.1:8051"
    ).filesystem_mountpoint_excludes == ("/run/docker/netns/*", "/var/lib/docker/*")


@pytest.mark.parametrize("path", ["/Volumes/a\nexcludes: evil", "/Volumes/a\rfoo", "/Volumes/a\x00", "/Volumes/a\x7f"])
def test_excludes_reject_control_characters(path: str) -> None:
    with pytest.raises(ValidationError):
        config(filesystem_mountpoint_excludes=(path,))


@pytest.mark.parametrize("name", ["vector.launchd.plist.j2", "vector.newsyslog.conf.j2"])
def test_native_role_resources_are_exact(name: str) -> None:
    shipped = ROOT / "src/ops_deploy/services/graphyard/templates" / name
    vendored = ROOT / "tests/parity/ansible" / ("graphyard_vector_deploy__" + name)
    assert shipped.read_bytes() == vendored.read_bytes()
    if source := os.environ.get("OPS_LIBRARY_PATH"):
        assert shipped.read_bytes() == (Path(source) / "roles/graphyard_vector_deploy/templates" / name).read_bytes()


def test_private_fragment_is_absent_from_every_command_argument() -> None:
    cfg = config()
    text = fragment_text(cfg, secrets_values())
    data = native_payload(cfg, text)
    for action in ("status", "apply", "verify"):
        command = host_command(data, action)
        decoded = json.loads(base64.b64decode(shlex.split(command)[-1]))
        assert "contents" not in decoded
        assert text not in str(decoded)
        assert secrets_values()["vector_ingest_token"] not in str(decoded)
        assert secrets_values()["vector_ingest_token"] not in command
        assert "hashes" in decoded


def test_native_plist_quotes_xml_text_without_changing_arguments() -> None:
    cfg = config().model_copy(update={"config_dir": Path("/tmp/vector & config")})
    data = native_payload(cfg, fragment_text(cfg, secrets_values()))
    parsed = plistlib.loads(data["contents"][str(data["launchd_plist_path"])].encode())
    assert parsed["ProgramArguments"][-1] == "/tmp/vector & config"


@pytest.mark.parametrize("state", ["current", "drift"])
def test_native_deploy_noop_and_secret_stdin_selection(state: str) -> None:
    cfg = config()
    data = native_payload(cfg, fragment_text(cfg, secrets_values()))
    run = run_deploy_fake(
        deploy_graphyard_vector, cfg, secrets_values(), responses={host_command(data, "status"): [state]}
    )
    assert run.succeeded, run.error
    assert len(run.mutating_changed_ops) == (state == "drift")
    assert run.uploaded_paths == []
    assert_no_secret_leaks(run)
    assert not any("apt" in command or "systemctl" in command for command in run.executed_commands)


def test_candidate_failure_never_publishes_or_restarts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = host_script()
    cfg = config()
    data = native_payload(cfg, fragment_text(cfg, secrets_values()))
    public = json.loads(base64.b64decode(shlex.split(host_command(data, "apply"))[-1]))
    public["plist_text"] = data["contents"][str(data["launchd_plist_path"])]
    public["resolved_binary"] = sys.executable
    monkeypatch.setattr(module, "tap_present", lambda _: True)
    monkeypatch.setattr(module, "installed", lambda _: True)
    monkeypatch.setattr(module, "duplicate", lambda _: True)
    brew_commands: list[Any] = []
    monkeypatch.setattr(module, "brew", lambda *args, **kwargs: brew_commands.append(args))
    monkeypatch.setattr(module, "directories", lambda *args, **kwargs: True)
    monkeypatch.setattr(
        module, "validate_candidate", lambda *args: (_ for _ in ()).throw(module.Failure("invalid candidate"))
    )
    published: list[Any] = []
    monkeypatch.setattr(module, "publish", lambda *args: published.append(args))
    monkeypatch.setattr(module, "job", lambda _: pytest.fail("job mutation after invalid candidate"))
    with pytest.raises(module.Failure, match="invalid candidate"):
        module.apply(public, data)
    assert published == []
    assert brew_commands == []


def test_unload_failure_keeps_configuration_unpublished(monkeypatch: pytest.MonkeyPatch) -> None:
    module = host_script()
    monkeypatch.setattr(module, "run", lambda *args, **kwargs: None)
    monkeypatch.setattr(module, "job", lambda _: (True, True))
    monkeypatch.setattr(module.time, "sleep", lambda _: None)
    with pytest.raises(module.Failure, match="configuration retained"):
        module.unload({"launchd_label": "fixture"})


def test_native_destination_collisions_fail_before_host_access() -> None:
    with pytest.raises(ValidationError, match="distinct"):
        config(config_name="00-global.yaml")
    with pytest.raises(ValidationError, match="must not overwrite"):
        GraphyardVectorConfig(
            host_id="fixture",
            ingest_url="http://127.0.0.1:8051",
            darwin=GraphyardVectorDarwinConfig(
                brew_user="runner", stdout_log_path=Path("/etc/vector/config.d/20-graphyard-host-metrics.yaml")
            ),
        )


def test_validation_retains_peer_content_and_uses_private_role_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from types import SimpleNamespace

    module = host_script()
    live = tmp_path / "live"
    live.mkdir()
    peer = live / "peer.toml"
    peer.write_text("# owned retained peer configuration\n")
    peer.chmod(0o644)
    original = (peer.read_bytes(), peer.stat().st_ino, peer.stat().st_mode)
    requested: list[tuple[Any, ...]] = []
    monkeypatch.setattr(module.os, "chown", lambda *args: requested.append(args))
    monkeypatch.setattr(module.grp, "getgrnam", lambda _: SimpleNamespace(gr_gid=123))

    def validate(argv: list[str]) -> None:
        staged = Path(argv[-1]) / "peer.toml"
        assert staged.read_bytes() == original[0]
        assert staged.stat().st_mode & 0o777 == 0o640

    monkeypatch.setattr(module, "run", validate)
    cfg = {
        "config_dir": str(live),
        "config_path": str(live / "20.yaml"),
        "global_config_path": str(live / "00.yaml"),
        "validation_group": "fixture",
        "resolved_binary": sys.executable,
    }
    module.validate_candidate(cfg, {cfg["config_path"]: "sources: {}\n", cfg["global_config_path"]: "data_dir: /tmp\n"})
    assert (peer.read_bytes(), peer.stat().st_ino, peer.stat().st_mode) == original
    assert any(Path(args[0]).name == "peer.toml" and args[1:] == (0, 123) for args in requested)
