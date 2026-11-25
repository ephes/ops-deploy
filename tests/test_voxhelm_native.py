"""Native Voxhelm role rendering, package selection and controller validation."""

from __future__ import annotations

import base64
import json
import plistlib
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.services.voxhelm import VoxhelmConfig, deploy_voxhelm
from ops_deploy.services.voxhelm import deploy as deploy_module
from ops_deploy.services.voxhelm.deploy import source_overrides
from ops_deploy.services.voxhelm.render import payload as control_payload
from ops_deploy.services.voxhelm_remote_worker import VoxhelmRemoteWorkerConfig, deploy_voxhelm_remote_worker
from ops_deploy.services.voxhelm_remote_worker.deploy import worker_host_command as command
from ops_deploy.services.voxhelm_remote_worker.render import payload as worker_payload
from ops_deploy.testing import RecordingRsyncRunner, run_deploy_fake
from tests import fakehost

TOKEN = "owned-synthetic-worker-token-not-a-private-credential"


def worker_config(**overrides: Any) -> VoxhelmRemoteWorkerConfig:
    return VoxhelmRemoteWorkerConfig.model_validate(
        {
            "voxhelm_remote_worker_service_user": "fixture",
            "voxhelm_remote_worker_base_url": "http://127.0.0.1:28787",
            "voxhelm_remote_worker_artifact_s3_endpoint_url": "http://127.0.0.1:29000",
            **overrides,
        }
    )


def worker_secrets() -> dict[str, str]:
    return {
        "voxhelm_remote_worker_token": TOKEN,
        "voxhelm_remote_worker_huggingface_token": "synthetic-hf-fixture",
        "voxhelm_remote_worker_artifact_s3_access_key_id": "synthetic-access-fixture",
        "voxhelm_remote_worker_artifact_s3_secret_access_key": "synthetic-secret-fixture",
    }


def control_config(tmp_path: Path, **overrides: Any) -> VoxhelmConfig:
    return VoxhelmConfig.model_validate(
        {
            "voxhelm_source_path": str(tmp_path),
            "voxhelm_bootstrap_operator_username": "fixture-operator",
            **overrides,
        }
    )


def control_secrets() -> dict[str, str]:
    return {
        "voxhelm_django_secret_key": "synthetic-django-fixture",
        "voxhelm_bearer_tokens_env": TOKEN,
        "voxhelm_bootstrap_operator_password": "synthetic-password-fixture",
    }


def test_worker_default_paths_and_caffeinate_template_are_original() -> None:
    cfg = worker_config()
    data = worker_payload(cfg, worker_secrets())
    assert cfg.voxhelm_remote_worker_work_dir == "/Users/fixture/Library/Application Support/voxhelm-remote-worker"
    plist = plistlib.loads(data["contents"][cfg.voxhelm_remote_worker_launchd_plist_path]["content"].encode())
    assert plist["UserName"] == "fixture"
    assert plist["GroupName"] == "staff"
    assert plist["ProgramArguments"] == ["/bin/sh", cfg.voxhelm_remote_worker_launcher_path]
    launcher = data["contents"][cfg.voxhelm_remote_worker_launcher_path]["content"]
    assert "caffeinate" in launcher
    assert "--env-file" in launcher


@pytest.mark.parametrize(
    "overrides",
    [
        {"voxhelm_remote_worker_package_name": "other"},
        {"voxhelm_remote_worker_public_index_url": "https://other.test"},
        {"voxhelm_remote_worker_package_version": "latest"},
        {"voxhelm_remote_worker_poll_seconds": 0},
        {"voxhelm_remote_worker_service_user": "CHANGEME"},
        {"voxhelm_remote_worker_private_url_hosts": ["host,other"]},
        {"voxhelm_remote_worker_ad_analysis_enabled": True},
        {"voxhelm_remote_worker_model_cache_dir": "/tmp/../other"},
    ],
)
def test_worker_invalid_inputs_fail_before_connection(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        worker_config(**overrides)


def test_worker_disabled_role_does_not_contact_or_stop_existing_service() -> None:
    cfg = VoxhelmRemoteWorkerConfig(voxhelm_remote_worker_enabled=False)
    run = run_deploy_fake(deploy_voxhelm_remote_worker, cfg, {})
    assert run.succeeded, run.error
    assert run.executed_commands == []
    assert run.stdin == []


def test_worker_current_state_sends_no_credentials_or_managed_changes() -> None:
    cfg = worker_config()
    run = run_deploy_fake(deploy_voxhelm_remote_worker, cfg, worker_secrets(), responses={" status ": ["current"]})
    assert run.succeeded, run.error
    assert run.mutating_changed_ops == []
    assert run.stdin == []
    assert TOKEN not in run.all_text()


def test_worker_payload_is_stdin_only_with_public_resource_hashes() -> None:
    data = worker_payload(worker_config(), worker_secrets())
    for action in ("status", "apply", "verify"):
        public = command(data, action)
        assert TOKEN not in public
        decoded = json.loads(base64.b64decode(shlex.split(public)[-1]))
        assert TOKEN not in json.dumps(decoded)
        assert all("content" not in resource for resource in decoded["contents"].values())


def test_control_preserves_periodic_pruning_without_starting_it(tmp_path: Path) -> None:
    cfg = control_config(tmp_path, voxhelm_prune_enabled=True, voxhelm_prune_dry_run=False)
    data = control_payload(cfg, control_secrets())
    prune = next(unit for unit in data["units"] if unit["name"] == "prune")
    assert prune["start"] is False
    assert prune["periodic"] is True
    plist = plistlib.loads(data["contents"][cfg.voxhelm_prune_plist_path]["content"].encode())
    assert plist["RunAtLoad"] is False
    assert plist["KeepAlive"] is False
    assert plist["StartInterval"] == 3600
    assert not plist.get("StartCalendarInterval")


def test_control_wyoming_runs_interactive_and_warms_up_by_default(tmp_path: Path) -> None:
    cfg = control_config(tmp_path)
    data = control_payload(cfg, control_secrets())
    wyoming = plistlib.loads(data["contents"][cfg.voxhelm_wyoming_stt_plist_path]["content"].encode())
    assert wyoming["ProcessType"] == "Interactive"
    api = plistlib.loads(data["contents"][cfg.voxhelm_launchd_plist_path]["content"].encode())
    assert "ProcessType" not in api
    env = data["contents"][cfg.voxhelm_config_dir + "/voxhelm.env"]["content"]
    assert "VOXHELM_WYOMING_STT_WARMUP=true\n" in env


def test_control_wyoming_process_type_and_warm_up_can_be_switched_off(tmp_path: Path) -> None:
    cfg = control_config(tmp_path, voxhelm_wyoming_stt_process_type="", voxhelm_wyoming_stt_warmup=False)
    data = control_payload(cfg, control_secrets())
    wyoming = plistlib.loads(data["contents"][cfg.voxhelm_wyoming_stt_plist_path]["content"].encode())
    assert "ProcessType" not in wyoming
    env = data["contents"][cfg.voxhelm_config_dir + "/voxhelm.env"]["content"]
    assert "VOXHELM_WYOMING_STT_WARMUP=false\n" in env


def test_control_parakeet_wyoming_backend_renders_model_dir(tmp_path: Path) -> None:
    cfg = control_config(
        tmp_path, voxhelm_wyoming_stt_backend="parakeet-mlx", voxhelm_parakeet_model_dir="/models/parakeet/rev"
    )
    data = control_payload(cfg, control_secrets())
    env = data["contents"][cfg.voxhelm_config_dir + "/voxhelm.env"]["content"]
    assert "VOXHELM_WYOMING_STT_BACKEND=parakeet-mlx\n" in env
    assert "VOXHELM_PARAKEET_MODEL_DIR=/models/parakeet/rev\n" in env


def test_control_default_env_leaves_parakeet_model_dir_unset(tmp_path: Path) -> None:
    cfg = control_config(tmp_path)
    env = control_payload(cfg, control_secrets())["contents"][cfg.voxhelm_config_dir + "/voxhelm.env"]["content"]
    assert "VOXHELM_PARAKEET_MODEL_DIR" not in env


def test_control_false_component_flags_leave_them_unmanaged(tmp_path: Path) -> None:
    cfg = control_config(tmp_path, voxhelm_worker_enabled=False, voxhelm_wyoming_stt_enabled=False)
    data = control_payload(cfg, control_secrets())
    assert [unit["name"] for unit in data["units"]] == ["api"]
    assert cfg.voxhelm_worker_plist_path not in data["contents"]


@pytest.mark.parametrize(
    "overrides",
    [
        {"voxhelm_prune_interval_seconds": 59},
        {"voxhelm_wyoming_stt_process_type": "Realtime"},
        {"voxhelm_wyoming_stt_backend": "parakeet-mlx"},
        {"voxhelm_wyoming_stt_backend": "parakeet-mlx", "voxhelm_parakeet_model_dir": "relative/dir"},
        {"voxhelm_prune_daily_time": "25:00"},
        {"voxhelm_known_speaker_stt_backend": "other"},
        {"voxhelm_csrf_trusted_origins": ["https://example.test/path"]},
        {"voxhelm_transcription_execution_mode": "other"},
        {"voxhelm_source_artifact_retention_seconds": -1},
        {"voxhelm_tts_language_routing_enabled": True, "voxhelm_tts_language_voices": {"en": "kokoro-unconfigured"}},
    ],
)
def test_control_invalid_inputs_fail_before_connection(tmp_path: Path, overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        control_config(tmp_path, **overrides)


def test_control_remote_pull_requires_shared_credentials(tmp_path: Path) -> None:
    cfg = control_config(tmp_path, voxhelm_transcription_execution_mode="remote_pull")
    with pytest.raises(ValueError, match="shared S3 artifacts"):
        control_payload(cfg, control_secrets())


def test_control_current_bootstrap_probe_is_readonly_stdin_and_no_managed_operation(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nname="voxhelm"\nversion="0.1.11"\n')
    cfg = control_config(tmp_path)
    responses = {"-status ": ["current"], " bootstrap-check ": ["current"], **fakehost.directory(cfg.voxhelm_app_dir)}
    run = run_deploy_fake(deploy_voxhelm, cfg, control_secrets(), responses=responses, rsync=RecordingRsyncRunner())
    assert run.succeeded, run.error
    assert run.mutating_changed_ops == []
    assert len(run.stdin) == 2
    # One standard redacted fact input and one read-only verification input.
    assert "bootstrap-check" in run.stdin[0][0]
    assert control_secrets()["voxhelm_bootstrap_operator_password"] in run.stdin[0][1]
    for value in control_secrets().values():
        assert value not in run.all_text()


def test_control_fresh_database_and_bootstrap_precede_launchd(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nname="voxhelm"\nversion="0.1.11"\n')
    cfg = control_config(tmp_path)
    run = run_deploy_fake(
        deploy_voxhelm, cfg, control_secrets(), responses={" bootstrap-check ": ["drift"]}, rsync=RecordingRsyncRunner()
    )
    assert run.succeeded, run.error
    operations = "\n".join(run.mutating_changed_ops)
    assert operations.index("Render native Voxhelm environment") < operations.index("database migrations")
    assert operations.index("database migrations") < operations.index("bootstrap operator")
    assert operations.index("bootstrap operator") < operations.index("launchd services")
    assert operations.index("launchd services") < operations.index("Complete verified")
    for value in control_secrets().values():
        assert value not in run.all_text()


def test_source_blob_preservation_is_exact_revision_and_clean_tree_only(tmp_path: Path) -> None:
    def git(*arguments: str) -> str:
        return subprocess.run(
            ["git", "-C", str(tmp_path), *arguments], check=True, capture_output=True, text=True
        ).stdout.strip()

    git("init", "--initial-branch=main")
    (tmp_path / "README.md").write_text("current public source documentation\n")
    git("add", "README.md")
    git("-c", "user.name=Owned Fixture", "-c", "user.email=fixture@example.test", "commit", "-m", "owned baseline")
    head = git("rev-parse", "HEAD")
    cfg = control_config(
        tmp_path, source_preservation_revision=head, source_overrides={"README.md": "older public blob\n"}
    )
    index = (tmp_path / ".git/index").stat()
    assert source_overrides(cfg) == {"README.md": "older public blob\n"}
    assert source_overrides(cfg) == {"README.md": "older public blob\n"}
    after = (tmp_path / ".git/index").stat()
    assert (after.st_ino, after.st_mtime_ns, after.st_ctime_ns) == (index.st_ino, index.st_mtime_ns, index.st_ctime_ns)
    # Deliberately edited source resumes ordinary rsync, even before a commit.
    (tmp_path / "README.md").write_text("deliberately changed source\n")
    assert source_overrides(cfg) == {}
    git("add", "README.md")
    git("-c", "user.name=Owned Fixture", "-c", "user.email=fixture@example.test", "commit", "-m", "owned update")
    assert source_overrides(cfg) == {}


def test_source_sync_protects_rendered_launchers_from_delete(tmp_path: Path) -> None:
    # The launchers are rendered into the synced tree but are not source files;
    # --delete would remove them on every unchanged repeat.
    (tmp_path / "pyproject.toml").write_text('[project]\nname="voxhelm"\nversion="0.1.11"\n')
    cfg = control_config(tmp_path, voxhelm_worker_enabled=False, voxhelm_prune_enabled=False)
    recorder = RecordingRsyncRunner()
    responses = {"-status ": ["current"], " bootstrap-check ": ["current"], **fakehost.directory(cfg.voxhelm_app_dir)}
    run = run_deploy_fake(deploy_voxhelm, cfg, control_secrets(), responses=responses, rsync=recorder)
    assert run.succeeded, run.error
    argv = recorder.calls[0]
    assert "--delete" in argv
    for name in ["start.sh", "worker.sh", "wyoming-stt.sh", "whisperkit.sh", "prune.sh"]:
        assert "--exclude=/" + name in argv
    outside = control_config(tmp_path, voxhelm_start_script_path="/usr/local/libexec/voxhelm-start.sh")
    assert "/start.sh" not in deploy_module.generated_launchers(outside)


def test_control_batch_url_limits_match_long_recordings(tmp_path: Path) -> None:
    cfg = control_config(tmp_path)
    data = control_payload(cfg, control_secrets())
    env = data["contents"][cfg.voxhelm_config_dir + "/voxhelm.env"]["content"].splitlines()
    assert f"VOXHELM_BATCH_MAX_DOWNLOAD_BYTES={16 * 1024**3}" in env
    assert "VOXHELM_BATCH_URL_FETCH_TIMEOUT_SECONDS=3600" in env
    assert f"VOXHELM_MAX_URL_DOWNLOAD_BYTES={128 * 1024**2}" in env
    assert "VOXHELM_URL_FETCH_TIMEOUT_SECONDS=60" in env

    custom = control_config(
        tmp_path, voxhelm_batch_max_download_bytes=1024, voxhelm_batch_url_fetch_timeout_seconds=7200
    )
    custom_env = control_payload(custom, control_secrets())["contents"][custom.voxhelm_config_dir + "/voxhelm.env"][
        "content"
    ].splitlines()
    assert "VOXHELM_BATCH_MAX_DOWNLOAD_BYTES=1024" in custom_env
    assert "VOXHELM_BATCH_URL_FETCH_TIMEOUT_SECONDS=7200" in custom_env


@pytest.mark.parametrize(
    "overrides",
    [
        {"voxhelm_batch_max_download_bytes": 0},
        {"voxhelm_batch_url_fetch_timeout_seconds": 0},
        {"voxhelm_batch_url_fetch_timeout_seconds": -1},
    ],
)
def test_control_batch_url_limits_must_be_positive(tmp_path: Path, overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError, match="must be positive"):
        control_config(tmp_path, **overrides)


@pytest.mark.skipif(shutil.which("rsync") is None, reason="needs rsync, as on the target")
def test_source_sync_keeps_sqlite_database_and_sidecars_across_delete(tmp_path: Path) -> None:
    # The live database runs in rollback-journal mode; --delete must never
    # unlink a hot journal (or a WAL/SHM pair) next to db.sqlite3.
    source = tmp_path / "source"
    source.mkdir()
    (source / "pyproject.toml").write_text('[project]\nname="voxhelm"\nversion="0.1.15"\n')
    cfg = control_config(source, voxhelm_worker_enabled=False, voxhelm_prune_enabled=False)
    recorder = RecordingRsyncRunner()
    responses = {"-status ": ["current"], " bootstrap-check ": ["current"], **fakehost.directory(cfg.voxhelm_app_dir)}
    run = run_deploy_fake(deploy_voxhelm, cfg, control_secrets(), responses=responses, rsync=recorder)
    assert run.succeeded, run.error
    excludes = [arg for arg in recorder.calls[0] if arg.startswith("--exclude=")]
    assert "--exclude=db.sqlite3" in excludes
    assert "--exclude=db.sqlite3-*" in excludes
    target = tmp_path / "site"
    target.mkdir()
    kept = ["db.sqlite3", "db.sqlite3-journal", "db.sqlite3-wal", "db.sqlite3-shm"]
    for name in kept:
        (target / name).write_bytes(b"fixture " + name.encode() + b"\n")
    (target / "stale.py").write_text("removed by --delete\n")
    subprocess.run(
        ["rsync", "-rl", "--delete", *excludes, str(source) + "/", str(target) + "/"],
        check=True,
        capture_output=True,
        timeout=30,
    )
    assert not (target / "stale.py").exists()
    assert (target / "pyproject.toml").is_file()
    for name in kept:
        assert (target / name).read_bytes() == b"fixture " + name.encode() + b"\n"
