"""Actual pyinfra operation plans for MinIO's bounded first/repeat paths."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr, ValidationError

from ops_deploy.helpers.traefik import hash_password
from ops_deploy.services.minio import MinioConfig, MinioCredentials, MinioPolicy, deploy_minio
from ops_deploy.services.minio.config import MC_DOWNLOAD_URL, MC_SHA256, MC_VERSION, MINIO_SHA256
from ops_deploy.services.minio.deploy import host_command
from ops_deploy.services.minio.render import render
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests import fakehost

CREDS = MinioCredentials(root_user=SecretStr("fixture-root"), root_password=SecretStr("fixture-root-value"))
PREFIX = "Deploy MinIO | "


def facts(cfg: MinioConfig, creds: MinioCredentials = CREDS, *, pending: int = 0) -> dict[str, Any]:
    result = {
        **fakehost.UBUNTU,
        **fakehost.system_account(cfg.user, cfg.home, shell="/usr/sbin/nologin"),
        **fakehost.directory(cfg.home, user=cfg.user),
        **fakehost.directory(cfg.config_dir),
        **fakehost.directory("/etc/systemd/system"),
        **fakehost.directory(cfg.policy_dir, mode="drwxr-x---"),
        **fakehost.file(cfg.env_file, render("minio.env.j2", cfg, creds), mode="-rw-------"),
        **fakehost.file(cfg.service_unit, render("minio.service.j2", cfg, creds)),
        **fakehost.stat(cfg.bin_path, mode="-rwxr-xr-x"),
        **fakehost.stat(cfg.mc_bin_path, mode="-rwxr-xr-x"),
        **fakehost.service("minio.service"),
        f"sha256sum {cfg.bin_path} ": [f"{MINIO_SHA256}  {cfg.bin_path}"],
        f"sha256sum {cfg.mc_bin_path} ": [f"{MC_SHA256}  {cfg.mc_bin_path}"],
        host_command("data_roots"): ["current"],
        host_command("iam_host", "check"): [json.dumps({"pending": pending, "changed": False})],
        host_command("iam_host", "inspect-current"): [json.dumps({"pending": pending, "changed": False})],
        host_command("iam_host", "recovery"): [json.dumps({"recover_client": False, "recover_service": False})],
    }
    for path in cfg.data_dirs:
        result.update(fakehost.directory(path, user=cfg.user, mode="drwxr-x---"))
    for policy in cfg.policies:
        result.update(fakehost.file(f"{cfg.policy_dir}/{policy.name}.json", policy.file_content, mode="-rw-r-----"))
    return result


def execute(cfg: MinioConfig, responses: dict[str, Any], creds: MinioCredentials = CREDS) -> FakeRun:
    return run_deploy_fake(deploy_minio, cfg, creds, responses=responses)


def test_matching_service_and_iam_have_zero_managed_operations_and_uploads() -> None:
    cfg = MinioConfig(bootstrap_with_mc=True)
    run = execute(cfg, facts(cfg))
    assert run.succeeded, run.error
    assert run.mutating_changed_ops == []
    assert run.uploads == []
    assert not any("restart" in command or "daemon-reload" in command for command in run.executed_commands)
    assert all("fixture-root-value" not in command for command in run.executed_commands)


def test_iam_rotation_alone_has_one_operation_without_restart_or_upload() -> None:
    cfg = MinioConfig(bootstrap_with_mc=True)
    run = execute(cfg, facts(cfg, pending=1))
    assert run.succeeded, run.error
    assert run.mutating_changed_ops == [PREFIX + "Converge declared MinIO IAM and bucket configuration"]
    assert run.uploads == []
    assert not any("restart" in command for command in run.executed_commands)


def test_unknown_iam_response_stops_before_any_operation() -> None:
    cfg = MinioConfig(bootstrap_with_mc=True)
    response = facts(cfg)
    response[host_command("iam_host", "inspect-current")] = [
        "refused: client could not execute",
        "ops-deploy-probe-failed",
    ]
    run = execute(cfg, response)
    assert run.error is not None
    assert run.ops == []
    assert run.uploads == []


def test_foreign_data_owner_stops_before_any_operation() -> None:
    cfg = MinioConfig(bootstrap_with_mc=True)
    response = facts(cfg)
    response[host_command("data_roots")] = ["refused: foreign owner", "ops-deploy-probe-failed"]
    run = execute(cfg, response)
    assert run.error is not None
    assert run.ops == []


def test_policy_file_spelling_drift_does_not_rewrite_identical_server_policy() -> None:
    policy = MinioPolicy(name="fixture", document={"Version": "2012-10-17", "Statement": []})
    cfg = MinioConfig(bootstrap_with_mc=True, policies=(policy,))
    response = facts(cfg)
    response.update(fakehost.file(f"{cfg.policy_dir}/fixture.json", "old spelling", mode="-rw-r-----"))
    run = execute(cfg, response)
    assert run.succeeded, run.error
    assert run.mutating_changed_ops == [PREFIX + f"Write {cfg.policy_dir}/fixture.json"]
    assert len(run.uploads) == 1


def test_existing_console_bcrypt_hash_and_role_route_are_preserved() -> None:
    creds = MinioCredentials.model_validate(
        {**CREDS.model_dump(), "console_basic_auth_password": SecretStr("synthetic-console-value")}
    )
    cfg = MinioConfig(
        expose_via_traefik=True, traefik_host="minio.example.test", traefik_api_host="objects.example.test"
    )
    hashed = hash_password("synthetic-console-value")
    response = facts(cfg, creds)
    response.update(fakehost.directory("/etc/traefik/dynamic"))
    response.update(fakehost.deb_installed("apache2-utils"))
    response.update(fakehost.file(cfg.traefik_config_path, render("traefik-minio.yml.j2", cfg, creds, hashed)))
    run = execute(cfg, response, creds)
    assert run.succeeded, run.error
    assert run.mutating_changed_ops == []
    assert run.uploads == []


def test_fresh_server_starts_before_bootstrap_and_does_not_restart_again() -> None:
    cfg = MinioConfig(bootstrap_with_mc=True)
    run = execute(
        cfg,
        {
            **fakehost.UBUNTU,
            host_command("data_roots"): ["empty"],
            host_command("iam_host", "check"): [json.dumps({"pending": 1, "changed": False})],
        },
    )
    assert run.succeeded, run.error
    changed = run.mutating_changed_ops
    assert changed.index(PREFIX + "Start minio.service") < changed.index(
        PREFIX + "Converge declared MinIO IAM and bucket configuration"
    )
    assert PREFIX + "Restart minio.service" not in changed
    assert not any("chmod -R" in command or "chown -R" in command for command in run.executed_commands)


def test_existing_data_is_not_misclassified_as_fresh_after_missing_unit() -> None:
    cfg = MinioConfig(bootstrap_with_mc=True)
    response = {
        **fakehost.UBUNTU,
        **fakehost.directory(cfg.data_dirs[0], user="minio"),
        host_command("data_roots"): ["current"],
        host_command("iam_host", "check"): ["ops-deploy-probe-failed"],
    }
    run = execute(cfg, response)
    assert run.error is not None
    assert run.ops == []


def test_wrong_local_binary_hash_fails_before_operations(tmp_path: Path) -> None:
    path = tmp_path / "minio"
    path.write_bytes(b"wrong artifact")
    with pytest.raises(ValueError, match="pinned checksum"):
        execute(MinioConfig(local_minio_binary=path), {})


@pytest.mark.parametrize(
    "fields",
    [
        {"data_dirs": ()},
        {"data_dirs": ("/",)},
        {"data_dirs": ("/var/../data",)},
        {"api_port": True},
        {"api_port": 9002},
        {"traefik_config_path": "/tmp/ignored.yml"},
    ],
)
def test_invalid_configuration_refused(fields: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        MinioConfig.model_validate(fields)


def test_bad_download_never_replaces_existing_executable(tmp_path: Path) -> None:
    import os
    import shutil
    import subprocess

    from ops_deploy.services.minio.deploy import binary_install_command

    assert shutil.which("sha256sum") is not None
    directory = tmp_path / "bin"
    directory.mkdir()
    curl = directory / "curl"
    curl.write_text(
        '#!/bin/sh\nprintf curl-executed >&2\nwhile [ "$1" != "-o" ]; do shift; done\nprintf wrong > "$2"\n'
    )
    curl.chmod(0o700)
    binary = tmp_path / "minio"
    binary.write_bytes(b"existing executable")
    binary.chmod(0o755)
    before = binary.read_bytes(), binary.stat().st_mtime_ns, binary.stat().st_ino
    result = subprocess.run(
        binary_install_command(str(binary), MINIO_SHA256, "https://example.invalid/artifact"),
        shell=True,
        env={**os.environ, "PATH": str(directory) + os.pathsep + os.environ["PATH"]},
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert result.stderr == "curl-executed"
    assert (binary.read_bytes(), binary.stat().st_mtime_ns, binary.stat().st_ino) == before
    assert list(tmp_path.glob(".minio-artifact.*")) == []


@pytest.mark.parametrize("field", ["traefik_host", "traefik_api_host"])
def test_both_route_hostnames_must_be_configured(field: str) -> None:
    fields = {
        "expose_via_traefik": True,
        "traefik_host": "console.example.test",
        "traefik_api_host": "objects.example.test",
    }
    fields.pop(field)
    with pytest.raises(ValueError, match="console and API"):
        execute(MinioConfig.model_validate(fields), {})


def test_exact_identity_cannot_retire_superseded_policy() -> None:
    from ops_deploy.services.minio import MinioIdentity, MinioSupersededPolicy

    with pytest.raises(ValidationError, match="additive identity"):
        MinioConfig(
            bootstrap_with_mc=True,
            policies=(MinioPolicy(name="current", document={"Version": "2012-10-17", "Statement": []}),),
            identities=(MinioIdentity(name="identity", policies=("current",), exact=True, proof="bucket"),),
            superseded=(MinioSupersededPolicy(name="old", identity="identity"),),
        )


def test_both_original_port_preflights_precede_managed_operations() -> None:
    cfg = MinioConfig(bootstrap_with_mc=True)
    run = execute(cfg, facts(cfg))
    assert run.succeeded, run.error
    assert [op.name for op in run.ops][:2] == [PREFIX + f"MinIO port preflight tcp/{port}" for port in (9001, 9002)]
    assert all(op.read_only for op in run.ops[:2])
    commands = [cmd for cmd in run.executed_commands if "ss -Hltnp" in cmd]
    assert len(commands) == 2
    assert all("0::/system.slice/minio.service" in cmd for cmd in commands)


@pytest.mark.parametrize(
    "reason", ["unrecognized root credentials", "client could not execute", "transport or unknown"]
)
def test_existing_unavailable_iam_refuses_before_recovery_changes(reason: str) -> None:
    cfg = MinioConfig(bootstrap_with_mc=True)
    response = facts(cfg)
    response[host_command("iam_host", "inspect-current")] = ["refused: " + reason, "ops-deploy-probe-failed"]
    run = execute(cfg, response)
    assert run.error is not None
    assert run.ops == []
    assert run.uploads == []


def test_missing_client_is_managed_before_late_iam_refusal_and_no_env_write() -> None:
    cfg = MinioConfig(bootstrap_with_mc=True)
    response = facts(cfg)
    response[host_command("iam_host", "recovery")] = [json.dumps({"recover_client": True, "recover_service": False})]
    response[f"sha256sum {cfg.mc_bin_path} "] = ["old-client"]
    response[host_command("iam_host", "inspect-current")] = {"success": False, "stdout": ["refused: disabled user"]}
    run = execute(cfg, response)
    assert not run.succeeded
    assert run.mutating_changed_ops == [PREFIX + "Download pinned MinIO recovery client"]
    assert run.uploads == []
    assert not any("restart" in command for command in run.executed_commands)


def test_root_rotation_uses_current_admission_then_desired_env_restart_and_iam() -> None:
    cfg = MinioConfig(bootstrap_with_mc=True)
    desired = MinioCredentials(root_user=SecretStr("fixture-root-new"), root_password=SecretStr("fixture-new-value"))
    response = facts(cfg, CREDS, pending=1)
    run = execute(cfg, response, desired)
    assert run.succeeded, run.error
    changes = run.mutating_changed_ops
    assert (
        changes.index(PREFIX + "Write MinIO environment")
        < changes.index(PREFIX + "Restart minio.service")
        < changes.index(PREFIX + "Converge declared MinIO IAM and bucket configuration")
    )
    assert run.uploads == []  # secret_file transports protected stdin, not an upload.
    assert any("inspect-current" in event.value for event in run.events if event.kind == "fact")


def test_successful_client_recovery_downloads_once_before_late_admission() -> None:
    cfg = MinioConfig(bootstrap_with_mc=True)
    response = facts(cfg)
    response[host_command("iam_host", "recovery")] = [json.dumps({"recover_client": True, "recover_service": False})]
    response[f"sha256sum {cfg.mc_bin_path} "] = ["old-client"]
    run = execute(cfg, response)
    assert run.succeeded, run.error
    assert run.mutating_changed_ops == [PREFIX + "Download pinned MinIO recovery client"]
    assert run.uploads == []


def test_verified_official_mc_source_is_used_only_for_missing_or_drifted_client() -> None:
    assert MC_DOWNLOAD_URL == (
        "https://github.com/minio/mc/releases/download/" + MC_VERSION + "/mc.linux-amd64." + MC_VERSION
    )
    cfg = MinioConfig(bootstrap_with_mc=True)
    current = execute(cfg, facts(cfg))
    assert current.succeeded, current.error
    assert not any("curl -fsSL" in command for command in current.executed_commands)
    response = facts(cfg)
    response[host_command("iam_host", "recovery")] = [json.dumps({"recover_client": True, "recover_service": False})]
    response[f"sha256sum {cfg.mc_bin_path} "] = ["old-client"]
    missing = execute(cfg, response)
    assert missing.succeeded, missing.error
    downloads = [command for command in missing.executed_commands if "curl -fsSL" in command]
    assert len(downloads) == 1
    assert MC_DOWNLOAD_URL in downloads[0]
    assert MC_SHA256 in downloads[0]
