"""RustFS operation plans against a fake host, plus the IAM helper's pure parts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any
from unittest import mock

import pytest
from pydantic import SecretStr, ValidationError

from ops_deploy.services.rustfs import (
    RUSTFS_ARTIFACTS,
    RustfsBucket,
    RustfsConfig,
    RustfsCredentials,
    RustfsIdentity,
    RustfsPolicy,
    RustfsUserCredentials,
    deploy_rustfs,
)
from ops_deploy.services.rustfs.deploy import binary_install_command, host_command, render
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests import fakehost

ROOT = RustfsUserCredentials(access=SecretStr("fixture-root"), secret=SecretStr("fixture-root-value"))
CREDS = RustfsCredentials(root=ROOT)
PREFIX = "Deploy RustFS | "
POLICY = RustfsPolicy(
    name="app-rw",
    document={
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::app/x/*"]}],
    },
)
IAM_CFG = RustfsConfig(
    buckets=(RustfsBucket(name="app"),),
    policies=(POLICY,),
    identities=(RustfsIdentity(name="app", policies=("app-rw",), proof="app/x/.absent"),),
)
IAM_CREDS = RustfsCredentials(
    root=ROOT,
    identities={"app": RustfsUserCredentials(access=SecretStr("app-user"), secret=SecretStr("app-user-value"))},
)


def facts(
    cfg: RustfsConfig, creds: RustfsCredentials = CREDS, *, pending: int = 0, arch: str = "x86_64"
) -> dict[str, Any]:
    result = {
        **fakehost.UBUNTU,
        "uname -m": [arch],
        **fakehost.system_account(cfg.user, cfg.home, shell="/usr/sbin/nologin"),
        **fakehost.directory(cfg.home, user=cfg.user, mode="drwxr-x---"),
        **fakehost.directory("/mnt/cryptdata/rustfs"),
        **fakehost.directory("/etc/systemd/system"),
        **fakehost.directory(cfg.data_dir, user=cfg.user, mode="drwxr-x---"),
        **fakehost.file(cfg.env_file, render("rustfs.env.j2", cfg, creds), mode="-rw-------"),
        **fakehost.file(cfg.service_unit, render("rustfs.service.j2", cfg)),
        **fakehost.stat(cfg.bin_path, mode="-rwxr-xr-x"),
        **fakehost.service("rustfs.service"),
        f"sha256sum {cfg.bin_path} ": [f"{RUSTFS_ARTIFACTS[arch].binary_sha256}  {cfg.bin_path}"],
        host_command("data_roots"): ["current"],
        host_command("iam_host", "check"): [json.dumps({"pending": pending, "changed": False})],
    }
    return result


def execute(cfg: RustfsConfig, responses: dict[str, Any], creds: RustfsCredentials = CREDS) -> FakeRun:
    return run_deploy_fake(deploy_rustfs, cfg, creds, responses=responses)


@pytest.mark.parametrize("arch", ["x86_64", "aarch64"])
def test_converged_host_has_zero_managed_operations(arch: str) -> None:
    run = execute(IAM_CFG, facts(IAM_CFG, IAM_CREDS, arch=arch), IAM_CREDS)
    assert run.succeeded, run.error
    assert run.mutating_changed_ops == []
    assert run.uploads == []
    assert not any("restart" in command or "daemon-reload" in command for command in run.executed_commands)
    for command in run.executed_commands:
        assert "fixture-root-value" not in command
        assert "app-user-value" not in command


def test_iam_drift_alone_converges_without_restart_or_upload() -> None:
    run = execute(IAM_CFG, facts(IAM_CFG, IAM_CREDS, pending=2), IAM_CREDS)
    assert run.succeeded, run.error
    assert run.mutating_changed_ops == [PREFIX + "Converge declared RustFS buckets and IAM"]
    assert run.uploads == []
    assert not any("restart" in command for command in run.executed_commands)


def test_fresh_install_downloads_verified_artifact_then_defers_iam() -> None:
    response = {
        **fakehost.UBUNTU,
        "uname -m": ["x86_64"],
        host_command("data_roots"): ["empty"],
        # Never probed while planning: only after the started server answers.
        host_command("iam_host", "check"): [json.dumps({"pending": 3, "changed": False})],
    }
    run = execute(IAM_CFG, response, IAM_CREDS)
    names = [name.removeprefix(PREFIX) for name in run.mutating_changed_ops]
    assert "Download pinned RustFS" in names
    assert names.index("Download pinned RustFS") < names.index("Converge declared RustFS buckets and IAM")
    download = next(command for command in run.executed_commands if "rustfs-linux-x86_64-musl-v1.0.4.zip" in command)
    assert RUSTFS_ARTIFACTS["x86_64"].archive_sha256 in download
    assert RUSTFS_ARTIFACTS["x86_64"].binary_sha256 in download


def test_absent_mount_or_foreign_data_stops_before_any_operation() -> None:
    response = facts(RustfsConfig())
    response[host_command("data_roots")] = ["refused: required mount is absent", "ops-deploy-probe-failed"]
    run = execute(RustfsConfig(), response)
    assert run.error is not None
    assert run.ops == []


def test_unknown_iam_answer_refuses_before_writes() -> None:
    response = facts(IAM_CFG, IAM_CREDS)
    response[host_command("iam_host", "check")] = ["refused: client failure", "ops-deploy-probe-failed"]
    run = execute(IAM_CFG, response, IAM_CREDS)
    assert run.error is not None
    # Planning failed: no operation ran.
    assert run.executed_commands == []


def test_unpinned_architecture_is_refused() -> None:
    response = facts(RustfsConfig())
    response["uname -m"] = ["riscv64"]
    run = execute(RustfsConfig(), response)
    assert run.error is not None
    assert run.ops == []


def test_environment_change_restarts_and_defers_iam_to_execution() -> None:
    response = facts(IAM_CFG, IAM_CREDS)
    response.update(fakehost.file(IAM_CFG.env_file, "old", mode="-rw-------"))
    response[host_command("iam_host", "check")] = ["refused: root rejected", "ops-deploy-probe-failed"]
    run = execute(IAM_CFG, response, IAM_CREDS)
    assert PREFIX + "Write RustFS environment" in run.mutating_changed_ops
    assert any("restart" in command for command in run.executed_commands)


def test_stopped_service_is_started_before_deferred_iam_inspection() -> None:
    response = facts(IAM_CFG, IAM_CREDS)
    response.update(fakehost.service("rustfs.service", running=False))
    # The stopped server cannot answer while planning; execution inspects after the start.
    response[host_command("iam_host", "check")] = [json.dumps({"pending": 0, "changed": False})]
    run = execute(IAM_CFG, response, IAM_CREDS)
    assert run.succeeded, run.error
    assert run.mutating_changed_ops == [PREFIX + "Start rustfs.service"]


def test_local_binary_is_staged_and_renamed_over_a_drifted_executable(tmp_path: Path) -> None:
    from ops_deploy.services.rustfs import config as pins
    from ops_deploy.services.rustfs import deploy as module

    local = tmp_path / "rustfs"
    local.write_bytes(b"fixture executable")
    digest = hashlib.sha256(b"fixture executable").hexdigest()
    pinned = pins.RUSTFS_ARTIFACTS["x86_64"]
    replaced = {"x86_64": pins.RustfsArtifact(pinned.archive, pinned.archive_sha256, digest)}
    cfg = RustfsConfig(local_binary=local)
    response = facts(cfg)
    response[f"sha256sum {cfg.bin_path} "] = [f"{'0' * 64}  {cfg.bin_path}"]
    with (
        mock.patch.object(module, "RUSTFS_ARTIFACTS", replaced),
        mock.patch.object(module, "BINARY_SHA256", frozenset({digest})),
    ):
        run = execute(cfg, response)
    assert run.succeeded, run.error
    assert PREFIX + "Stage verified RustFS executable" in run.mutating_changed_ops
    assert f"mv -f {cfg.bin_path}.ops-deploy-new {cfg.bin_path}" in run.executed_commands
    assert any("restart rustfs.service" in command for command in run.executed_commands)


def test_wrong_local_binary_fails_before_operations(tmp_path: Path) -> None:
    local = tmp_path / "rustfs"
    local.write_bytes(b"not the pinned binary")
    with pytest.raises(ValueError, match="pinned binary"):
        execute(RustfsConfig(local_binary=local), facts(RustfsConfig()))


def test_templates_disable_console_alternate_protocols_and_update_checks() -> None:
    env = render("rustfs.env.j2", RustfsConfig(), CREDS)
    for line in (
        'RUSTFS_ADDRESS="127.0.0.1:9020"',
        'RUSTFS_VOLUMES="/mnt/cryptdata/rustfs/data"',
        'RUSTFS_CONSOLE_ENABLE="false"',
        'RUSTFS_FTP_ENABLE="false"',
        'RUSTFS_FTPS_ENABLE="false"',
        'RUSTFS_SFTP_ENABLE="false"',
        'RUSTFS_WEBDAV_ENABLE="false"',
        'RUSTFS_CHECK_UPDATE="false"',
    ):
        assert line in env.splitlines()
    unit = render("rustfs.service.j2", RustfsConfig())
    assert "AssertPathIsMountPoint=/mnt/cryptdata" in unit
    assert "RequiresMountsFor=/mnt/cryptdata/rustfs/data" in unit
    assert "fixture-root" not in unit


def test_traefik_route_is_internal_only_without_compression() -> None:
    cfg = RustfsConfig(expose_via_traefik=True, traefik_api_host="objects.example.test")
    route = render("traefik-rustfs.yml.j2", cfg)
    assert "ClientIP(`192.168.0.0/16`)" in route
    assert "compress:" not in route
    assert "basicAuth" not in route
    assert route.count("rule:") == 2
    assert all("ClientIP" in line for line in route.splitlines() if "rule:" in line)


def test_download_command_verifies_archive_and_member_before_replacing() -> None:
    command = binary_install_command("/usr/local/bin/rustfs", RUSTFS_ARTIFACTS["aarch64"])
    assert command.index("sha256sum") < command.index("zipfile") < command.rindex("sha256sum") < command.index("mv -f")


@pytest.mark.parametrize(
    "fields",
    [
        {"api_port": 9001},
        {"api_port": 9002},
        {"data_dir": "/var/lib/rustfs/data"},
        {"data_dir": "/mnt/cryptdata"},
        {"data_dir": "/mnt/cryptdata/../x"},
        {"identities": (RustfsIdentity(name="x", policies=("missing",), proof="bucket"),)},
        {"buckets": (RustfsBucket(name="dup"), RustfsBucket(name="dup"))},
    ],
)
def test_invalid_configuration_refused(fields: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        RustfsConfig(**fields)


@pytest.mark.parametrize("secret", ["short", "CHANGEME", "has space value"])
def test_weak_or_placeholder_secrets_refused(secret: str) -> None:
    with pytest.raises(ValidationError):
        RustfsUserCredentials(access=SecretStr("user"), secret=SecretStr(secret))


def test_identity_credentials_must_match_declarations_and_differ_from_root() -> None:
    with pytest.raises(ValueError, match="exactly the declared"):
        execute(IAM_CFG, facts(IAM_CFG), CREDS)
    clash = RustfsCredentials(root=ROOT, identities={"app": ROOT})
    with pytest.raises(ValueError, match="distinct"):
        execute(IAM_CFG, facts(IAM_CFG), clash)


def test_pins_are_the_published_release_digests() -> None:
    assert {artifact.archive for artifact in RUSTFS_ARTIFACTS.values()} == {
        "rustfs-linux-x86_64-musl-v1.0.4.zip",
        "rustfs-linux-aarch64-musl-v1.0.4.zip",
    }
    assert all(len(artifact.binary_sha256) == 64 for artifact in RUSTFS_ARTIFACTS.values())


def helper() -> dict[str, Any]:
    namespace: dict[str, Any] = {"__name__": "rustfs_iam_host"}
    source = Path("src/ops_deploy/services/rustfs/files/iam_host.py").read_text()
    exec(compile(source, "iam_host", "exec"), namespace)
    return namespace


def test_policy_comparison_ignores_order_and_single_value_condition_spelling() -> None:
    normalized = helper()["normalized"]
    declared = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "arn:aws:s3:::b",
             "Condition": {"StringLike": {"s3:prefix": ["a/*"]}}},
            {"Effect": "Allow", "Action": ["s3:PutObject", "s3:GetObject"], "Resource": ["arn:aws:s3:::b/a/*"]},
        ],
    }  # fmt: skip
    stored: dict[str, Any] = {
        "Version": "2012-10-17",
        "Statement": [
            {"Action": ["s3:GetObject", "s3:PutObject"], "Effect": "Allow", "Resource": ["arn:aws:s3:::b/a/*"]},
            {"Action": ["s3:ListBucket"], "Condition": {"StringLike": {"s3:prefix": "a/*"}}, "Effect": "Allow",
             "Resource": ["arn:aws:s3:::b"]},
        ],
    }  # fmt: skip
    assert normalized(declared) == normalized(stored)
    stored["Statement"][1]["Condition"]["StringLike"]["s3:prefix"] = "b/*"
    assert normalized(declared) != normalized(stored)


def test_helper_quotes_keys_and_refuses_non_loopback_endpoints() -> None:
    # Signatures are checked end to end against a real server in tests/integration/rustfs.
    namespace = helper()
    assert namespace["quote"]("Arbeit/Quotes Benutzt.md", safe="/-_.~") == "Arbeit/Quotes%20Benutzt.md"
    assert namespace["quote"]("ä") == "%C3%A4"
    with pytest.raises(namespace["Refused"]):
        namespace["Api"]("http://10.0.0.1:9020", "us-east-1")
