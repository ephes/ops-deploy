"""Local safety/receipt checks; these do not qualify the native application."""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml
from pydantic import SecretStr
from pyinfra.connectors.local import LocalConnector

from tests.integration.paperless import application_matrix, evidence, harness


def test_native_guard_refuses_local_execution_before_any_command(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)

    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("host command must not run outside the owned guest")

    monkeypatch.setattr(harness, "command", forbidden)
    with pytest.raises(AssertionError):
        harness.main()
    assert not harness.OWNED_ADMITTED


def test_bash_runner_refuses_local_environment_before_docker() -> None:
    path = Path(__file__).parent / "integration/paperless/run-owned.sh"
    result = subprocess.run(
        ["bash", str(path)], env={"PATH": os.environ["PATH"]}, capture_output=True, text=True, check=False, timeout=10
    )
    assert result.returncode != 0
    assert not result.stdout
    assert not result.stderr


def test_complete_snapshot_keeps_private_bytes_and_digests_out(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(harness, "EVIDENCE", tmp_path)
    private = b"owned-secret-must-stay-in-memory"
    snapshot = harness.Snapshot({"file": {"inode": 123, "mtime_ns": 456}}, {"/synthetic/env": private})
    receipt = harness.snapshot_receipt("phase", "before", snapshot)
    raw = gzip.decompress((tmp_path / receipt["file"]).read_bytes())
    assert json.loads(raw) == snapshot.public
    assert private not in raw
    assert hashlib.sha256(private).hexdigest().encode() not in raw
    assert receipt == harness.snapshot_receipt("phase", "before", snapshot)


def test_log_bound_counts_utf8_bytes_and_refuses_before_extra_write(tmp_path: Path) -> None:
    path = tmp_path / "raw-private.log"
    with path.open("w") as stream, harness.BoundedLog(stream, limit=5) as log:
        assert log.write("ä") == 1
        assert log.write("abc") == 3
        with pytest.raises(RuntimeError, match="exceeds bound"):
            log.write("d")
    assert path.read_text() == "äabc"


def test_split_synthetic_log_value_is_redacted_after_complete_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret = "owned-only-value"
    monkeypatch.setattr(harness, "VALUES", [secret])
    path = tmp_path / "raw-private.log"
    with path.open("w") as stream, harness.BoundedLog(stream) as log:
        log.write(secret[:5])
        log.write(secret[5:])
    assert harness.sanitize(path.read_text()) == "<synthetic-redacted>"


def test_actual_fixture_refusal_records_bounded_log_without_host_commands(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(harness, "ROOT", tmp_path)
    monkeypatch.setattr(harness, "EVIDENCE", tmp_path)
    monkeypatch.setattr(harness, "PHASES", [])
    monkeypatch.setattr(harness, "snapshot", lambda cfg: harness.Snapshot({"owned": True}, {}))

    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("credential mismatch must refuse before any connector command")

    monkeypatch.setattr(LocalConnector, "run_shell_command", forbidden)
    result = harness.deploy("owned-refusal", failure=True, shared_redis_password=SecretStr("wrong-owned-value"))
    assert result["operations"] == []
    assert result["uploads"] == 0
    assert "shared Redis credentials differ" in result["error"]
    assert (tmp_path / "owned-refusal.log").exists()
    assert not (tmp_path / "private-current-cli.log").exists()
    started = json.loads((tmp_path / "owned-refusal-started.json").read_text())
    final = json.loads((tmp_path / started["completion_receipt"]).read_text())
    assert final["before"] == started["before"]
    assert final["after"]["file"] == "owned-refusal-after.json.gz"


def test_evidence_collector_hashes_actual_files_and_refuses_foreign_link(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    root.mkdir()
    (root / "phase.json").write_bytes(b"{}")
    assert evidence.manifest(root) == {
        "files": {"phase.json": {"size": 2, "sha256": hashlib.sha256(b"{}").hexdigest()}},
        "total_size": 2,
    }
    foreign = tmp_path / "foreign"
    foreign.write_text("do not copy")
    (root / "linked.log").symlink_to(foreign)
    with pytest.raises(ValueError, match="unexpected path type"):
        evidence.manifest(root)


def test_evidence_collector_refuses_oversized_sparse_file_without_reading_it(tmp_path: Path) -> None:
    with (tmp_path / "large.log").open("wb") as stream:
        stream.truncate(40 * 1024 * 1024 + 1)
    with pytest.raises(ValueError, match="file exceeds limit"):
        evidence.manifest(tmp_path)


def test_interrupted_phase_preserves_durable_before_without_claiming_after(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(harness, "ROOT", tmp_path)
    monkeypatch.setattr(harness, "EVIDENCE", tmp_path)
    monkeypatch.setattr(harness, "snapshot", lambda cfg: harness.Snapshot({"owned": True}, {}))

    def interrupt(*args: object, **kwargs: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(harness, "add_deploy", interrupt)
    with pytest.raises(KeyboardInterrupt):
        harness.deploy("owned-interrupted")
    receipt = json.loads((tmp_path / "owned-interrupted-started.json").read_text())
    assert receipt["completion_receipt"] == "owned-interrupted.json"
    assert not (tmp_path / receipt["completion_receipt"]).exists()
    assert json.loads(gzip.decompress((tmp_path / receipt["before"]["file"]).read_bytes())) == {"owned": True}
    assert not (tmp_path / "owned-interrupted-after.json.gz").exists()
    assert not (tmp_path / "owned-interrupted.json").exists()


@pytest.mark.parametrize("boundary", ["snapshot", "playbook_write"])
def test_ansible_early_failure_never_leaves_secret_playbook(
    boundary: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(harness, "ROOT", tmp_path)
    monkeypatch.setattr(harness, "EVIDENCE", tmp_path)

    def fail(*args: object, **kwargs: object) -> None:
        raise RuntimeError("owned injected failure")

    monkeypatch.setattr(
        harness, "snapshot", fail if boundary == "snapshot" else lambda: harness.Snapshot({"owned": True}, {})
    )
    monkeypatch.setattr(yaml, "safe_dump", fail)
    with pytest.raises(RuntimeError, match="owned injected failure"):
        harness.ansible("owned-failed-ansible")
    assert not (tmp_path / "owned-ansible.yml").exists()
    assert not (tmp_path / "owned-failed-ansible.json").exists()


@pytest.mark.parametrize("owned_image_present", [True, False])
def test_runner_image_receipt_does_not_require_cached_base_tag(tmp_path: Path, owned_image_present: bool) -> None:
    """Execute the real receipt command with a Docker inventory lacking a base tag."""
    source = (Path(__file__).parent / "integration/paperless/run-owned.sh").read_text()
    commands = [line for line in source.splitlines() if line.startswith("docker image inspect ")]
    assert len(commands) == 1
    docker = tmp_path / "docker"
    docker.write_text(
        "#!/bin/sh\n"
        'printf "%s\\n" "$@" > "$CALLS"\n'
        'test "$OWNED_PRESENT" = true || exit 1\n'
        'test "$#" = 3 && test "$1" = image && test "$2" = inspect && test "$3" = "$IMAGE" || exit 1\n'
        'printf \'[{"Id":"sha256:owned-image"}]\\n\'\n'
    )
    docker.chmod(0o700)
    result = subprocess.run(
        ["bash", "-euc", commands[0]],
        env={
            "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"],
            "IMAGE": "ops-owned-paperless:synthetic",
            "EVIDENCE": str(tmp_path),
            "CALLS": str(tmp_path / "calls"),
            "OWNED_PRESENT": str(owned_image_present).lower(),
        },
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert (result.returncode == 0) is owned_image_present
    if owned_image_present:
        assert json.loads((tmp_path / "images.json").read_text()) == [{"Id": "sha256:owned-image"}]
    else:
        assert not (tmp_path / "images.json").read_text()


@pytest.mark.parametrize("fixed_writes", [False, True])
def test_migration_root_control_detects_fixed_command_writes(
    tmp_path: Path,
    fixed_writes: bool,
) -> None:
    cfg = harness.CFG.model_copy(
        update={"external_storage_root": str(tmp_path / "roots"), "sftp_chroot_dir": str(tmp_path / "scanner")}
    )
    paths = [Path(cfg.external_storage_root) / name for name in ("data", "media", "consume")]
    paths.append(Path(cfg.sftp_chroot_dir) / "inbox")
    for path in paths:
        path.mkdir(parents=True)
    receipts: list[Any] = []

    def owned_command(*args: str, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        if "--skip-checks" not in args[-1] or fixed_writes:
            for path in paths:
                marker = path / "owned-write-test"
                marker.write_text("")
                marker.unlink()
        return subprocess.CompletedProcess(args, 0, "", "")

    fixture = SimpleNamespace(
        CFG=cfg,
        OWNED_ADMITTED=True,
        command=owned_command,
        public_metadata=harness.public_metadata,
        write=lambda name, data: receipts.append(json.loads(json.dumps(data))),
    )
    if fixed_writes:
        with pytest.raises(AssertionError, match="fixed migration status changed"):
            application_matrix.migration_status_roots(fixture)
    else:
        application_matrix.migration_status_roots(fixture)
    assert len(receipts) == 2
    assert receipts[-1][0]["classification"] == "intentional-old-write-test-control"
    assert receipts[-1][1]["skip_checks"] is True
