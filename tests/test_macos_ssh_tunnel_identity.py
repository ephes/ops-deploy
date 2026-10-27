"""Pure unit coverage; actual OpenSSH/Darwin execution is in the owned fixture."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

from ops_deploy.services.macos_ssh_tunnel.identity import IdentityProbeError, probe_identity


@pytest.fixture
def identity(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path, Mock]:
    home = tmp_path.resolve()
    parent = home / ".ssh"
    parent.mkdir(mode=0o700)
    key = parent / "fixture"
    key.write_bytes(b"synthetic private fixture; OpenSSH mocked in unit tests")
    key.chmod(0o600)
    key.with_suffix(".pub").write_text("ssh-ed25519 YWJj fixture\n")
    key.with_suffix(".pub").chmod(0o644)
    runner = Mock(return_value=subprocess.CompletedProcess([], 0, "ssh-ed25519 YWJj comment\n", ""))
    monkeypatch.setattr(subprocess, "run", runner)
    return home, key, runner


def test_current_identity_uses_pinned_fd_and_no_credential_environment(identity: tuple[Path, Path, Mock]) -> None:
    home, key, runner = identity
    before = {p: (p.stat().st_ino, p.stat().st_mtime_ns, p.stat().st_ctime_ns) for p in key.parent.iterdir()}
    assert probe_identity(str(home), str(key), os.getuid(), "fixture") == {
        "state": "current",
        "public_key": "ssh-ed25519 YWJj",
    }
    argv = runner.call_args.args[0]
    options = runner.call_args.kwargs
    assert argv[-1] == f"/dev/fd/{options['pass_fds'][0]}"
    assert options["stdin"] == subprocess.DEVNULL
    assert not {"HOME", "SSH_AUTH_SOCK", "SSH_ASKPASS"} & options["env"].keys()
    assert {p: (p.stat().st_ino, p.stat().st_mtime_ns, p.stat().st_ctime_ns) for p in key.parent.iterdir()} == before


def test_missing_identity_does_not_generate_or_stage(identity: tuple[Path, Path, Mock]) -> None:
    home, key, runner = identity
    key.unlink()
    key.with_suffix(".pub").unlink()
    assert probe_identity(str(home), str(key), os.getuid(), "fixture") == {"state": "missing"}
    runner.assert_not_called()
    assert list(key.parent.iterdir()) == []


def test_missing_public_requests_reconcile_without_writes(identity: tuple[Path, Path, Mock]) -> None:
    home, key, _ = identity
    key.with_suffix(".pub").unlink()
    assert probe_identity(str(home), str(key), os.getuid(), "fixture")["state"] == "drift"
    assert not key.with_suffix(".pub").exists()


@pytest.mark.parametrize(
    "kind",
    [
        "private_mode",
        "public_mode",
        "hardlink",
        "private_symlink",
        "public_symlink",
        "parent_symlink",
        "parent_mode",
        "orphan",
    ],
)
def test_unsafe_entries_are_preserved(identity: tuple[Path, Path, Mock], kind: str) -> None:
    home, key, _ = identity
    if kind == "private_mode":
        key.chmod(0o644)
    elif kind == "public_mode":
        key.with_suffix(".pub").chmod(0o600)
    elif kind == "hardlink":
        os.link(key, key.parent / "second")
    elif kind == "private_symlink":
        key.rename(key.parent / "original")
        key.symlink_to(key.parent / "original")
    elif kind == "public_symlink":
        key.with_suffix(".pub").rename(key.parent / "original.pub")
        key.with_suffix(".pub").symlink_to(key.parent / "original.pub")
    elif kind == "parent_symlink":
        key.parent.rename(home / "original")
        key.parent.symlink_to(home / "original", target_is_directory=True)
    elif kind == "parent_mode":
        key.parent.chmod(0o750)
    else:
        key.unlink()
    with pytest.raises(IdentityProbeError):
        probe_identity(str(home), str(key), os.getuid(), "fixture")


def test_group_writable_home_is_rejected(identity: tuple[Path, Path, Mock]) -> None:
    home, key, runner = identity
    home.chmod(0o770)
    with pytest.raises(IdentityProbeError, match="home and descendant"):
        probe_identity(str(home), str(key), os.getuid(), "fixture")
    runner.assert_not_called()


def test_writable_intermediate_directory_is_rejected(identity: tuple[Path, Path, Mock]) -> None:
    home, key, runner = identity
    intermediate = home / "intermediate"
    intermediate.mkdir(mode=0o700)
    intermediate.chmod(0o770)
    key.parent.rename(intermediate / ".ssh")
    with pytest.raises(IdentityProbeError, match="home and descendant"):
        probe_identity(str(home), str(intermediate / ".ssh" / key.name), os.getuid(), "fixture")
    runner.assert_not_called()


def test_explicit_safe_parent_mode_repair_is_drift_never_current(identity: tuple[Path, Path, Mock]) -> None:
    home, key, _ = identity
    key.parent.chmod(0o750)
    before = key.stat()
    result = probe_identity(
        str(home), str(key), os.getuid(), "fixture", gid=key.parent.stat().st_gid, allow_parent_mode_drift=True
    )
    assert result == {"state": "drift", "public_key": "ssh-ed25519 YWJj"}
    assert key.parent.stat().st_mode & 0o777 == 0o750
    assert key.stat().st_ino == before.st_ino


@pytest.mark.parametrize("unsafe", ["writable_parent", "wrong_group", "private_mode", "orphan"])
def test_parent_repair_option_does_not_weaken_unsafe_identity_refusal(
    identity: tuple[Path, Path, Mock], unsafe: str
) -> None:
    home, key, _ = identity
    key.parent.chmod(0o750)
    gid = key.parent.stat().st_gid
    if unsafe == "writable_parent":
        key.parent.chmod(0o770)
    elif unsafe == "wrong_group":
        gid += 1
    elif unsafe == "private_mode":
        key.chmod(0o640)
    else:
        key.unlink()
    with pytest.raises(IdentityProbeError):
        probe_identity(str(home), str(key), os.getuid(), "fixture", gid=gid, allow_parent_mode_drift=True)


@pytest.mark.parametrize("component", ["home", "parent"])
def test_foreign_hierarchy_owner_is_rejected(
    identity: tuple[Path, Path, Mock], monkeypatch: pytest.MonkeyPatch, component: str
) -> None:
    home, key, runner = identity
    target = (home if component == "home" else key.parent).stat().st_ino
    original = os.fstat

    def foreign(descriptor: int) -> os.stat_result:
        info = original(descriptor)
        if info.st_ino == target:
            fields = list(info)
            fields[4] = os.getuid() + 1
            return os.stat_result(fields)
        return info

    monkeypatch.setattr(os, "fstat", foreign)
    with pytest.raises(IdentityProbeError, match="home and descendant"):
        probe_identity(str(home), str(key), os.getuid(), "fixture")
    runner.assert_not_called()


def test_private_substitution_during_derivation_is_rejected(identity: tuple[Path, Path, Mock]) -> None:
    home, key, runner = identity

    def replace(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        key.unlink()
        key.write_bytes(b"substitute")
        key.chmod(0o600)
        return subprocess.CompletedProcess([], 0, "ssh-ed25519 YWJj", "")

    runner.side_effect = replace
    with pytest.raises(IdentityProbeError, match="changed during inspection"):
        probe_identity(str(home), str(key), os.getuid(), "fixture")


def test_open_ssh_failure_does_not_disclose_private_error(identity: tuple[Path, Path, Mock]) -> None:
    home, key, runner = identity
    runner.return_value = subprocess.CompletedProcess([], 1, "", "synthetic-private-diagnostic")
    with pytest.raises(IdentityProbeError, match="passphrase-free Ed25519") as error:
        probe_identity(str(home), str(key), os.getuid(), "fixture")
    assert "synthetic-private-diagnostic" not in str(error.value)


def test_pending_creation_intent_defers_to_original_mutation_algorithm(identity: tuple[Path, Path, Mock]) -> None:
    home, key, runner = identity
    (key.parent / ".fixture.creation.json").write_text("{}")
    assert probe_identity(str(home), str(key), os.getuid(), "fixture") == {"state": "drift"}
    runner.assert_not_called()
