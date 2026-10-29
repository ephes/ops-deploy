"""Real owned Git ref conversion and cleanup; no app import or upstream fetch."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from ops_deploy.services.daybook_photos_offload.controller_source import PhotosBundleError, photos_main_bundle


def git(root: Path, *args: str) -> str:
    return subprocess.check_output(
        ["/usr/bin/git", "-C", str(root), *args], text=True, stderr=subprocess.DEVNULL
    ).strip()


@pytest.fixture
def source(tmp_path: Path) -> tuple[Path, str, Path]:
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "--quiet", "--template=", "-b", "main")
    (repo / "code.py").write_text("# owned code, never imported\n")
    git(repo, "add", ".")
    git(repo, "-c", "user.name=Owned", "-c", "user.email=owned@example.test", "commit", "-qm", "owned")
    revision = git(repo, "rev-parse", "HEAD")
    git(repo, "update-ref", "refs/remotes/origin/main", revision)
    bundle = tmp_path / "source.bundle"
    git(repo, "bundle", "create", str(bundle), "refs/remotes/origin/main")
    cache = tmp_path / "run"
    cache.mkdir(mode=0o700)
    return bundle, revision, cache


def test_exact_original_photos_clone_and_fetch_contract_with_lifetime(source: tuple[Path, str, Path]) -> None:
    bundle, revision, cache = source
    original = bundle.read_bytes()
    with photos_main_bundle(bundle, revision, cache) as derived:
        assert derived.is_file()
        target = cache / "target"
        git(cache, "clone", "--quiet", "--no-checkout", "--branch", "main", str(derived), str(target))
        git(target, "fetch", "--quiet", "--no-tags", "--force", "origin", "refs/heads/main")
        git(target, "checkout", "--quiet", "--detach", revision)
        assert git(target, "rev-parse", "HEAD") == revision
        assert git(target, "status", "--porcelain") == ""
        assert bundle.read_bytes() == original
    assert not derived.exists()
    assert bundle.read_bytes() == original


def test_wrong_revision_refuses_before_derived_publication(source: tuple[Path, str, Path]) -> None:
    bundle, _, cache = source
    with pytest.raises(PhotosBundleError, match="source_ref_mismatch"), photos_main_bundle(bundle, "f" * 40, cache):
        pytest.fail("wrong source accepted")
    assert not list(cache.iterdir())


def test_exception_cleans_only_owned_derivation(source: tuple[Path, str, Path]) -> None:
    bundle, revision, cache = source
    original = bundle.read_bytes()
    with pytest.raises(RuntimeError, match="owned injected"), photos_main_bundle(bundle, revision, cache) as derived:
        raise RuntimeError("owned injected")
    assert not derived.exists()
    assert bundle.read_bytes() == original
    assert not list(cache.iterdir())


def test_nonprivate_cache_refused(source: tuple[Path, str, Path]) -> None:
    bundle, revision, cache = source
    cache.chmod(0o755)
    with pytest.raises(PhotosBundleError, match="private_run_directory"), photos_main_bundle(bundle, revision, cache):
        pytest.fail("nonprivate cache accepted")
