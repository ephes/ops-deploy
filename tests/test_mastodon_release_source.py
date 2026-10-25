"""Real local Git transport and release-input safety, without host mutation."""

from __future__ import annotations

import hashlib
import importlib.util
import subprocess
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.services.mastodon.release_config import MastodonReleaseConfig
from tests.test_mastodon import config

HOST = Path(__file__).parents[1] / "src/ops_deploy/services/mastodon/files/release_host.py"


def release_config(**changes: Any) -> MastodonReleaseConfig:
    return MastodonReleaseConfig(
        **{
            **config().model_dump(),
            "git_ref": "v4.6.9",
            "source_tracked_paths": [".nvmrc", ".ruby-version", "Gemfile.lock", "package.json", "yarn.lock"],
            "migration_versions": ["20260101000000"],
            "runtime_tool_commits": {"ruby_build": "b" * 40},
            **changes,
        }
    )


@pytest.mark.parametrize(
    "path",
    [
        ".env.production",
        "public/system/avatar",
        "public",
        "vendor/bundle/gems/x",
        "../escape",
        "/absolute",
        ".git/config",
    ],
)
def test_candidate_protected_collision_is_rejected_before_actions(path: str) -> None:
    with pytest.raises(ValidationError):
        release_config(source_tracked_paths=[path])


@pytest.mark.parametrize(
    "command",
    [
        "em pur",
        "emoji purge",
        "emoji purge --remote-only false",
        "emoji purge --remote-only --unknown",
        "media remove; touch /tmp/x",
    ],
)
def test_maintenance_preserves_role_local_emoji_and_shell_validation(command: str) -> None:
    with pytest.raises(ValidationError):
        release_config(maintenance_extra_commands=[command])


def test_maintenance_uses_actual_role_defaults_and_never_runs_cleanup() -> None:
    cfg = release_config(
        maintenance_extra_commands=["emoji purge --remote-only", "media remove --prune-profiles --days 30"]
    )
    assert cfg.bundle_jobs == 4
    assert cfg.ruby_configure_opts == "-with-jemalloc"
    assert cfg.maintenance_run_now is False
    assert cfg.maintenance_tootctl_commands is None
    assert cfg.maintenance_media_days == 4
    with pytest.raises(ValidationError):
        release_config(maintenance_run_now=True)
    with pytest.raises(ValidationError):
        release_config(runtime_tool_commits={})
    assert release_config(ruby_build_update=False, runtime_tool_commits={}).runtime_tool_commits == {}


def git(path: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(path), *args], text=True).strip()


def host_module(tmp_path: Path) -> Any:
    spec = importlib.util.spec_from_file_location("mastodon_release_host", HOST)
    assert spec is not None
    assert spec.loader is not None
    module: Any = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.STATE = tmp_path / "state"

    def local_user(cfg: Any, argv: list[str], **kwargs: Any) -> Any:
        assert not kwargs.get("shell")
        return module.command(argv, optional=kwargs.get("optional", False))

    module.user = local_user
    return module


def test_git_force_detach_preserves_retained_files_and_retries_debt(tmp_path: Path) -> None:
    origin = tmp_path / "origin"
    origin.mkdir()
    subprocess.run(["git", "init", "-q", str(origin)], check=True)
    git(origin, "config", "user.email", "fixture@example.org")
    git(origin, "config", "user.name", "Fixture")
    for name in config().source_files:
        (origin / name).write_text("old\n")
    for name in ("log/.keep", "vendor/.keep"):
        (origin / name).parent.mkdir(exist_ok=True)
        (origin / name).touch()
    (origin / "lib").mkdir()
    (origin / "lib/café.rb").write_text("# Unicode source path\n")
    (origin / 'lib/a"b.rb').write_text("# quoted source path\n")
    git(origin, "add", ".")
    git(origin, "commit", "-qm", "old")
    site = tmp_path / "live"
    subprocess.run(["git", "clone", "-q", str(origin), str(site)], check=True)
    retained = [
        ".env.production",
        "public/system/opaque",
        "vendor/bundle/installed",
        "node_modules/installed",
        ".bundle/config",
        "log/retained",
        "tmp/retained",
    ]
    for name in retained:
        path = site / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"opaque retained data")
    (origin / "Gemfile.lock").write_text("new\n")
    git(origin, "add", ".")
    git(origin, "commit", "-qm", "new")
    commit = git(origin, "rev-parse", "HEAD")
    cfg = {
        "site_path": str(site),
        "git_repo": str(origin),
        "git_ref": git(origin, "symbolic-ref", "--short", "HEAD"),
        "source_commit": commit,
        "source_tracked_paths": git(origin, "ls-tree", "-r", "--name-only", "-z", "HEAD").split("\x00")[:-1],
        "source_files": {n: hashlib.sha256((origin / n).read_bytes()).hexdigest() for n in config().source_files},
    }
    module = host_module(tmp_path)
    assert module.source_state(cfg)
    module.source(cfg)
    assert not module.source_state(cfg)
    assert all((site / name).read_bytes() == b"opaque retained data" for name in retained)
    assert module.state_read("pending-rollout") is True
    assert module.state_read("pending-cache-clear") is True
    # A tracked dirty/index change is repaired even on the selected commit.
    (site / "Gemfile.lock").write_text("dirty\n")
    git(site, "add", "Gemfile.lock")
    module.source(cfg)
    assert git(site, "rev-parse", "HEAD") == commit
    assert not module.source_state(cfg)
    # A moving ref fails before checkout, and durable debt remains for retry.
    (origin / "Gemfile.lock").write_text("later\n")
    git(origin, "add", ".")
    git(origin, "commit", "-qm", "later")
    with pytest.raises(ValueError, match="moved"):
        module.source(cfg)
    assert git(site, "rev-parse", "HEAD") == commit
    assert module.state_read("pending-rollout") is True
    assert all((site / name).read_bytes() == b"opaque retained data" for name in retained)


def test_current_propshaft_vite_build_rejects_stale_legacy_manifests(tmp_path: Path) -> None:
    import json

    module = host_module(tmp_path)
    site = tmp_path / "live"
    assets = site / "public/assets"
    packs = site / "public/packs"
    assets.mkdir(parents=True)
    (packs / ".vite").mkdir(parents=True)
    (site / "config").mkdir()
    (site / "Gemfile.lock").write_text("    propshaft (1.3.2)\n")
    (site / "config/vite.json").write_text(json.dumps({"production": {"publicOutputDir": "packs"}}))
    # Retained files from an old build cannot qualify the selected pipeline.
    (assets / ".sprockets-manifest-old.json").write_text('{"assets":{}}')
    (packs / "manifest.json").write_text('{"old":"/packs/old.js"}')
    cfg = {"site_path": str(site)}
    assert module.assets_output(cfg) is False
    (assets / ".manifest.json").write_text('{"app.css":{"digested_path":"app-hash.css","integrity":"fixture-SRI"}}')
    (packs / ".vite/manifest.json").write_text('{"entry":{"file":"assets/app.js","css":["assets/app.css"]}}')
    assert module.assets_output(cfg) is False
    (assets / "app-hash.css").write_text("body {}")
    (packs / "assets").mkdir()
    (packs / "assets/app.js").write_text("console.log('fixture')")
    assert module.assets_output(cfg) is False
    (packs / "assets/app.css").write_text("body {}")
    assert module.assets_output(cfg) is True
    (packs / "assets/app.js").unlink()
    assert module.assets_output(cfg) is False


@pytest.mark.skipif(not __import__("os").environ.get("OPS_LIBRARY_PATH"), reason="fresh role checkout not configured")
def test_new_release_defaults_match_the_actual_roles() -> None:
    import os

    import yaml

    root = Path(os.environ["OPS_LIBRARY_PATH"]) / "roles"
    expected = {}
    for role in ("mastodon_shared", "mastodon_deploy", "mastodon_maintenance"):
        expected.update(yaml.safe_load((root / role / "defaults/main.yml").read_text()))
    cfg = release_config()
    for name, field in type(cfg).model_fields.items():
        key = "mastodon_" + name
        if field.is_required() or name in {"git_repo", "maintenance_tootctl_commands"} or key not in expected:
            continue
        if "{{" in repr(expected[key]):
            continue
        assert getattr(cfg, name) == expected[key], name


@pytest.mark.parametrize(
    "settings",
    [
        {"all": {"publicOutputDir": "packs"}},
        {"all": {"publicOutputDir": "other"}, "production": {"publicOutputDir": "packs"}},
    ],
)
def test_vite_output_configuration_merges_all_then_production(tmp_path: Path, settings: dict[str, Any]) -> None:
    import json

    module = host_module(tmp_path)
    site = tmp_path / "live"
    (site / "config").mkdir(parents=True)
    (site / "Gemfile.lock").write_text("    propshaft (1.3.2)\n")
    assets = site / "public/assets"
    assets.mkdir(parents=True)
    (assets / ".manifest.json").write_text("{}")
    packs = site / "public/packs"
    (packs / ".vite").mkdir(parents=True)
    (packs / "entry.js").write_text("console.log('actual output')")
    (packs / ".vite/manifest.json").write_text('{"entry":{"file":"entry.js"}}')
    (site / "config/vite.json").write_text(json.dumps(settings))
    assert module.assets_output({"site_path": str(site)}) is True


@pytest.mark.parametrize(
    ("entry", "expected"),
    [("app-hash.css", True), ({"integrity": "missing-digested-path"}, False)],
)
def test_propshaft_legacy_string_and_malformed_object_entries(tmp_path: Path, entry: Any, expected: bool) -> None:
    import json

    module = host_module(tmp_path)
    site = tmp_path / "live"
    assets = site / "public/assets"
    assets.mkdir(parents=True)
    (site / "Gemfile.lock").write_text("    propshaft (1.3.2)\n")
    (assets / "app-hash.css").write_text("body {}")
    (assets / ".manifest.json").write_text(json.dumps({"app.css": entry}))
    assert module.assets_output({"site_path": str(site)}) is expected
