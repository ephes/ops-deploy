"""Owned small artifacts: no-read continuity, changed pin and rollback."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
from importlib.resources import files
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from ops_deploy.services.voxhelm.artifacts import ArtifactContinuity


def host_module(service: str) -> ModuleType:
    resource = files("ops_deploy.services." + service).joinpath("files/" + service + "_host.py")
    spec = importlib.util.spec_from_file_location("owned_" + service, str(resource))
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("service", ["voxhelm", "voxhelm_remote_worker"])
def test_initial_pin_is_metadata_continuity_and_never_reads_model(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, service: str
) -> None:
    module = host_module(service)
    model = tmp_path / "model.bin"
    model.write_bytes(b"owned synthetic artifact")
    pin = hashlib.sha256(b"owned synthetic artifact").hexdigest()
    continuity = {"pin": pin, "metadata": module.artifact_metadata(model)}
    ArtifactContinuity.model_validate(continuity)
    cfg = {"config_dir": str(tmp_path), "service_group": "staff", "preserved_artifacts": {str(model): continuity}}
    original = Path.open

    def no_model_body(self: Path, *args: Any, **kwargs: Any) -> Any:
        assert self != model, "a continuity probe read the model body"
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", no_model_body)
    before = model.stat()
    assert module.model_pin(cfg, model) == pin
    assert module.model_pin(cfg, model) == pin
    after = model.stat()
    assert (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) == (
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    assert not (tmp_path / ".native-artifacts.json").exists()
    model.chmod(0o600 if before.st_mode & 0o777 != 0o600 else 0o640)
    assert module.model_pin(cfg, model) is None


@pytest.mark.parametrize("service", ["voxhelm", "voxhelm_remote_worker"])
def test_link_continuity_includes_exact_referent_metadata(tmp_path: Path, service: str) -> None:
    module = host_module(service)
    source = tmp_path / "owned-source.bin"
    source.write_bytes(b"owned model source")
    model = tmp_path / "model.bin"
    model.symlink_to(source)
    continuity = {"pin": "a" * 64, "metadata": module.artifact_metadata(model)}
    ArtifactContinuity.model_validate(continuity)
    cfg = {"config_dir": str(tmp_path), "service_group": "staff", "preserved_artifacts": {str(model): continuity}}
    assert module.model_pin(cfg, model) == "a" * 64
    source.write_bytes(b"different owned source")
    assert module.model_pin(cfg, model) is None


@pytest.mark.parametrize("service", ["voxhelm", "voxhelm_remote_worker"])
def test_changed_native_provenance_outranks_stale_initial_pin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, service: str
) -> None:
    module = host_module(service)
    model = tmp_path / "model.bin"
    model.write_bytes(b"first owned artifact")
    old = {"pin": "a" * 64, "metadata": module.artifact_metadata(model)}
    cfg = {"config_dir": str(tmp_path), "service_group": "staff", "preserved_artifacts": {str(model): old}}
    model.write_bytes(b"second owned artifact")
    native = {"pin": "b" * 64, "metadata": module.artifact_metadata(model)}
    (tmp_path / ".native-artifacts.json").write_text(json.dumps({str(model): native}))
    monkeypatch.setattr(module, "metadata", lambda *args, **kwargs: True)
    assert module.model_pin(cfg, model) == "b" * 64
    # Even if the old metadata description is replaced to match today's file,
    # the existing native path record prevents adopting the old wanted pin.
    old["metadata"] = module.artifact_metadata(model)
    assert module.model_pin(cfg, model) != "a" * 64
    model.write_bytes(b"third unexpected artifact")
    assert module.model_pin(cfg, model) is None


def test_control_actual_changed_pin_then_rollback_downloads_both_verified_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = host_module("voxhelm")
    first, second = b"first owned public fixture artifact", b"second owned public fixture artifact"
    old_pin, new_pin = hashlib.sha256(first).hexdigest(), hashlib.sha256(second).hexdigest()
    model = tmp_path / "model.bin"
    model.write_bytes(first)
    cfg = {
        "config_dir": str(tmp_path),
        "preserved_artifacts": {
            str(model): {"pin": old_pin, "metadata": module.artifact_metadata(model)},
        },
    }
    calls = []

    def download(url: str, **kwargs: Any) -> io.BytesIO:
        calls.append(url)
        return io.BytesIO(second if url.endswith("new") else first)

    def put(path: str, resource: dict[str, Any]) -> None:
        Path(path).write_text(resource["content"])

    monkeypatch.setattr(module.urllib.request, "urlopen", download)
    monkeypatch.setattr(module.os, "fchown", lambda *args: None)
    # Linux CI has no Darwin "wheel" group; ownership is not under test here.
    monkeypatch.setattr(module.grp, "getgrnam", lambda name: SimpleNamespace(gr_gid=0))
    monkeypatch.setattr(module, "put", put)
    monkeypatch.setattr(module, "metadata", lambda *args, **kwargs: True)
    assert module.model_pin(cfg, model) == old_pin
    module.download(cfg, model, "https://example.test/new", new_pin)
    assert module.model_pin(cfg, model) == new_pin
    module.download(cfg, model, "https://example.test/old", old_pin)
    assert module.model_pin(cfg, model) == old_pin
    assert model.read_bytes() == first
    assert calls == ["https://example.test/new", "https://example.test/old"]
    assert {p.name for p in tmp_path.iterdir()} == {"model.bin", ".native-artifacts.json"}


def test_failed_new_artifact_retains_old_model_and_provenance(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = host_module("voxhelm")
    model = tmp_path / "model.bin"
    model.write_bytes(b"existing owned model")
    cfg = {"config_dir": str(tmp_path)}
    monkeypatch.setattr(module.urllib.request, "urlopen", lambda *args, **kwargs: io.BytesIO(b"invalid new artifact"))
    monkeypatch.setattr(module.os, "fchown", lambda *args: None)
    # Linux CI has no Darwin "wheel" group; ownership is not under test here.
    monkeypatch.setattr(module.grp, "getgrnam", lambda name: SimpleNamespace(gr_gid=0))
    with pytest.raises(RuntimeError, match="checksum differs"):
        module.download(cfg, model, "https://example.test/new", "0" * 64)
    assert model.read_bytes() == b"existing owned model"
    assert {p.name for p in tmp_path.iterdir()} == {"model.bin"}


@pytest.mark.parametrize("service", ["opsgate", "voxhelm", "voxhelm_remote_worker", "llama_server"])
def test_declared_owner_commands_keep_public_home_flags_after_sudo(
    monkeypatch: pytest.MonkeyPatch, service: str
) -> None:
    module = host_module(service)
    account = SimpleNamespace(pw_uid=501, pw_name="fixture-owner", pw_dir="/Users/fixture-owner")
    monkeypatch.setattr(module.os, "geteuid", lambda: 0)
    monkeypatch.setattr(module.pwd, "getpwnam", lambda user: account)
    commands = []

    def capture(argv: list[str], **kwargs: Any) -> Any:
        commands.append((argv, kwargs))
        return type("Completed", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    monkeypatch.setattr(module.subprocess, "run", capture)
    if service in {"voxhelm", "voxhelm_remote_worker"}:
        module.run(["/usr/bin/true"], {"launchd_path": "/usr/bin:/bin"}, user=account.pw_name)
    else:
        module.run(["/usr/bin/true"], user=account.pw_name)
    argv, kwargs = commands[0]
    assert argv[:6] == ["/usr/bin/sudo", "-H", "-u", account.pw_name, "--", "/usr/bin/env"]
    assert "HOME=" + account.pw_dir in argv
    assert "PATH=" + kwargs["env"]["PATH"] in argv
    assert argv[-1] == "/usr/bin/true"


def completed(returncode: int) -> Any:
    return SimpleNamespace(returncode=returncode, stdout="", stderr="")


@pytest.mark.parametrize("service", ["voxhelm", "voxhelm_remote_worker", "llama_server"])
def test_homebrew_presence_uses_the_role_per_formula_check(monkeypatch: pytest.MonkeyPatch, service: str) -> None:
    # Current Homebrew rejects `list --full-name --versions`; the role's own
    # `list --versions <formula>` also resolves renamed formulae.
    module = host_module(service)
    installed = {"whisper-cpp", "llama.cpp"}
    calls: list[list[str]] = []

    def run(argv: list[str], *args: Any, check: bool = True, **kwargs: Any) -> Any:
        if argv[1:] == ["tap"]:
            return SimpleNamespace(returncode=0, stdout="homebrew/cask\nowned/tapped\n", stderr="")
        calls.append(argv)
        assert not check
        assert "--full-name" not in argv
        return completed(0 if argv[-1] in installed else 1)

    monkeypatch.setattr(module, "run", run)
    if service == "llama_server":
        assert module.installed({"brew": "/opt/homebrew/bin/brew", "brew_formula": "llama.cpp"})
        assert not module.installed({"brew": "/opt/homebrew/bin/brew", "brew_formula": "absent"})
        listed = len(calls)
        assert not module.installed({"brew": "/opt/homebrew/bin/brew", "brew_formula": "other/untapped/llama.cpp"})
        assert len(calls) == listed, "an untapped repository's formula is never resolved"
        installed.add("owned/tapped/llama.cpp")
        assert module.installed({"brew": "/opt/homebrew/bin/brew", "brew_formula": "owned/tapped/llama.cpp"})
    else:
        owner = "brew_owner" if service == "voxhelm" else "brew_user"
        cfg = {"brew": "/opt/homebrew/bin/brew", owner: "fixture", "packages": ["whisper-cpp"], "brew_update": False}
        assert module.packages(cfg)
        assert not module.packages({**cfg, "packages": ["whisper-cpp", "espeak-ng"]})
    assert all(argv[:4] == ["/opt/homebrew/bin/brew", "list", "--formula", "--versions"] for argv in calls)


def worker_apply_harness(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, plist_changed: bool, fail_model: bool
) -> tuple[ModuleType, dict[str, Any], list[str]]:
    module = host_module("voxhelm_remote_worker")
    events: list[str] = []
    plist = str(tmp_path / "worker.plist")
    cfg: dict[str, Any] = {
        "config_dir": str(tmp_path),
        "launchd_plist_path": plist,
        "launchd_label": "com.example.worker",
        "launchd_manage_state": True,
        "launchd_start_service": True,
        "contents": {plist: {}, str(tmp_path / "worker.env"): {}},
    }
    published: set[str] = set()

    def step(name: str) -> Any:
        def converge(c: dict[str, Any], apply: bool = False) -> bool:
            if apply:
                events.append(name)
            return True

        return converge

    for name in ["directories", "packages", "runtime", "whisper_link", "parakeet"]:
        monkeypatch.setattr(module, name, step(name))

    def window_model(c: dict[str, Any], apply: bool = False) -> bool:
        if not apply:
            return False
        events.append("window_model")
        if fail_model:
            raise RuntimeError("window model checksum differs; current cache retained")
        return True

    monkeypatch.setattr(module, "window_model", window_model)
    monkeypatch.setattr(
        module, "resource_current", lambda path, resource: path in published or (path == plist and not plist_changed)
    )
    monkeypatch.setattr(module, "metadata", lambda *args, **kwargs: True)

    def put(path: str, resource: dict[str, Any]) -> None:
        if path.endswith(".ops-deploy-restart"):
            Path(path).write_text(resource["content"])
            events.append("intent")
        else:
            published.add(path)
            events.append("publish")

    monkeypatch.setattr(module, "put", put)
    monkeypatch.setattr(module, "job", lambda c: (True, True))

    def run(argv: list[str], c: dict[str, Any], **kwargs: Any) -> Any:
        events.append(" ".join(argv[1:3]))
        return completed(0)

    monkeypatch.setattr(module, "run", run)
    return module, cfg, events


def test_worker_failed_model_change_keeps_running_service_and_owes_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module, cfg, events = worker_apply_harness(tmp_path, monkeypatch, plist_changed=False, fail_model=True)
    with pytest.raises(RuntimeError, match="checksum differs"):
        module.apply(cfg)
    assert not any(event.startswith(("bootout", "kickstart", "bootstrap")) for event in events)
    assert json.loads((tmp_path / ".ops-deploy-restart").read_text()) == {"reload": False}
    assert module.restart_intent(cfg) == {"reload": False}
    module, cfg, events = worker_apply_harness(tmp_path, monkeypatch, plist_changed=False, fail_model=False)
    module.apply(cfg)
    assert events.index("publish") < events.index("kickstart -k")
    assert "bootout system/com.example.worker" not in events
    assert not (tmp_path / ".ops-deploy-restart").exists()


def test_worker_changed_plist_reloads_after_publication(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module, cfg, events = worker_apply_harness(tmp_path, monkeypatch, plist_changed=True, fail_model=False)
    module.apply(cfg)
    order = [event for event in events if event in {"intent", "publish", "bootout system/com.example.worker"}]
    assert order[0] == "intent"
    assert order[-1] == "bootout system/com.example.worker"
    assert events[-3:] == ["bootstrap system", "enable system/com.example.worker", "kickstart -k"]
    assert not (tmp_path / ".ops-deploy-restart").exists()


def test_control_runtime_sync_keeps_running_units_loaded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The role syncs/recreates the venv while units run and restarts afterwards;
    # stopping first would leave every unit down when the sync fails.
    module = host_module("voxhelm")
    commands: list[list[str]] = []
    marked: list[bool] = []
    monkeypatch.setattr(module, "mark", lambda c: marked.append(True))

    def run(argv: list[str], c: dict[str, Any], **kwargs: Any) -> Any:
        commands.append(argv)
        return SimpleNamespace(returncode=0, stdout="/owned/python\n", stderr="")

    monkeypatch.setattr(module, "run", run)
    cfg = {
        "app_dir": str(tmp_path),
        "uv_bin": "/owned/uv",
        "python_version": "3.14.8",
        "launchd_manage_state": True,
        "uv_extras": [],
        "diarization_backend": "none",
        "tts_kokoro_enabled": False,
        "tts_language_routing_enabled": False,
        "units": [{"label": "com.example.api", "periodic": False, "start": True}],
    }
    module.runtime_apply(cfg)
    assert marked == [True]
    assert not any("/bin/launchctl" in argv for argv in commands)
    assert commands[-1][:4] == ["/owned/uv", "sync", "--frozen", "--no-dev"]


def test_worker_directories_give_created_ancestors_the_requested_owner_and_mode(tmp_path: Path) -> None:
    import grp
    import os
    import pwd

    module = host_module("voxhelm_remote_worker")
    owner = pwd.getpwuid(os.getuid()).pw_name
    group = grp.getgrgid(os.getgid()).gr_name
    existing = tmp_path / "home"
    existing.mkdir(mode=0o700)
    target = existing / "Caches" / "voxhelm" / "models"
    module.directory(str(target), owner, group, 0o750)
    for created in [existing / "Caches", existing / "Caches/voxhelm", target]:
        assert created.stat().st_mode & 0o777 == 0o750
    assert existing.stat().st_mode & 0o777 == 0o700
